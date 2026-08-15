package frontend

import (
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"slices"
	"strings"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/wasm"
)

type (
	// stackValue is one slot of the Wasm operand stack: the SSA value in it, and the Wasm
	// type it has. The Wasm type is not recoverable from the SSA value: i64, funcref,
	// externref, exnref and the concrete ref types all lower to ssa.TypeI64, and telling
	// them apart is what lets the lowering know which slots hold something the runtime has
	// to account for.
	stackValue struct {
		v ssa.Value
		t wasm.ValueType
	}

	// loweringState is used to keep the state of lowering.
	loweringState struct {
		// values holds the values on the Wasm stack.
		values           []stackValue
		controlFrames    []controlFrame
		unreachable      bool
		unreachableDepth int
		tmpForBrTable    []uint32
		pc               int
	}
	controlFrame struct {
		kind controlFrameKind
		// originalStackLen holds the number of values on the Wasm stack
		// when start executing this control frame minus params for the block.
		originalStackLenWithoutParam int
		// blk is the loop header if this is loop, and is the else-block if this is an if frame.
		blk,
		// followingBlock is the basic block we enter if we reach "end" of block.
		followingBlock ssa.BasicBlock
		blockType *wasm.FunctionType
		// clonedArgs hold the arguments to Else block.
		clonedArgs ssa.Values
		// dispatchBlock is the exception-dispatch block for a try_table with catch
		// clauses: reached when an exception propagates out of a call (or throw)
		// inside the body. It matches the in-flight exception against this
		// try_table's clauses and branches to the matching handler, or to the
		// enclosing raise target when none match. Built lazily on the first raise
		// inside the body (so a body that cannot throw produces no dead blocks),
		// and sealed at the try_table's End.
		dispatchBlock ssa.BasicBlock
		// tryTableOrdinal and catches carry the data needed to build dispatchBlock
		// lazily. catch label targets are resolved eagerly at entry (their indices
		// are relative to the scope enclosing the try_table, per spec), but the
		// dispatch/handler blocks are only materialized if the body can raise.
		tryTableOrdinal int
		catches         []resolvedCatch
		// moduleClosedBlk is where a loop's module-closed check branches when the flag
		// is set, and is nil unless this is a loop compiled with ensureTermination. It
		// is only filled in at the loop's End: see lowerModuleClosed.
		moduleClosedBlk ssa.BasicBlock
	}

	// resolvedCatch is a try_table catch clause with its branch target resolved.
	resolvedCatch struct {
		clause    catchClause
		targetBlk ssa.BasicBlock
		// targetHeight is the operand stack height its label unwinds to. Taking this clause
		// discards everything between there and the try_table's own height, so this is what
		// says which slots the handler has to release. See releaseExnrefsUnwoundByCatch.
		targetHeight int
	}

	controlFrameKind byte
)

// String implements fmt.Stringer for debugging.
func (l *loweringState) String() string {
	var str []string
	for _, sv := range l.values {
		str = append(str, fmt.Sprintf("v%v", sv.v.ID()))
	}
	var frames []string
	for i := range l.controlFrames {
		frames = append(frames, l.controlFrames[i].kind.String())
	}
	return fmt.Sprintf("\n\tunreachable=%v(depth=%d)\n\tstack: %s\n\tcontrol frames: %s",
		l.unreachable, l.unreachableDepth,
		strings.Join(str, ", "),
		strings.Join(frames, ", "),
	)
}

const (
	controlFrameKindFunction = iota + 1
	controlFrameKindLoop
	controlFrameKindIfWithElse
	controlFrameKindIfWithoutElse
	controlFrameKindBlock
	controlFrameKindTryTable
	controlFrameKindTryTableWithCatch
)

// String implements fmt.Stringer for debugging.
func (k controlFrameKind) String() string {
	switch k {
	case controlFrameKindFunction:
		return "function"
	case controlFrameKindLoop:
		return "loop"
	case controlFrameKindIfWithElse:
		return "if_with_else"
	case controlFrameKindIfWithoutElse:
		return "if_without_else"
	case controlFrameKindBlock:
		return "block"
	case controlFrameKindTryTable:
		return "try_table"
	case controlFrameKindTryTableWithCatch:
		return "try_table_with_catch"
	default:
		panic(k)
	}
}

// isLoop returns true if this is a loop frame.
func (ctrl *controlFrame) isLoop() bool {
	return ctrl.kind == controlFrameKindLoop
}

func (ctrl *controlFrame) isTryCatch() bool {
	return ctrl.kind == controlFrameKindTryTableWithCatch
}

// reset resets the state of loweringState for reuse.
func (l *loweringState) reset() {
	l.values = l.values[:0]
	l.controlFrames = l.controlFrames[:0]
	l.pc = 0
	l.unreachable = false
	l.unreachableDepth = 0
}

func (l *loweringState) peek() (ret ssa.Value) {
	return l.values[len(l.values)-1].v
}

func (l *loweringState) truncate(height int) {
	l.values = l.values[:height]
}

func (l *loweringState) pop() (ret ssa.Value) {
	tail := len(l.values) - 1
	ret = l.values[tail].v
	l.values = l.values[:tail]
	return
}

func (l *loweringState) popTyped() stackValue {
	tail := len(l.values) - 1
	ret := l.values[tail]
	l.values = l.values[:tail]
	return ret
}

func (l *loweringState) push(v ssa.Value, t wasm.ValueType) {
	l.values = append(l.values, stackValue{v: v, t: t})
}

func (c *Compiler) nPeekDup(n int) ssa.Values {
	if n == 0 {
		return ssa.ValuesNil
	}

	l := c.state()
	tail := len(l.values)

	return c.allocateVarLengthStackValues(n, l.values[tail-n:tail])
}

func (c *Compiler) nPeekInto(args ssa.Values, n int) ssa.Values {
	l := c.state()
	pool := c.ssaBuilder.VarLengthPool()
	for _, sv := range l.values[len(l.values)-n:] {
		args = args.Append(pool, sv.v)
	}
	return args
}

func (c *Compiler) nPopInto(args ssa.Values, n int) ssa.Values {
	args = c.nPeekInto(args, n)
	l := c.state()
	l.truncate(len(l.values) - n)
	return args
}

func (l *loweringState) ctrlPop() (ret controlFrame) {
	tail := len(l.controlFrames) - 1
	ret = l.controlFrames[tail]
	l.controlFrames = l.controlFrames[:tail]
	return
}

func (l *loweringState) ctrlPush(ret controlFrame) {
	l.controlFrames = append(l.controlFrames, ret)
}

func (l *loweringState) ctrlPeekAt(n int) (ret *controlFrame) {
	tail := len(l.controlFrames) - 1
	return &l.controlFrames[tail-n]
}

// lowerBody lowers the body of the Wasm function to the SSA form.
func (c *Compiler) lowerBody(entryBlk ssa.BasicBlock) {
	c.ssaBuilder.Seal(entryBlk)

	if c.needListener {
		c.callListenerBefore()
	}

	// Pushes the empty control frame which corresponds to the function return.
	c.loweringState.ctrlPush(controlFrame{
		kind:           controlFrameKindFunction,
		blockType:      c.wasmFunctionTyp,
		followingBlock: c.ssaBuilder.ReturnBlock(),
	})

	for c.loweringState.pc < len(c.wasmFunctionBody) {
		blkBeforeLowering := c.ssaBuilder.CurrentBlock()
		c.lowerCurrentOpcode()
		blkAfterLowering := c.ssaBuilder.CurrentBlock()
		if blkBeforeLowering != blkAfterLowering {
			// In Wasm, once a block exits, that means we've done compiling the block.
			// Therefore, we finalize the known bounds at the end of the block for the exiting block.
			c.finalizeKnownSafeBoundsAtTheEndOfBlock(blkBeforeLowering.ID())
			// After that, we initialize the known bounds for the new compilation target block.
			c.initializeCurrentBlockKnownBounds()
		}
	}
}

func (c *Compiler) state() *loweringState {
	return &c.loweringState
}

func (c *Compiler) lowerCurrentOpcode() {
	op := c.wasmFunctionBody[c.loweringState.pc]

	if c.needSourceOffsetInfo {
		c.ssaBuilder.SetCurrentSourceOffset(
			ssa.SourceOffset(c.loweringState.pc) + ssa.SourceOffset(c.wasmFunctionBodyOffsetInCodeSection),
		)
	}

	builder := c.ssaBuilder
	state := c.state()
	switch op {
	case wasm.OpcodeI32Const:
		c := c.readI32s()
		if state.unreachable {
			break
		}

		iconst := builder.AllocateInstruction().AsIconst32(uint32(c)).Insert(builder)
		value := iconst.Return()
		state.push(value, wasm.ValueTypeI32)
	case wasm.OpcodeI64Const:
		c := c.readI64s()
		if state.unreachable {
			break
		}
		iconst := builder.AllocateInstruction().AsIconst64(uint64(c)).Insert(builder)
		value := iconst.Return()
		state.push(value, wasm.ValueTypeI64)
	case wasm.OpcodeF32Const:
		f32 := c.readF32()
		if state.unreachable {
			break
		}
		f32const := builder.AllocateInstruction().
			AsF32const(f32).
			Insert(builder).
			Return()
		state.push(f32const, wasm.ValueTypeF32)
	case wasm.OpcodeF64Const:
		f64 := c.readF64()
		if state.unreachable {
			break
		}
		f64const := builder.AllocateInstruction().
			AsF64const(f64).
			Insert(builder).
			Return()
		state.push(f64const, wasm.ValueTypeF64)
	case wasm.OpcodeI32Add, wasm.OpcodeI64Add:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		iadd := builder.AllocateInstruction()
		iadd.AsIadd(x.v, y)
		builder.InsertInstruction(iadd)
		value := iadd.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Sub, wasm.OpcodeI64Sub:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		isub := builder.AllocateInstruction()
		isub.AsIsub(x.v, y)
		builder.InsertInstruction(isub)
		value := isub.Return()
		state.push(value, x.t)
	case wasm.OpcodeF32Add, wasm.OpcodeF64Add:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		iadd := builder.AllocateInstruction()
		iadd.AsFadd(x.v, y)
		builder.InsertInstruction(iadd)
		value := iadd.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Mul, wasm.OpcodeI64Mul:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		imul := builder.AllocateInstruction()
		imul.AsImul(x.v, y)
		builder.InsertInstruction(imul)
		value := imul.Return()
		state.push(value, x.t)
	case wasm.OpcodeF32Sub, wasm.OpcodeF64Sub:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		isub := builder.AllocateInstruction()
		isub.AsFsub(x.v, y)
		builder.InsertInstruction(isub)
		value := isub.Return()
		state.push(value, x.t)
	case wasm.OpcodeF32Mul, wasm.OpcodeF64Mul:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		isub := builder.AllocateInstruction()
		isub.AsFmul(x.v, y)
		builder.InsertInstruction(isub)
		value := isub.Return()
		state.push(value, x.t)
	case wasm.OpcodeF32Div, wasm.OpcodeF64Div:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		isub := builder.AllocateInstruction()
		isub.AsFdiv(x.v, y)
		builder.InsertInstruction(isub)
		value := isub.Return()
		state.push(value, x.t)
	case wasm.OpcodeF32Max, wasm.OpcodeF64Max:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		isub := builder.AllocateInstruction()
		isub.AsFmax(x.v, y)
		builder.InsertInstruction(isub)
		value := isub.Return()
		state.push(value, x.t)
	case wasm.OpcodeF32Min, wasm.OpcodeF64Min:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		isub := builder.AllocateInstruction()
		isub.AsFmin(x.v, y)
		builder.InsertInstruction(isub)
		value := isub.Return()
		state.push(value, x.t)
	case wasm.OpcodeI64Extend8S:
		if state.unreachable {
			break
		}
		c.insertIntegerExtend(true, 8, wasm.ValueTypeI64)
	case wasm.OpcodeI64Extend16S:
		if state.unreachable {
			break
		}
		c.insertIntegerExtend(true, 16, wasm.ValueTypeI64)
	case wasm.OpcodeI64Extend32S, wasm.OpcodeI64ExtendI32S:
		if state.unreachable {
			break
		}
		c.insertIntegerExtend(true, 32, wasm.ValueTypeI64)
	case wasm.OpcodeI64ExtendI32U:
		if state.unreachable {
			break
		}
		c.insertIntegerExtend(false, 32, wasm.ValueTypeI64)
	case wasm.OpcodeI32Extend8S:
		if state.unreachable {
			break
		}
		c.insertIntegerExtend(true, 8, wasm.ValueTypeI32)
	case wasm.OpcodeI32Extend16S:
		if state.unreachable {
			break
		}
		c.insertIntegerExtend(true, 16, wasm.ValueTypeI32)
	case wasm.OpcodeI32Eqz, wasm.OpcodeI64Eqz:
		if state.unreachable {
			break
		}
		x := state.pop()
		zero := builder.AllocateInstruction()
		if op == wasm.OpcodeI32Eqz {
			zero.AsIconst32(0)
		} else {
			zero.AsIconst64(0)
		}
		builder.InsertInstruction(zero)
		icmp := builder.AllocateInstruction().
			AsIcmp(x, zero.Return(), ssa.IntegerCmpCondEqual).
			Insert(builder).
			Return()
		state.push(icmp, wasm.ValueTypeI32)
	case wasm.OpcodeI32Eq, wasm.OpcodeI64Eq:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondEqual)
	case wasm.OpcodeI32Ne, wasm.OpcodeI64Ne:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondNotEqual)
	case wasm.OpcodeI32LtS, wasm.OpcodeI64LtS:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondSignedLessThan)
	case wasm.OpcodeI32LtU, wasm.OpcodeI64LtU:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondUnsignedLessThan)
	case wasm.OpcodeI32GtS, wasm.OpcodeI64GtS:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondSignedGreaterThan)
	case wasm.OpcodeI32GtU, wasm.OpcodeI64GtU:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondUnsignedGreaterThan)
	case wasm.OpcodeI32LeS, wasm.OpcodeI64LeS:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondSignedLessThanOrEqual)
	case wasm.OpcodeI32LeU, wasm.OpcodeI64LeU:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondUnsignedLessThanOrEqual)
	case wasm.OpcodeI32GeS, wasm.OpcodeI64GeS:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondSignedGreaterThanOrEqual)
	case wasm.OpcodeI32GeU, wasm.OpcodeI64GeU:
		if state.unreachable {
			break
		}
		c.insertIcmp(ssa.IntegerCmpCondUnsignedGreaterThanOrEqual)

	case wasm.OpcodeF32Eq, wasm.OpcodeF64Eq:
		if state.unreachable {
			break
		}
		c.insertFcmp(ssa.FloatCmpCondEqual)
	case wasm.OpcodeF32Ne, wasm.OpcodeF64Ne:
		if state.unreachable {
			break
		}
		c.insertFcmp(ssa.FloatCmpCondNotEqual)
	case wasm.OpcodeF32Lt, wasm.OpcodeF64Lt:
		if state.unreachable {
			break
		}
		c.insertFcmp(ssa.FloatCmpCondLessThan)
	case wasm.OpcodeF32Gt, wasm.OpcodeF64Gt:
		if state.unreachable {
			break
		}
		c.insertFcmp(ssa.FloatCmpCondGreaterThan)
	case wasm.OpcodeF32Le, wasm.OpcodeF64Le:
		if state.unreachable {
			break
		}
		c.insertFcmp(ssa.FloatCmpCondLessThanOrEqual)
	case wasm.OpcodeF32Ge, wasm.OpcodeF64Ge:
		if state.unreachable {
			break
		}
		c.insertFcmp(ssa.FloatCmpCondGreaterThanOrEqual)
	case wasm.OpcodeF32Neg, wasm.OpcodeF64Neg:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		v := builder.AllocateInstruction().AsFneg(x.v).Insert(builder).Return()
		state.push(v, x.t)
	case wasm.OpcodeF32Sqrt, wasm.OpcodeF64Sqrt:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		v := builder.AllocateInstruction().AsSqrt(x.v).Insert(builder).Return()
		state.push(v, x.t)
	case wasm.OpcodeF32Abs, wasm.OpcodeF64Abs:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		v := builder.AllocateInstruction().AsFabs(x.v).Insert(builder).Return()
		state.push(v, x.t)
	case wasm.OpcodeF32Copysign, wasm.OpcodeF64Copysign:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		v := builder.AllocateInstruction().AsFcopysign(x.v, y).Insert(builder).Return()
		state.push(v, x.t)

	case wasm.OpcodeF32Ceil, wasm.OpcodeF64Ceil:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		v := builder.AllocateInstruction().AsCeil(x.v).Insert(builder).Return()
		state.push(v, x.t)
	case wasm.OpcodeF32Floor, wasm.OpcodeF64Floor:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		v := builder.AllocateInstruction().AsFloor(x.v).Insert(builder).Return()
		state.push(v, x.t)
	case wasm.OpcodeF32Trunc, wasm.OpcodeF64Trunc:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		v := builder.AllocateInstruction().AsTrunc(x.v).Insert(builder).Return()
		state.push(v, x.t)
	case wasm.OpcodeF32Nearest, wasm.OpcodeF64Nearest:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		v := builder.AllocateInstruction().AsNearest(x.v).Insert(builder).Return()
		state.push(v, x.t)
	case wasm.OpcodeI64TruncF64S, wasm.OpcodeI64TruncF32S,
		wasm.OpcodeI32TruncF64S, wasm.OpcodeI32TruncF32S,
		wasm.OpcodeI64TruncF64U, wasm.OpcodeI64TruncF32U,
		wasm.OpcodeI32TruncF64U, wasm.OpcodeI32TruncF32U:
		if state.unreachable {
			break
		}
		dstType := wasm.ValueTypeI32
		switch op {
		case wasm.OpcodeI64TruncF64S, wasm.OpcodeI64TruncF32S, wasm.OpcodeI64TruncF64U, wasm.OpcodeI64TruncF32U:
			dstType = wasm.ValueTypeI64
		}
		ret := builder.AllocateInstruction().AsFcvtToInt(
			state.pop(),
			c.execCtxPtrValue,
			op == wasm.OpcodeI64TruncF64S || op == wasm.OpcodeI64TruncF32S || op == wasm.OpcodeI32TruncF32S || op == wasm.OpcodeI32TruncF64S,
			dstType == wasm.ValueTypeI64,
			false,
		).Insert(builder).Return()
		state.push(ret, dstType)
	case wasm.OpcodeMiscPrefix:
		state.pc++
		// A misc opcode is encoded as an unsigned variable 32-bit integer.
		miscOpUint, num, err := leb128.LoadUint32(c.wasmFunctionBody[state.pc:])
		if err != nil {
			// In normal conditions this should never happen because the function has passed validation.
			panic(fmt.Sprintf("failed to read misc opcode: %v", err))
		}
		state.pc += int(num - 1)
		miscOp := wasm.OpcodeMisc(miscOpUint)
		switch miscOp {
		case wasm.OpcodeMiscI64TruncSatF64S, wasm.OpcodeMiscI64TruncSatF32S,
			wasm.OpcodeMiscI32TruncSatF64S, wasm.OpcodeMiscI32TruncSatF32S,
			wasm.OpcodeMiscI64TruncSatF64U, wasm.OpcodeMiscI64TruncSatF32U,
			wasm.OpcodeMiscI32TruncSatF64U, wasm.OpcodeMiscI32TruncSatF32U:
			if state.unreachable {
				break
			}
			dstType := wasm.ValueTypeI32
			switch miscOp {
			case wasm.OpcodeMiscI64TruncSatF64S, wasm.OpcodeMiscI64TruncSatF32S,
				wasm.OpcodeMiscI64TruncSatF64U, wasm.OpcodeMiscI64TruncSatF32U:
				dstType = wasm.ValueTypeI64
			}
			ret := builder.AllocateInstruction().AsFcvtToInt(
				state.pop(),
				c.execCtxPtrValue,
				miscOp == wasm.OpcodeMiscI64TruncSatF64S || miscOp == wasm.OpcodeMiscI64TruncSatF32S || miscOp == wasm.OpcodeMiscI32TruncSatF32S || miscOp == wasm.OpcodeMiscI32TruncSatF64S,
				dstType == wasm.ValueTypeI64,
				true,
			).Insert(builder).Return()
			state.push(ret, dstType)

		case wasm.OpcodeMiscTableSize:
			tableIndex := c.readI32u()
			if state.unreachable {
				break
			}

			// Load the table.
			loadTableInstancePtr := builder.AllocateInstruction()
			loadTableInstancePtr.AsLoad(c.moduleCtxPtrValue, c.offset.TableOffset(int(tableIndex)).U32(), ssa.TypeI64)
			builder.InsertInstruction(loadTableInstancePtr)
			tableInstancePtr := loadTableInstancePtr.Return()

			// Load the table's length.
			loadTableLen := builder.AllocateInstruction().
				AsLoad(tableInstancePtr, tableInstanceLenOffset, ssa.TypeI32).
				Insert(builder)
			state.push(loadTableLen.Return(), wasm.ValueTypeI32)

		case wasm.OpcodeMiscTableGrow:
			tableIndex := c.readI32u()
			if state.unreachable {
				break
			}

			c.storeCallerModuleContext()

			tableIndexVal := builder.AllocateInstruction().AsIconst32(tableIndex).Insert(builder).Return()

			num := state.pop()
			r := state.pop()

			tableGrowPtr := builder.AllocateInstruction().
				AsLoad(c.execCtxPtrValue,
					wazevoapi.ExecutionContextOffsetTableGrowTrampolineAddress.U32(),
					ssa.TypeI64,
				).Insert(builder).Return()

			args := c.allocateVarLengthValues(4, c.execCtxPtrValue, tableIndexVal, num, r)
			callGrowRet := builder.
				AllocateInstruction().
				AsCallIndirect(tableGrowPtr, &c.tableGrowSig, args).
				Insert(builder).Return()
			state.push(callGrowRet, wasm.ValueTypeI32)

		case wasm.OpcodeMiscTableCopy:
			dstTableIndex := c.readI32u()
			srcTableIndex := c.readI32u()
			if state.unreachable {
				break
			}

			copySize := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()
			srcOffset := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()
			dstOffset := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()

			// Out of bounds check.
			dstTableInstancePtr := c.boundsCheckInTable(dstTableIndex, dstOffset, copySize)
			srcTableInstancePtr := c.boundsCheckInTable(srcTableIndex, srcOffset, copySize)

			dstTableBaseAddr := c.loadTableBaseAddr(dstTableInstancePtr)
			srcTableBaseAddr := c.loadTableBaseAddr(srcTableInstancePtr)

			three := builder.AllocateInstruction().AsIconst64(3).Insert(builder).Return()

			dstOffsetInBytes := builder.AllocateInstruction().AsIshl(dstOffset, three).Insert(builder).Return()
			dstAddr := builder.AllocateInstruction().AsIadd(dstTableBaseAddr, dstOffsetInBytes).Insert(builder).Return()
			srcOffsetInBytes := builder.AllocateInstruction().AsIshl(srcOffset, three).Insert(builder).Return()
			srcAddr := builder.AllocateInstruction().AsIadd(srcTableBaseAddr, srcOffsetInBytes).Insert(builder).Return()

			if c.exnrefTable(dstTableIndex) {
				c.copyExnrefSlots(dstAddr, srcAddr, copySize)
				break
			}
			copySizeInBytes := builder.AllocateInstruction().AsIshl(copySize, three).Insert(builder).Return()
			c.callMemmove(dstAddr, srcAddr, copySizeInBytes)

		case wasm.OpcodeMiscMemoryCopy:
			state.pc += 2 // +2 to skip two memory indexes which are fixed to zero.
			if state.unreachable {
				break
			}

			copySize := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()
			srcOffset := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()
			dstOffset := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()

			// Out of bounds check.
			memLen := c.getMemoryLenValue(false)
			c.boundsCheckInMemory(memLen, dstOffset, copySize)
			c.boundsCheckInMemory(memLen, srcOffset, copySize)

			memBase := c.getMemoryBaseValue(false)
			dstAddr := builder.AllocateInstruction().AsIadd(memBase, dstOffset).Insert(builder).Return()
			srcAddr := builder.AllocateInstruction().AsIadd(memBase, srcOffset).Insert(builder).Return()

			c.callMemmove(dstAddr, srcAddr, copySize)

		case wasm.OpcodeMiscTableFill:
			tableIndex := c.readI32u()
			if state.unreachable {
				break
			}
			fillSize := state.pop()
			value := state.pop()
			offset := state.pop()

			fillSizeExt := builder.
				AllocateInstruction().AsUExtend(fillSize, 32, 64).Insert(builder).Return()
			offsetExt := builder.
				AllocateInstruction().AsUExtend(offset, 32, 64).Insert(builder).Return()
			tableInstancePtr := c.boundsCheckInTable(tableIndex, offsetExt, fillSizeExt)

			three := builder.AllocateInstruction().AsIconst64(3).Insert(builder).Return()
			offsetInBytes := builder.AllocateInstruction().AsIshl(offsetExt, three).Insert(builder).Return()
			fillSizeInBytes := builder.AllocateInstruction().AsIshl(fillSizeExt, three).Insert(builder).Return()

			// Calculate the base address of the table.
			tableBaseAddr := c.loadTableBaseAddr(tableInstancePtr)
			addr := builder.AllocateInstruction().AsIadd(tableBaseAddr, offsetInBytes).Insert(builder).Return()

			if c.exnrefTable(tableIndex) {
				c.fillExnrefSlots(addr, value, fillSizeExt)
				break
			}

			// Uses the copy trick for faster filling buffer like memory.fill, but in this case we copy 8 bytes at a time.
			// Tables are rarely huge, so ignore the 8KB maximum.
			// https://github.com/golang/go/blob/go1.24.0/src/slices/slices.go#L514-L517
			//
			// 	buf := memoryInst.Buffer[offset : offset+fillSize]
			// 	buf[0:8] = value
			// 	for i := 8; i < fillSize; i *= 2 { Begin with 8 bytes.
			// 		copy(buf[i:], buf[:i])
			// 	}

			// Prepare the loop and following block.
			beforeLoop := builder.AllocateBasicBlock()
			loopBlk := builder.AllocateBasicBlock()
			loopVar := loopBlk.AddParam(builder, ssa.TypeI64)
			followingBlk := builder.AllocateBasicBlock()

			// Insert the jump to the beforeLoop block; If the fillSize is zero, then jump to the following block to skip entire logics.
			zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder).Return()
			ifFillSizeZero := builder.AllocateInstruction().AsIcmp(fillSizeExt, zero, ssa.IntegerCmpCondEqual).
				Insert(builder).Return()
			builder.AllocateInstruction().AsBrnz(ifFillSizeZero, ssa.ValuesNil, followingBlk).Insert(builder)
			c.insertJumpToBlock(ssa.ValuesNil, beforeLoop)

			// buf[0:8] = value
			builder.SetCurrentBlock(beforeLoop)
			builder.AllocateInstruction().AsStore(ssa.OpcodeStore, value, addr, 0).Insert(builder)
			eight := builder.AllocateInstruction().AsIconst64(8).Insert(builder).Return()
			c.insertJumpToBlock(c.allocateVarLengthValues(1, eight), loopBlk)

			builder.SetCurrentBlock(loopBlk)
			dstAddr := builder.AllocateInstruction().AsIadd(addr, loopVar).Insert(builder).Return()

			newLoopVar := builder.AllocateInstruction().AsIadd(loopVar, loopVar).Insert(builder).Return()
			newLoopVarLessThanFillSize := builder.AllocateInstruction().
				AsIcmp(newLoopVar, fillSizeInBytes, ssa.IntegerCmpCondUnsignedLessThan).Insert(builder).Return()

			// On the last iteration, count must be fillSizeInBytes-loopVar.
			diff := builder.AllocateInstruction().AsIsub(fillSizeInBytes, loopVar).Insert(builder).Return()
			count := builder.AllocateInstruction().AsSelect(newLoopVarLessThanFillSize, loopVar, diff).Insert(builder).Return()

			c.callMemmove(dstAddr, addr, count)

			builder.AllocateInstruction().
				AsBrnz(newLoopVarLessThanFillSize, c.allocateVarLengthValues(1, newLoopVar), loopBlk).
				Insert(builder)

			c.insertJumpToBlock(ssa.ValuesNil, followingBlk)
			builder.SetCurrentBlock(followingBlk)

			builder.Seal(beforeLoop)
			builder.Seal(loopBlk)
			builder.Seal(followingBlk)

		case wasm.OpcodeMiscMemoryFill:
			state.pc++ // Skip the memory index which is fixed to zero.
			if state.unreachable {
				break
			}

			fillSize := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()
			value := state.pop()
			offset := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()

			// Out of bounds check.
			c.boundsCheckInMemory(c.getMemoryLenValue(false), offset, fillSize)

			// Calculate the base address:
			addr := builder.AllocateInstruction().AsIadd(c.getMemoryBaseValue(false), offset).Insert(builder).Return()

			// Uses the copy trick for faster filling buffer, with a maximum chunk size of 8KB.
			// https://github.com/golang/go/blob/go1.24.0/src/bytes/bytes.go#L664-L673
			//
			// 	buf := memoryInst.Buffer[offset : offset+fillSize]
			// 	buf[0] = value
			// 	for i := 1; i < fillSize; {
			// 		chunk := ((i - 1) & 8191) + 1
			// 		copy(buf[i:], buf[:chunk])
			// 		i += chunk
			// 	}

			// Prepare the loop and following block.
			beforeLoop := builder.AllocateBasicBlock()
			loopBlk := builder.AllocateBasicBlock()
			loopVar := loopBlk.AddParam(builder, ssa.TypeI64)
			followingBlk := builder.AllocateBasicBlock()

			// Insert the jump to the beforeLoop block; If the fillSize is zero, then jump to the following block to skip entire logics.
			zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder).Return()
			ifFillSizeZero := builder.AllocateInstruction().AsIcmp(fillSize, zero, ssa.IntegerCmpCondEqual).
				Insert(builder).Return()
			builder.AllocateInstruction().AsBrnz(ifFillSizeZero, ssa.ValuesNil, followingBlk).Insert(builder)
			c.insertJumpToBlock(ssa.ValuesNil, beforeLoop)

			// buf[0] = value
			builder.SetCurrentBlock(beforeLoop)
			builder.AllocateInstruction().AsStore(ssa.OpcodeIstore8, value, addr, 0).Insert(builder)
			one := builder.AllocateInstruction().AsIconst64(1).Insert(builder).Return()
			c.insertJumpToBlock(c.allocateVarLengthValues(1, one), loopBlk)

			builder.SetCurrentBlock(loopBlk)
			dstAddr := builder.AllocateInstruction().AsIadd(addr, loopVar).Insert(builder).Return()

			// chunk := ((i - 1) & 8191) + 1
			mask := builder.AllocateInstruction().AsIconst64(8191).Insert(builder).Return()
			tmp1 := builder.AllocateInstruction().AsIsub(loopVar, one).Insert(builder).Return()
			tmp2 := builder.AllocateInstruction().AsBand(tmp1, mask).Insert(builder).Return()
			chunk := builder.AllocateInstruction().AsIadd(tmp2, one).Insert(builder).Return()

			// i += chunk
			newLoopVar := builder.AllocateInstruction().AsIadd(loopVar, chunk).Insert(builder).Return()
			newLoopVarLessThanFillSize := builder.AllocateInstruction().
				AsIcmp(newLoopVar, fillSize, ssa.IntegerCmpCondUnsignedLessThan).Insert(builder).Return()

			// count = min(chunk, fillSize-loopVar)
			diff := builder.AllocateInstruction().AsIsub(fillSize, loopVar).Insert(builder).Return()
			count := builder.AllocateInstruction().AsSelect(newLoopVarLessThanFillSize, chunk, diff).Insert(builder).Return()

			c.callMemmove(dstAddr, addr, count)

			builder.AllocateInstruction().
				AsBrnz(newLoopVarLessThanFillSize, c.allocateVarLengthValues(1, newLoopVar), loopBlk).
				Insert(builder)

			c.insertJumpToBlock(ssa.ValuesNil, followingBlk)
			builder.SetCurrentBlock(followingBlk)

			builder.Seal(beforeLoop)
			builder.Seal(loopBlk)
			builder.Seal(followingBlk)

		case wasm.OpcodeMiscMemoryInit:
			index := c.readI32u()
			state.pc++ // Skip the memory index which is fixed to zero.
			if state.unreachable {
				break
			}

			copySize := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()
			offsetInDataInstance := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()
			offsetInMemory := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()

			dataInstPtr := c.dataOrElementInstanceAddr(index, c.offset.DataInstances1stElement)

			// Bounds check.
			c.boundsCheckInMemory(c.getMemoryLenValue(false), offsetInMemory, copySize)
			c.boundsCheckInDataOrElementInstance(dataInstPtr, offsetInDataInstance, copySize, wazevoapi.ExitCodeMemoryOutOfBounds)

			dataInstBaseAddr := builder.AllocateInstruction().AsLoad(dataInstPtr, 0, ssa.TypeI64).Insert(builder).Return()
			srcAddr := builder.AllocateInstruction().AsIadd(dataInstBaseAddr, offsetInDataInstance).Insert(builder).Return()

			memBase := c.getMemoryBaseValue(false)
			dstAddr := builder.AllocateInstruction().AsIadd(memBase, offsetInMemory).Insert(builder).Return()

			c.callMemmove(dstAddr, srcAddr, copySize)

		case wasm.OpcodeMiscTableInit:
			elemIndex := c.readI32u()
			tableIndex := c.readI32u()
			if state.unreachable {
				break
			}

			copySize := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()
			offsetInElementInstance := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()
			offsetInTable := builder.
				AllocateInstruction().AsUExtend(state.pop(), 32, 64).Insert(builder).Return()

			elemInstPtr := c.dataOrElementInstanceAddr(elemIndex, c.offset.ElementInstances1stElement)

			// Bounds check.
			tableInstancePtr := c.boundsCheckInTable(tableIndex, offsetInTable, copySize)
			c.boundsCheckInDataOrElementInstance(elemInstPtr, offsetInElementInstance, copySize, wazevoapi.ExitCodeTableOutOfBounds)

			three := builder.AllocateInstruction().AsIconst64(3).Insert(builder).Return()
			// Calculates the destination address in the table.
			tableOffsetInBytes := builder.AllocateInstruction().AsIshl(offsetInTable, three).Insert(builder).Return()
			tableBaseAddr := c.loadTableBaseAddr(tableInstancePtr)
			dstAddr := builder.AllocateInstruction().AsIadd(tableBaseAddr, tableOffsetInBytes).Insert(builder).Return()

			// Calculates the source address in the element instance.
			srcOffsetInBytes := builder.AllocateInstruction().AsIshl(offsetInElementInstance, three).Insert(builder).Return()
			elemInstBaseAddr := builder.AllocateInstruction().AsLoad(elemInstPtr, 0, ssa.TypeI64).Insert(builder).Return()
			srcAddr := builder.AllocateInstruction().AsIadd(elemInstBaseAddr, srcOffsetInBytes).Insert(builder).Return()

			if c.exnrefTable(tableIndex) {
				c.copyExnrefSlots(dstAddr, srcAddr, copySize)
				break
			}

			copySizeInBytes := builder.AllocateInstruction().AsIshl(copySize, three).Insert(builder).Return()
			c.callMemmove(dstAddr, srcAddr, copySizeInBytes)

		case wasm.OpcodeMiscElemDrop:
			index := c.readI32u()
			if state.unreachable {
				break
			}

			c.dropDataOrElementInstance(index, c.offset.ElementInstances1stElement)

		case wasm.OpcodeMiscDataDrop:
			index := c.readI32u()
			if state.unreachable {
				break
			}
			c.dropDataOrElementInstance(index, c.offset.DataInstances1stElement)

		default:
			panic("Unknown MiscOp " + wasm.MiscInstructionName(miscOp))
		}

	case wasm.OpcodeI32ReinterpretF32:
		if state.unreachable {
			break
		}
		reinterpret := builder.AllocateInstruction().
			AsBitcast(state.pop(), ssa.TypeI32).
			Insert(builder).Return()
		state.push(reinterpret, wasm.ValueTypeI32)

	case wasm.OpcodeI64ReinterpretF64:
		if state.unreachable {
			break
		}
		reinterpret := builder.AllocateInstruction().
			AsBitcast(state.pop(), ssa.TypeI64).
			Insert(builder).Return()
		state.push(reinterpret, wasm.ValueTypeI64)

	case wasm.OpcodeF32ReinterpretI32:
		if state.unreachable {
			break
		}
		reinterpret := builder.AllocateInstruction().
			AsBitcast(state.pop(), ssa.TypeF32).
			Insert(builder).Return()
		state.push(reinterpret, wasm.ValueTypeF32)

	case wasm.OpcodeF64ReinterpretI64:
		if state.unreachable {
			break
		}
		reinterpret := builder.AllocateInstruction().
			AsBitcast(state.pop(), ssa.TypeF64).
			Insert(builder).Return()
		state.push(reinterpret, wasm.ValueTypeF64)

	case wasm.OpcodeI32DivS, wasm.OpcodeI64DivS:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		result := builder.AllocateInstruction().AsSDiv(x.v, y, c.execCtxPtrValue).Insert(builder).Return()
		state.push(result, x.t)

	case wasm.OpcodeI32DivU, wasm.OpcodeI64DivU:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		result := builder.AllocateInstruction().AsUDiv(x.v, y, c.execCtxPtrValue).Insert(builder).Return()
		state.push(result, x.t)

	case wasm.OpcodeI32RemS, wasm.OpcodeI64RemS:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		result := builder.AllocateInstruction().AsSRem(x.v, y, c.execCtxPtrValue).Insert(builder).Return()
		state.push(result, x.t)

	case wasm.OpcodeI32RemU, wasm.OpcodeI64RemU:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		result := builder.AllocateInstruction().AsURem(x.v, y, c.execCtxPtrValue).Insert(builder).Return()
		state.push(result, x.t)

	case wasm.OpcodeI32And, wasm.OpcodeI64And:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		and := builder.AllocateInstruction()
		and.AsBand(x.v, y)
		builder.InsertInstruction(and)
		value := and.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Or, wasm.OpcodeI64Or:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		or := builder.AllocateInstruction()
		or.AsBor(x.v, y)
		builder.InsertInstruction(or)
		value := or.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Xor, wasm.OpcodeI64Xor:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		xor := builder.AllocateInstruction()
		xor.AsBxor(x.v, y)
		builder.InsertInstruction(xor)
		value := xor.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Shl, wasm.OpcodeI64Shl:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		ishl := builder.AllocateInstruction()
		ishl.AsIshl(x.v, y)
		builder.InsertInstruction(ishl)
		value := ishl.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32ShrU, wasm.OpcodeI64ShrU:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		ishl := builder.AllocateInstruction()
		ishl.AsUshr(x.v, y)
		builder.InsertInstruction(ishl)
		value := ishl.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32ShrS, wasm.OpcodeI64ShrS:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		ishl := builder.AllocateInstruction()
		ishl.AsSshr(x.v, y)
		builder.InsertInstruction(ishl)
		value := ishl.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Rotl, wasm.OpcodeI64Rotl:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		rotl := builder.AllocateInstruction()
		rotl.AsRotl(x.v, y)
		builder.InsertInstruction(rotl)
		value := rotl.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Rotr, wasm.OpcodeI64Rotr:
		if state.unreachable {
			break
		}
		y, x := state.pop(), state.popTyped()
		rotr := builder.AllocateInstruction()
		rotr.AsRotr(x.v, y)
		builder.InsertInstruction(rotr)
		value := rotr.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Clz, wasm.OpcodeI64Clz:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		clz := builder.AllocateInstruction()
		clz.AsClz(x.v)
		builder.InsertInstruction(clz)
		value := clz.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Ctz, wasm.OpcodeI64Ctz:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		ctz := builder.AllocateInstruction()
		ctz.AsCtz(x.v)
		builder.InsertInstruction(ctz)
		value := ctz.Return()
		state.push(value, x.t)
	case wasm.OpcodeI32Popcnt, wasm.OpcodeI64Popcnt:
		if state.unreachable {
			break
		}
		x := state.popTyped()
		popcnt := builder.AllocateInstruction()
		popcnt.AsPopcnt(x.v)
		builder.InsertInstruction(popcnt)
		value := popcnt.Return()
		state.push(value, x.t)

	case wasm.OpcodeI32WrapI64:
		if state.unreachable {
			break
		}
		x := state.pop()
		wrap := builder.AllocateInstruction().AsIreduce(x, ssa.TypeI32).Insert(builder).Return()
		state.push(wrap, wasm.ValueTypeI32)
	case wasm.OpcodeGlobalGet:
		index := c.readI32u()
		if state.unreachable {
			break
		}
		if c.exnrefGlobal(index) {
			state.push(c.loadExnrefSlot(c.wasmGlobalAddr(index)), wasm.ValueTypeExnref)
			break
		}
		v := c.getWasmGlobalValue(index, false)
		state.push(v, c.globalType(index))
	case wasm.OpcodeGlobalSet:
		index := c.readI32u()
		if state.unreachable {
			break
		}
		v := state.pop()
		if c.exnrefGlobal(index) {
			c.storeExnrefSlot(c.wasmGlobalAddr(index), v)
			break
		}
		c.setWasmGlobalValue(index, v)
	case wasm.OpcodeLocalGet:
		index := c.readI32u()
		if state.unreachable {
			break
		}
		variable := c.localVariable(index)
		v := builder.MustFindValue(variable)
		lt := c.localType(index)
		if wasm.IsExnref(lt) {
			// The copy this leaves on the stack is a reference of its own: the local can be
			// overwritten while it is still live, so it cannot lean on the local's.
			c.adjustExnrefs(v, ssa.ValueInvalid)
		}
		state.push(v, lt)

	case wasm.OpcodeLocalSet:
		index := c.readI32u()
		if state.unreachable {
			break
		}
		variable := c.localVariable(index)
		newValue := state.pop()
		if wasm.IsExnref(c.localType(index)) {
			// The stack slot's reference moves into the local, so the count does not change
			// for the value being stored. What the local held loses its reference.
			c.adjustExnrefs(ssa.ValueInvalid, builder.MustFindValue(variable))
		}
		builder.DefineVariableInCurrentBB(variable, newValue)

	case wasm.OpcodeLocalTee:
		index := c.readI32u()
		if state.unreachable {
			break
		}
		variable := c.localVariable(index)
		newValue := state.peek()
		if wasm.IsExnref(c.localType(index)) {
			// Unlike local.set this does not pop, so the stack slot keeps its reference and
			// the local takes one of its own. What the local held loses one.
			c.adjustExnrefs(newValue, builder.MustFindValue(variable))
		}
		builder.DefineVariableInCurrentBB(variable, newValue)

	case wasm.OpcodeSelect, wasm.OpcodeTypedSelect:
		if op == wasm.OpcodeTypedSelect {
			state.pc += 2 // ignores the type which is only needed during validation.
		}

		if state.unreachable {
			break
		}

		cond := state.pop()
		v2 := state.pop()
		// The result has the operands' type, which select's own immediate repeats but the
		// stack already knows -- and the stack's is the one that distinguishes the reference
		// types sharing ssa.TypeI64.
		v1 := state.popTyped()

		sl := builder.AllocateInstruction().
			AsSelect(cond, v1.v, v2).
			Insert(builder).
			Return()
		if wasm.IsExnref(v1.t) {
			// Both operands had a reference and only one survives, but which is not known
			// until it runs. Taking one for the result and releasing both nets out correctly
			// either way: the survivor keeps a reference and the loser's goes.
			c.adjustExnrefs(sl, v1.v)
			c.adjustExnrefs(ssa.ValueInvalid, v2)
		}
		state.push(sl, v1.t)

	case wasm.OpcodeMemorySize:
		state.pc++ // skips the memory index.
		if state.unreachable {
			break
		}

		var memSizeInBytes ssa.Value
		if c.offset.LocalMemoryBegin < 0 {
			memInstPtr := builder.AllocateInstruction().
				AsLoad(c.moduleCtxPtrValue, c.offset.ImportedMemoryBegin.U32(), ssa.TypeI64).
				Insert(builder).
				Return()

			memSizeInBytes = builder.AllocateInstruction().
				AsLoad(memInstPtr, memoryInstanceBufSizeOffset, ssa.TypeI32).
				Insert(builder).
				Return()
		} else {
			memSizeInBytes = builder.AllocateInstruction().
				AsLoad(c.moduleCtxPtrValue, c.offset.LocalMemoryLen().U32(), ssa.TypeI32).
				Insert(builder).
				Return()
		}

		amount := builder.AllocateInstruction()
		amount.AsIconst32(uint32(wasm.MemoryPageSizeInBits))
		builder.InsertInstruction(amount)
		memSize := builder.AllocateInstruction().
			AsUshr(memSizeInBytes, amount.Return()).
			Insert(builder).
			Return()
		state.push(memSize, wasm.ValueTypeI32)

	case wasm.OpcodeMemoryGrow:
		state.pc++ // skips the memory index.
		if state.unreachable {
			break
		}

		c.storeCallerModuleContext()

		pages := state.pop()
		memoryGrowPtr := builder.AllocateInstruction().
			AsLoad(c.execCtxPtrValue,
				wazevoapi.ExecutionContextOffsetMemoryGrowTrampolineAddress.U32(),
				ssa.TypeI64,
			).Insert(builder).Return()

		args := c.allocateVarLengthValues(2, c.execCtxPtrValue, pages)
		callGrowRet := builder.
			AllocateInstruction().
			AsCallIndirect(memoryGrowPtr, &c.memoryGrowSig, args).
			Insert(builder).Return()
		state.push(callGrowRet, wasm.ValueTypeI32)

		// After the memory grow, reload the cached memory base and len.
		c.reloadMemoryBaseLen()

	case wasm.OpcodeI32Store,
		wasm.OpcodeI64Store,
		wasm.OpcodeF32Store,
		wasm.OpcodeF64Store,
		wasm.OpcodeI32Store8,
		wasm.OpcodeI32Store16,
		wasm.OpcodeI64Store8,
		wasm.OpcodeI64Store16,
		wasm.OpcodeI64Store32:

		_, offset := c.readMemArg()
		if state.unreachable {
			break
		}
		var opSize uint64
		var opcode ssa.Opcode
		switch op {
		case wasm.OpcodeI32Store, wasm.OpcodeF32Store:
			opcode = ssa.OpcodeStore
			opSize = 4
		case wasm.OpcodeI64Store, wasm.OpcodeF64Store:
			opcode = ssa.OpcodeStore
			opSize = 8
		case wasm.OpcodeI32Store8, wasm.OpcodeI64Store8:
			opcode = ssa.OpcodeIstore8
			opSize = 1
		case wasm.OpcodeI32Store16, wasm.OpcodeI64Store16:
			opcode = ssa.OpcodeIstore16
			opSize = 2
		case wasm.OpcodeI64Store32:
			opcode = ssa.OpcodeIstore32
			opSize = 4
		default:
			panic("BUG")
		}

		value := state.pop()
		baseAddr := state.pop()
		addr := c.memOpSetup(baseAddr, uint64(offset), opSize)
		builder.AllocateInstruction().
			AsStore(opcode, value, addr, offset).
			Insert(builder)

	case wasm.OpcodeI32Load,
		wasm.OpcodeI64Load,
		wasm.OpcodeF32Load,
		wasm.OpcodeF64Load,
		wasm.OpcodeI32Load8S,
		wasm.OpcodeI32Load8U,
		wasm.OpcodeI32Load16S,
		wasm.OpcodeI32Load16U,
		wasm.OpcodeI64Load8S,
		wasm.OpcodeI64Load8U,
		wasm.OpcodeI64Load16S,
		wasm.OpcodeI64Load16U,
		wasm.OpcodeI64Load32S,
		wasm.OpcodeI64Load32U:
		_, offset := c.readMemArg()
		if state.unreachable {
			break
		}

		var opSize uint64
		switch op {
		case wasm.OpcodeI32Load, wasm.OpcodeF32Load:
			opSize = 4
		case wasm.OpcodeI64Load, wasm.OpcodeF64Load:
			opSize = 8
		case wasm.OpcodeI32Load8S, wasm.OpcodeI32Load8U:
			opSize = 1
		case wasm.OpcodeI32Load16S, wasm.OpcodeI32Load16U:
			opSize = 2
		case wasm.OpcodeI64Load8S, wasm.OpcodeI64Load8U:
			opSize = 1
		case wasm.OpcodeI64Load16S, wasm.OpcodeI64Load16U:
			opSize = 2
		case wasm.OpcodeI64Load32S, wasm.OpcodeI64Load32U:
			opSize = 4
		default:
			panic("BUG")
		}

		baseAddr := state.pop()
		addr := c.memOpSetup(baseAddr, uint64(offset), opSize)
		load := builder.AllocateInstruction()
		var vt wasm.ValueType
		switch op {
		case wasm.OpcodeI32Load:
			load.AsLoad(addr, offset, ssa.TypeI32)
			vt = wasm.ValueTypeI32
		case wasm.OpcodeI64Load:
			load.AsLoad(addr, offset, ssa.TypeI64)
			vt = wasm.ValueTypeI64
		case wasm.OpcodeF32Load:
			load.AsLoad(addr, offset, ssa.TypeF32)
			vt = wasm.ValueTypeF32
		case wasm.OpcodeF64Load:
			load.AsLoad(addr, offset, ssa.TypeF64)
			vt = wasm.ValueTypeF64
		case wasm.OpcodeI32Load8S:
			load.AsExtLoad(ssa.OpcodeSload8, addr, offset, false)
			vt = wasm.ValueTypeI32
		case wasm.OpcodeI32Load8U:
			load.AsExtLoad(ssa.OpcodeUload8, addr, offset, false)
			vt = wasm.ValueTypeI32
		case wasm.OpcodeI32Load16S:
			load.AsExtLoad(ssa.OpcodeSload16, addr, offset, false)
			vt = wasm.ValueTypeI32
		case wasm.OpcodeI32Load16U:
			load.AsExtLoad(ssa.OpcodeUload16, addr, offset, false)
			vt = wasm.ValueTypeI32
		case wasm.OpcodeI64Load8S:
			load.AsExtLoad(ssa.OpcodeSload8, addr, offset, true)
			vt = wasm.ValueTypeI64
		case wasm.OpcodeI64Load8U:
			load.AsExtLoad(ssa.OpcodeUload8, addr, offset, true)
			vt = wasm.ValueTypeI64
		case wasm.OpcodeI64Load16S:
			load.AsExtLoad(ssa.OpcodeSload16, addr, offset, true)
			vt = wasm.ValueTypeI64
		case wasm.OpcodeI64Load16U:
			load.AsExtLoad(ssa.OpcodeUload16, addr, offset, true)
			vt = wasm.ValueTypeI64
		case wasm.OpcodeI64Load32S:
			load.AsExtLoad(ssa.OpcodeSload32, addr, offset, true)
			vt = wasm.ValueTypeI64
		case wasm.OpcodeI64Load32U:
			load.AsExtLoad(ssa.OpcodeUload32, addr, offset, true)
			vt = wasm.ValueTypeI64
		default:
			panic("BUG")
		}
		builder.InsertInstruction(load)
		state.push(load.Return(), vt)
	case wasm.OpcodeBlock:
		// Note: we do not need to create a BB for this as that would always have only one predecessor
		// which is the current BB, and therefore it's always ok to merge them in any way.

		bt := c.readBlockType()

		if state.unreachable {
			state.unreachableDepth++
			break
		}

		followingBlk := builder.AllocateBasicBlock()
		c.addBlockParamsFromWasmTypes(bt.Results, followingBlk)

		state.ctrlPush(controlFrame{
			kind:                         controlFrameKindBlock,
			originalStackLenWithoutParam: len(state.values) - len(bt.Params),
			followingBlock:               followingBlk,
			blockType:                    bt,
		})
	case wasm.OpcodeLoop:
		bt := c.readBlockType()

		if state.unreachable {
			state.unreachableDepth++
			break
		}

		loopHeader, afterLoopBlock := builder.AllocateBasicBlock(), builder.AllocateBasicBlock()
		c.addBlockParamsFromWasmTypes(bt.Params, loopHeader)
		c.addBlockParamsFromWasmTypes(bt.Results, afterLoopBlock)

		var moduleClosedBlk ssa.BasicBlock
		if c.ensureTermination {
			moduleClosedBlk = builder.AllocateBasicBlock()
		}

		originalLen := len(state.values) - len(bt.Params)
		state.ctrlPush(controlFrame{
			originalStackLenWithoutParam: originalLen,
			kind:                         controlFrameKindLoop,
			blk:                          loopHeader,
			followingBlock:               afterLoopBlock,
			blockType:                    bt,
			moduleClosedBlk:              moduleClosedBlk,
		})

		args := c.nPeekDup(len(bt.Params))

		// Insert the jump to the header of loop.
		br := builder.AllocateInstruction()
		br.AsJump(args, loopHeader)
		builder.InsertInstruction(br)

		c.switchTo(originalLen, loopHeader, bt.Params)

		if c.ensureTermination {
			// Cheap inline check: load moduleClosedPtr from execCtx, then load the
			// ModuleInstance.Closed it points to. If zero, fall through to the loop
			// body. If non-zero (set by the cancellation watchdog OR by an explicit
			// module.Close from another goroutine), branch out to moduleClosedBlk,
			// which re-enters Go to report the error.
			//
			// Neither load needs atomic semantics. The pointer is written once at
			// callEngine setup; the flag is a single aligned word that only ever goes
			// from zero to non-zero, so the worst a racing close can cost is being
			// noticed an iteration later.
			closedPtr := builder.AllocateInstruction().
				AsLoad(c.execCtxPtrValue,
					wazevoapi.ExecutionContextOffsetModuleClosedPtr.U32(),
					ssa.TypeI64,
				).Insert(builder).Return()
			closed := builder.AllocateInstruction().
				AsLoad(closedPtr, 0, ssa.TypeI64).Insert(builder).Return()

			// The header ends here, so the body needs a block of its own. Neither edge
			// carries arguments: this header is the only predecessor of either block,
			// so the loop's params are still live and unambiguous in both without
			// being passed.
			loopBody := builder.AllocateBasicBlock()
			builder.AllocateInstruction().
				AsBrnz(closed, ssa.ValuesNil, moduleClosedBlk).
				Insert(builder)
			c.insertJumpToBlock(ssa.ValuesNil, loopBody)

			// Lower the rest of the loop body in loopBody. The value stack still holds
			// loopHeader's params, which are the same values there: the header
			// dominates the body.
			builder.SetCurrentBlock(loopBody)
			builder.Seal(loopBody)
		}
	case wasm.OpcodeIf:
		bt := c.readBlockType()

		if state.unreachable {
			state.unreachableDepth++
			break
		}

		v := state.pop()
		thenBlk, elseBlk, followingBlk := builder.AllocateBasicBlock(), builder.AllocateBasicBlock(), builder.AllocateBasicBlock()

		// We do not make the Wasm-level block parameters as SSA-level block params for if-else blocks
		// since they won't be PHI and the definition is unique.

		// On the other hand, the following block after if-else-end will likely have
		// multiple definitions (one in Then and another in Else blocks).
		c.addBlockParamsFromWasmTypes(bt.Results, followingBlk)

		args := c.nPeekDup(len(bt.Params))

		// Insert the conditional jump to the Else block.
		brz := builder.AllocateInstruction()
		brz.AsBrz(v, ssa.ValuesNil, elseBlk)
		builder.InsertInstruction(brz)

		// Then, insert the jump to the Then block.
		br := builder.AllocateInstruction()
		br.AsJump(ssa.ValuesNil, thenBlk)
		builder.InsertInstruction(br)

		state.ctrlPush(controlFrame{
			kind:                         controlFrameKindIfWithoutElse,
			originalStackLenWithoutParam: len(state.values) - len(bt.Params),
			blk:                          elseBlk,
			followingBlock:               followingBlk,
			blockType:                    bt,
			clonedArgs:                   args,
		})

		builder.SetCurrentBlock(thenBlk)

		// Then and Else (if exists) have only one predecessor.
		builder.Seal(thenBlk)
		builder.Seal(elseBlk)
	case wasm.OpcodeElse:
		ifctrl := state.ctrlPeekAt(0)
		if unreachable := state.unreachable; unreachable && state.unreachableDepth > 0 {
			// If it is currently in unreachable and is a nested if,
			// we just remove the entire else block.
			break
		}

		ifctrl.kind = controlFrameKindIfWithElse
		if !state.unreachable {
			// If this Then block is currently reachable, we have to insert the branching to the following BB.
			followingBlk := ifctrl.followingBlock // == the BB after if-then-else.
			args := c.nPeekDup(len(ifctrl.blockType.Results))
			c.insertJumpToBlock(args, followingBlk)
		} else {
			state.unreachable = false
		}

		// Reset the stack so that we can correctly handle the else block.
		state.truncate(ifctrl.originalStackLenWithoutParam)
		elseBlk := ifctrl.blk
		for i, arg := range ifctrl.clonedArgs.View() {
			state.push(arg, ifctrl.blockType.Params[i])
		}

		builder.SetCurrentBlock(elseBlk)

	case wasm.OpcodeEnd:
		if state.unreachableDepth > 0 {
			state.unreachableDepth--
			break
		}

		ctrl := state.ctrlPop()
		followingBlk := ctrl.followingBlock

		unreachable := state.unreachable
		if !unreachable {
			// Top n-th args will be used as a result of the current control frame.
			args := c.nPeekDup(len(ctrl.blockType.Results))

			// Insert the unconditional branch to the target.
			c.insertJumpToBlock(args, followingBlk)
		} else { // recover from the unreachable state.
			state.unreachable = false
		}

		switch ctrl.kind {
		case controlFrameKindFunction:
			// Seal the exception propagate blocks (if any) now that all propagating
			// predecessors throughout the function have been wired.
			for _, blk := range [...]ssa.BasicBlock{c.exceptionPropagateBlk, c.exceptionPropagateAfterReleaseBlk} {
				if blk != nil && !blk.Sealed() {
					builder.Seal(blk)
				}
			}
		case controlFrameKindLoop:
			if ctrl.moduleClosedBlk != nil {
				c.lowerModuleClosed(&ctrl)
			}
			// Loop header block can be reached from any br/br_table contained in the loop,
			// so now that we've reached End of it, we can seal it.
			builder.Seal(ctrl.blk)
		case controlFrameKindIfWithoutElse:
			// If this is the end of Then block, we have to emit the empty Else block.
			elseBlk := ctrl.blk
			builder.SetCurrentBlock(elseBlk)
			c.insertJumpToBlock(ctrl.clonedArgs, followingBlk)
		case controlFrameKindTryTableWithCatch:
			// All predecessors of the dispatch block (per-call landing pads and throws
			// inside the body) have now been lowered, so it can be sealed. It may
			// be nil if the body could never raise (no calls or throws).
			if ctrl.dispatchBlock != nil && !ctrl.dispatchBlock.Sealed() {
				builder.Seal(ctrl.dispatchBlock)
			}
		}

		builder.Seal(followingBlk)

		// Ready to start translating the following block.
		c.switchTo(ctrl.originalStackLenWithoutParam, followingBlk, ctrl.blockType.Results)

	case wasm.OpcodeBr:
		labelIndex := c.readI32u()
		if state.unreachable {
			break
		}

		targetBlk, argNum := state.brTargetArgNumFor(labelIndex)
		args := c.nPeekDup(argNum)
		if !targetBlk.ReturnBlock() {
			// A branch to the function's own label is the frame exit, which
			// insertJumpToBlock owns; releasing here as well would release it twice.
			from, to := c.branchRange(labelIndex, argNum)
			c.releaseExnrefs(from, to, false)
		}
		c.insertJumpToBlock(args, targetBlk)

		state.unreachable = true

	case wasm.OpcodeBrIf:
		labelIndex := c.readI32u()
		if state.unreachable {
			break
		}

		v := state.pop()

		targetBlk, argNum := state.brTargetArgNumFor(labelIndex)
		args := c.nPeekDup(argNum)
		targetBlk, args, sealTargetBlk := c.takenEdgeTarget(labelIndex, argNum, targetBlk, args)

		// Insert the conditional jump to the target block.
		brnz := builder.AllocateInstruction()
		brnz.AsBrnz(v, args, targetBlk)
		builder.InsertInstruction(brnz)

		if sealTargetBlk {
			builder.Seal(targetBlk)
		}

		// Insert the unconditional jump to the Else block which corresponds to after br_if.
		elseBlk := builder.AllocateBasicBlock()
		c.insertJumpToBlock(ssa.ValuesNil, elseBlk)

		// Now start translating the instructions after br_if.
		builder.Seal(elseBlk) // Else of br_if has the current block as the only one successor.
		builder.SetCurrentBlock(elseBlk)

	case wasm.OpcodeBrTable:
		labels := state.tmpForBrTable[:0]
		labelCount := c.readI32u()
		for i := 0; i < int(labelCount); i++ {
			labels = append(labels, c.readI32u())
		}
		labels = append(labels, c.readI32u()) // default label.
		if state.unreachable {
			break
		}

		index := state.pop()
		if labelCount == 0 { // If this br_table is empty, we can just emit the unconditional jump.
			targetBlk, argNum := state.brTargetArgNumFor(labels[0])
			args := c.nPeekDup(argNum)
			// Unconditional, like br, so the releases can go in this block rather than a
			// block of their own.
			if !targetBlk.ReturnBlock() {
				from, to := c.branchRange(labels[0], argNum)
				c.releaseExnrefs(from, to, false)
			}
			c.insertJumpToBlock(args, targetBlk)
		} else {
			c.lowerBrTable(labels, index)
		}
		state.tmpForBrTable = labels // reuse the temporary slice for next use.
		state.unreachable = true

	case wasm.OpcodeNop:
	case wasm.OpcodeReturn:
		if state.unreachable {
			break
		}
		if c.needListener {
			c.callListenerAfter()
		}

		c.lowerReturn(builder)
		state.unreachable = true

	case wasm.OpcodeUnreachable:
		if state.unreachable {
			break
		}
		exit := builder.AllocateInstruction()
		exit.AsExitWithCode(c.execCtxPtrValue, wazevoapi.ExitCodeUnreachable)
		builder.InsertInstruction(exit)
		state.unreachable = true

	case wasm.OpcodeCallIndirect:
		typeIndex := c.readI32u()
		tableIndex := c.readI32u()
		if state.unreachable {
			break
		}
		c.lowerCallIndirect(typeIndex, tableIndex)

	case wasm.OpcodeCall:
		fnIndex := c.readI32u()
		if state.unreachable {
			break
		}
		c.lowerCall(fnIndex)

	case wasm.OpcodeDrop:
		if state.unreachable {
			break
		}
		if dropped := state.popTyped(); wasm.IsExnref(dropped.t) {
			c.adjustExnrefs(ssa.ValueInvalid, dropped.v)
		}
	case wasm.OpcodeF64ConvertI32S, wasm.OpcodeF64ConvertI64S, wasm.OpcodeF64ConvertI32U, wasm.OpcodeF64ConvertI64U:
		if state.unreachable {
			break
		}
		result := builder.AllocateInstruction().AsFcvtFromInt(
			state.pop(),
			op == wasm.OpcodeF64ConvertI32S || op == wasm.OpcodeF64ConvertI64S,
			true,
		).Insert(builder).Return()
		state.push(result, wasm.ValueTypeF64)
	case wasm.OpcodeF32ConvertI32S, wasm.OpcodeF32ConvertI64S, wasm.OpcodeF32ConvertI32U, wasm.OpcodeF32ConvertI64U:
		if state.unreachable {
			break
		}
		result := builder.AllocateInstruction().AsFcvtFromInt(
			state.pop(),
			op == wasm.OpcodeF32ConvertI32S || op == wasm.OpcodeF32ConvertI64S,
			false,
		).Insert(builder).Return()
		state.push(result, wasm.ValueTypeF32)
	case wasm.OpcodeF32DemoteF64:
		if state.unreachable {
			break
		}
		cvt := builder.AllocateInstruction()
		cvt.AsFdemote(state.pop())
		builder.InsertInstruction(cvt)
		state.push(cvt.Return(), wasm.ValueTypeF32)
	case wasm.OpcodeF64PromoteF32:
		if state.unreachable {
			break
		}
		cvt := builder.AllocateInstruction()
		cvt.AsFpromote(state.pop())
		builder.InsertInstruction(cvt)
		state.push(cvt.Return(), wasm.ValueTypeF64)

	case wasm.OpcodeVecPrefix:
		state.pc++
		vecOp := c.wasmFunctionBody[state.pc]
		switch vecOp {
		case wasm.OpcodeVecV128Const:
			state.pc++
			lo := binary.LittleEndian.Uint64(c.wasmFunctionBody[state.pc:])
			state.pc += 8
			hi := binary.LittleEndian.Uint64(c.wasmFunctionBody[state.pc:])
			state.pc += 7
			if state.unreachable {
				break
			}
			ret := builder.AllocateInstruction().AsVconst(lo, hi).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128Load:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}
			baseAddr := state.pop()
			addr := c.memOpSetup(baseAddr, uint64(offset), 16)
			load := builder.AllocateInstruction()
			load.AsLoad(addr, offset, ssa.TypeV128)
			builder.InsertInstruction(load)
			state.push(load.Return(), wasm.ValueTypeV128)
		case wasm.OpcodeVecV128Load8Lane, wasm.OpcodeVecV128Load16Lane, wasm.OpcodeVecV128Load32Lane:
			_, offset := c.readMemArg()
			state.pc++
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			var loadOp ssa.Opcode
			var opSize uint64
			switch vecOp {
			case wasm.OpcodeVecV128Load8Lane:
				loadOp, lane, opSize = ssa.OpcodeUload8, ssa.VecLaneI8x16, 1
			case wasm.OpcodeVecV128Load16Lane:
				loadOp, lane, opSize = ssa.OpcodeUload16, ssa.VecLaneI16x8, 2
			case wasm.OpcodeVecV128Load32Lane:
				loadOp, lane, opSize = ssa.OpcodeUload32, ssa.VecLaneI32x4, 4
			}
			laneIndex := c.wasmFunctionBody[state.pc]
			vector := state.pop()
			baseAddr := state.pop()
			addr := c.memOpSetup(baseAddr, uint64(offset), opSize)
			load := builder.AllocateInstruction().
				AsExtLoad(loadOp, addr, offset, false).
				Insert(builder).Return()
			ret := builder.AllocateInstruction().
				AsInsertlane(vector, load, laneIndex, lane).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128Load64Lane:
			_, offset := c.readMemArg()
			state.pc++
			if state.unreachable {
				break
			}
			laneIndex := c.wasmFunctionBody[state.pc]
			vector := state.pop()
			baseAddr := state.pop()
			addr := c.memOpSetup(baseAddr, uint64(offset), 8)
			load := builder.AllocateInstruction().
				AsLoad(addr, offset, ssa.TypeI64).
				Insert(builder).Return()
			ret := builder.AllocateInstruction().
				AsInsertlane(vector, load, laneIndex, ssa.VecLaneI64x2).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecV128Load32zero, wasm.OpcodeVecV128Load64zero:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}

			var scalarType ssa.Type
			switch vecOp {
			case wasm.OpcodeVecV128Load32zero:
				scalarType = ssa.TypeF32
			case wasm.OpcodeVecV128Load64zero:
				scalarType = ssa.TypeF64
			}

			baseAddr := state.pop()
			addr := c.memOpSetup(baseAddr, uint64(offset), uint64(scalarType.Size()))

			ret := builder.AllocateInstruction().
				AsVZeroExtLoad(addr, offset, scalarType).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecV128Load8x8u, wasm.OpcodeVecV128Load8x8s,
			wasm.OpcodeVecV128Load16x4u, wasm.OpcodeVecV128Load16x4s,
			wasm.OpcodeVecV128Load32x2u, wasm.OpcodeVecV128Load32x2s:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			var signed bool
			switch vecOp {
			case wasm.OpcodeVecV128Load8x8s:
				signed = true
				fallthrough
			case wasm.OpcodeVecV128Load8x8u:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecV128Load16x4s:
				signed = true
				fallthrough
			case wasm.OpcodeVecV128Load16x4u:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecV128Load32x2s:
				signed = true
				fallthrough
			case wasm.OpcodeVecV128Load32x2u:
				lane = ssa.VecLaneI32x4
			}
			baseAddr := state.pop()
			addr := c.memOpSetup(baseAddr, uint64(offset), 8)
			load := builder.AllocateInstruction().
				AsLoad(addr, offset, ssa.TypeF64).
				Insert(builder).Return()
			ret := builder.AllocateInstruction().
				AsWiden(load, lane, signed, true).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128Load8Splat, wasm.OpcodeVecV128Load16Splat,
			wasm.OpcodeVecV128Load32Splat, wasm.OpcodeVecV128Load64Splat:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			var opSize uint64
			switch vecOp {
			case wasm.OpcodeVecV128Load8Splat:
				lane, opSize = ssa.VecLaneI8x16, 1
			case wasm.OpcodeVecV128Load16Splat:
				lane, opSize = ssa.VecLaneI16x8, 2
			case wasm.OpcodeVecV128Load32Splat:
				lane, opSize = ssa.VecLaneI32x4, 4
			case wasm.OpcodeVecV128Load64Splat:
				lane, opSize = ssa.VecLaneI64x2, 8
			}
			baseAddr := state.pop()
			addr := c.memOpSetup(baseAddr, uint64(offset), opSize)
			ret := builder.AllocateInstruction().
				AsLoadSplat(addr, offset, lane).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128Store:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}
			value := state.pop()
			baseAddr := state.pop()
			addr := c.memOpSetup(baseAddr, uint64(offset), 16)
			builder.AllocateInstruction().
				AsStore(ssa.OpcodeStore, value, addr, offset).
				Insert(builder)
		case wasm.OpcodeVecV128Store8Lane, wasm.OpcodeVecV128Store16Lane,
			wasm.OpcodeVecV128Store32Lane, wasm.OpcodeVecV128Store64Lane:
			_, offset := c.readMemArg()
			state.pc++
			if state.unreachable {
				break
			}
			laneIndex := c.wasmFunctionBody[state.pc]
			var storeOp ssa.Opcode
			var lane ssa.VecLane
			var opSize uint64
			switch vecOp {
			case wasm.OpcodeVecV128Store8Lane:
				storeOp, lane, opSize = ssa.OpcodeIstore8, ssa.VecLaneI8x16, 1
			case wasm.OpcodeVecV128Store16Lane:
				storeOp, lane, opSize = ssa.OpcodeIstore16, ssa.VecLaneI16x8, 2
			case wasm.OpcodeVecV128Store32Lane:
				storeOp, lane, opSize = ssa.OpcodeIstore32, ssa.VecLaneI32x4, 4
			case wasm.OpcodeVecV128Store64Lane:
				storeOp, lane, opSize = ssa.OpcodeStore, ssa.VecLaneI64x2, 8
			}
			vector := state.pop()
			baseAddr := state.pop()
			addr := c.memOpSetup(baseAddr, uint64(offset), opSize)
			value := builder.AllocateInstruction().
				AsExtractlane(vector, laneIndex, lane, false).
				Insert(builder).Return()
			builder.AllocateInstruction().
				AsStore(storeOp, value, addr, offset).
				Insert(builder)
		case wasm.OpcodeVecV128Not:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVbnot(v1).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128And:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVband(v1, v2).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128AndNot:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVbandnot(v1, v2).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128Or:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVbor(v1, v2).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128Xor:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVbxor(v1, v2).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128Bitselect:
			if state.unreachable {
				break
			}
			c := state.pop()
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVbitselect(c, v1, v2).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128AnyTrue:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVanyTrue(v1).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeI32)
		case wasm.OpcodeVecI8x16AllTrue, wasm.OpcodeVecI16x8AllTrue, wasm.OpcodeVecI32x4AllTrue, wasm.OpcodeVecI64x2AllTrue:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16AllTrue:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8AllTrue:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4AllTrue:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2AllTrue:
				lane = ssa.VecLaneI64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVallTrue(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeI32)
		case wasm.OpcodeVecI8x16BitMask, wasm.OpcodeVecI16x8BitMask, wasm.OpcodeVecI32x4BitMask, wasm.OpcodeVecI64x2BitMask:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16BitMask:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8BitMask:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4BitMask:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2BitMask:
				lane = ssa.VecLaneI64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVhighBits(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeI32)
		case wasm.OpcodeVecI8x16Abs, wasm.OpcodeVecI16x8Abs, wasm.OpcodeVecI32x4Abs, wasm.OpcodeVecI64x2Abs:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16Abs:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8Abs:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4Abs:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2Abs:
				lane = ssa.VecLaneI64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVIabs(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16Neg, wasm.OpcodeVecI16x8Neg, wasm.OpcodeVecI32x4Neg, wasm.OpcodeVecI64x2Neg:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16Neg:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8Neg:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4Neg:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2Neg:
				lane = ssa.VecLaneI64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVIneg(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16Popcnt:
			if state.unreachable {
				break
			}
			lane := ssa.VecLaneI8x16
			v1 := state.pop()

			ret := builder.AllocateInstruction().AsVIpopcnt(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16Add, wasm.OpcodeVecI16x8Add, wasm.OpcodeVecI32x4Add, wasm.OpcodeVecI64x2Add:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16Add:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8Add:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4Add:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2Add:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVIadd(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16AddSatS, wasm.OpcodeVecI16x8AddSatS:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16AddSatS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8AddSatS:
				lane = ssa.VecLaneI16x8
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVSaddSat(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16AddSatU, wasm.OpcodeVecI16x8AddSatU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16AddSatU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8AddSatU:
				lane = ssa.VecLaneI16x8
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVUaddSat(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16SubSatS, wasm.OpcodeVecI16x8SubSatS:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16SubSatS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8SubSatS:
				lane = ssa.VecLaneI16x8
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVSsubSat(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16SubSatU, wasm.OpcodeVecI16x8SubSatU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16SubSatU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8SubSatU:
				lane = ssa.VecLaneI16x8
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVUsubSat(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI8x16Sub, wasm.OpcodeVecI16x8Sub, wasm.OpcodeVecI32x4Sub, wasm.OpcodeVecI64x2Sub:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16Sub:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8Sub:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4Sub:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2Sub:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVIsub(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16MinS, wasm.OpcodeVecI16x8MinS, wasm.OpcodeVecI32x4MinS:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16MinS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8MinS:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4MinS:
				lane = ssa.VecLaneI32x4
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVImin(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16MinU, wasm.OpcodeVecI16x8MinU, wasm.OpcodeVecI32x4MinU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16MinU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8MinU:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4MinU:
				lane = ssa.VecLaneI32x4
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVUmin(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16MaxS, wasm.OpcodeVecI16x8MaxS, wasm.OpcodeVecI32x4MaxS:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16MaxS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8MaxS:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4MaxS:
				lane = ssa.VecLaneI32x4
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVImax(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16MaxU, wasm.OpcodeVecI16x8MaxU, wasm.OpcodeVecI32x4MaxU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16MaxU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8MaxU:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4MaxU:
				lane = ssa.VecLaneI32x4
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVUmax(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16AvgrU, wasm.OpcodeVecI16x8AvgrU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16AvgrU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8AvgrU:
				lane = ssa.VecLaneI16x8
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVAvgRound(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI16x8Mul, wasm.OpcodeVecI32x4Mul, wasm.OpcodeVecI64x2Mul:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI16x8Mul:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4Mul:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2Mul:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVImul(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI16x8Q15mulrSatS:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsSqmulRoundSat(v1, v2, ssa.VecLaneI16x8).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16Eq, wasm.OpcodeVecI16x8Eq, wasm.OpcodeVecI32x4Eq, wasm.OpcodeVecI64x2Eq:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16Eq:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8Eq:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4Eq:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2Eq:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16Ne, wasm.OpcodeVecI16x8Ne, wasm.OpcodeVecI32x4Ne, wasm.OpcodeVecI64x2Ne:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16Ne:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8Ne:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4Ne:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2Ne:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondNotEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16LtS, wasm.OpcodeVecI16x8LtS, wasm.OpcodeVecI32x4LtS, wasm.OpcodeVecI64x2LtS:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16LtS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8LtS:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4LtS:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2LtS:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondSignedLessThan, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16LtU, wasm.OpcodeVecI16x8LtU, wasm.OpcodeVecI32x4LtU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16LtU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8LtU:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4LtU:
				lane = ssa.VecLaneI32x4
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondUnsignedLessThan, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16LeS, wasm.OpcodeVecI16x8LeS, wasm.OpcodeVecI32x4LeS, wasm.OpcodeVecI64x2LeS:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16LeS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8LeS:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4LeS:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2LeS:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondSignedLessThanOrEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16LeU, wasm.OpcodeVecI16x8LeU, wasm.OpcodeVecI32x4LeU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16LeU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8LeU:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4LeU:
				lane = ssa.VecLaneI32x4
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondUnsignedLessThanOrEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16GtS, wasm.OpcodeVecI16x8GtS, wasm.OpcodeVecI32x4GtS, wasm.OpcodeVecI64x2GtS:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16GtS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8GtS:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4GtS:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2GtS:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondSignedGreaterThan, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16GtU, wasm.OpcodeVecI16x8GtU, wasm.OpcodeVecI32x4GtU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16GtU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8GtU:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4GtU:
				lane = ssa.VecLaneI32x4
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondUnsignedGreaterThan, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16GeS, wasm.OpcodeVecI16x8GeS, wasm.OpcodeVecI32x4GeS, wasm.OpcodeVecI64x2GeS:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16GeS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8GeS:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4GeS:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2GeS:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondSignedGreaterThanOrEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16GeU, wasm.OpcodeVecI16x8GeU, wasm.OpcodeVecI32x4GeU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16GeU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8GeU:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4GeU:
				lane = ssa.VecLaneI32x4
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVIcmp(v1, v2, ssa.IntegerCmpCondUnsignedGreaterThanOrEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Max, wasm.OpcodeVecF64x2Max:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Max:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Max:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVFmax(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Abs, wasm.OpcodeVecF64x2Abs:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Abs:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Abs:
				lane = ssa.VecLaneF64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVFabs(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Min, wasm.OpcodeVecF64x2Min:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Min:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Min:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVFmin(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Neg, wasm.OpcodeVecF64x2Neg:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Neg:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Neg:
				lane = ssa.VecLaneF64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVFneg(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Sqrt, wasm.OpcodeVecF64x2Sqrt:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Sqrt:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Sqrt:
				lane = ssa.VecLaneF64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVSqrt(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecF32x4Add, wasm.OpcodeVecF64x2Add:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Add:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Add:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVFadd(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Sub, wasm.OpcodeVecF64x2Sub:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Sub:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Sub:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVFsub(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Mul, wasm.OpcodeVecF64x2Mul:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Mul:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Mul:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVFmul(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Div, wasm.OpcodeVecF64x2Div:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Div:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Div:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVFdiv(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI16x8ExtaddPairwiseI8x16S, wasm.OpcodeVecI16x8ExtaddPairwiseI8x16U:
			if state.unreachable {
				break
			}
			v := state.pop()
			signed := vecOp == wasm.OpcodeVecI16x8ExtaddPairwiseI8x16S
			ret := builder.AllocateInstruction().AsExtIaddPairwise(v, ssa.VecLaneI8x16, signed).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI32x4ExtaddPairwiseI16x8S, wasm.OpcodeVecI32x4ExtaddPairwiseI16x8U:
			if state.unreachable {
				break
			}
			v := state.pop()
			signed := vecOp == wasm.OpcodeVecI32x4ExtaddPairwiseI16x8S
			ret := builder.AllocateInstruction().AsExtIaddPairwise(v, ssa.VecLaneI16x8, signed).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI16x8ExtMulLowI8x16S, wasm.OpcodeVecI16x8ExtMulLowI8x16U:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := c.lowerExtMul(
				v1, v2,
				ssa.VecLaneI8x16, ssa.VecLaneI16x8,
				vecOp == wasm.OpcodeVecI16x8ExtMulLowI8x16S, true)
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI16x8ExtMulHighI8x16S, wasm.OpcodeVecI16x8ExtMulHighI8x16U:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := c.lowerExtMul(
				v1, v2,
				ssa.VecLaneI8x16, ssa.VecLaneI16x8,
				vecOp == wasm.OpcodeVecI16x8ExtMulHighI8x16S, false)
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI32x4ExtMulLowI16x8S, wasm.OpcodeVecI32x4ExtMulLowI16x8U:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := c.lowerExtMul(
				v1, v2,
				ssa.VecLaneI16x8, ssa.VecLaneI32x4,
				vecOp == wasm.OpcodeVecI32x4ExtMulLowI16x8S, true)
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI32x4ExtMulHighI16x8S, wasm.OpcodeVecI32x4ExtMulHighI16x8U:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := c.lowerExtMul(
				v1, v2,
				ssa.VecLaneI16x8, ssa.VecLaneI32x4,
				vecOp == wasm.OpcodeVecI32x4ExtMulHighI16x8S, false)
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI64x2ExtMulLowI32x4S, wasm.OpcodeVecI64x2ExtMulLowI32x4U:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := c.lowerExtMul(
				v1, v2,
				ssa.VecLaneI32x4, ssa.VecLaneI64x2,
				vecOp == wasm.OpcodeVecI64x2ExtMulLowI32x4S, true)
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI64x2ExtMulHighI32x4S, wasm.OpcodeVecI64x2ExtMulHighI32x4U:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := c.lowerExtMul(
				v1, v2,
				ssa.VecLaneI32x4, ssa.VecLaneI64x2,
				vecOp == wasm.OpcodeVecI64x2ExtMulHighI32x4S, false)
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI32x4DotI16x8S:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()

			ret := builder.AllocateInstruction().AsWideningPairwiseDotProductS(v1, v2).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecF32x4Eq, wasm.OpcodeVecF64x2Eq:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Eq:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Eq:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVFcmp(v1, v2, ssa.FloatCmpCondEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Ne, wasm.OpcodeVecF64x2Ne:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Ne:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Ne:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVFcmp(v1, v2, ssa.FloatCmpCondNotEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Lt, wasm.OpcodeVecF64x2Lt:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Lt:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Lt:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVFcmp(v1, v2, ssa.FloatCmpCondLessThan, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Le, wasm.OpcodeVecF64x2Le:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Le:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Le:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVFcmp(v1, v2, ssa.FloatCmpCondLessThanOrEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Gt, wasm.OpcodeVecF64x2Gt:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Gt:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Gt:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVFcmp(v1, v2, ssa.FloatCmpCondGreaterThan, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Ge, wasm.OpcodeVecF64x2Ge:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Ge:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Ge:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVFcmp(v1, v2, ssa.FloatCmpCondGreaterThanOrEqual, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Ceil, wasm.OpcodeVecF64x2Ceil:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Ceil:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Ceil:
				lane = ssa.VecLaneF64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVCeil(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Floor, wasm.OpcodeVecF64x2Floor:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Floor:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Floor:
				lane = ssa.VecLaneF64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVFloor(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Trunc, wasm.OpcodeVecF64x2Trunc:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Trunc:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Trunc:
				lane = ssa.VecLaneF64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVTrunc(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Nearest, wasm.OpcodeVecF64x2Nearest:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Nearest:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Nearest:
				lane = ssa.VecLaneF64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVNearest(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Pmin, wasm.OpcodeVecF64x2Pmin:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Pmin:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Pmin:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVMinPseudo(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4Pmax, wasm.OpcodeVecF64x2Pmax:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecF32x4Pmax:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Pmax:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVMaxPseudo(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI32x4TruncSatF32x4S, wasm.OpcodeVecI32x4TruncSatF32x4U:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVFcvtToIntSat(v1, ssa.VecLaneF32x4, vecOp == wasm.OpcodeVecI32x4TruncSatF32x4S).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI32x4TruncSatF64x2SZero, wasm.OpcodeVecI32x4TruncSatF64x2UZero:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVFcvtToIntSat(v1, ssa.VecLaneF64x2, vecOp == wasm.OpcodeVecI32x4TruncSatF64x2SZero).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4ConvertI32x4S, wasm.OpcodeVecF32x4ConvertI32x4U:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsVFcvtFromInt(v1, ssa.VecLaneF32x4, vecOp == wasm.OpcodeVecF32x4ConvertI32x4S).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF64x2ConvertLowI32x4S, wasm.OpcodeVecF64x2ConvertLowI32x4U:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			if runtime.GOARCH == "arm64" {
				// TODO: this is weird. fix.
				v1 = builder.AllocateInstruction().
					AsWiden(v1, ssa.VecLaneI32x4, vecOp == wasm.OpcodeVecF64x2ConvertLowI32x4S, true).Insert(builder).Return()
			}
			ret := builder.AllocateInstruction().
				AsVFcvtFromInt(v1, ssa.VecLaneF64x2, vecOp == wasm.OpcodeVecF64x2ConvertLowI32x4S).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16NarrowI16x8S, wasm.OpcodeVecI8x16NarrowI16x8U:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsNarrow(v1, v2, ssa.VecLaneI16x8, vecOp == wasm.OpcodeVecI8x16NarrowI16x8S).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI16x8NarrowI32x4S, wasm.OpcodeVecI16x8NarrowI32x4U:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsNarrow(v1, v2, ssa.VecLaneI32x4, vecOp == wasm.OpcodeVecI16x8NarrowI32x4S).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI16x8ExtendLowI8x16S, wasm.OpcodeVecI16x8ExtendLowI8x16U:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsWiden(v1, ssa.VecLaneI8x16, vecOp == wasm.OpcodeVecI16x8ExtendLowI8x16S, true).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI16x8ExtendHighI8x16S, wasm.OpcodeVecI16x8ExtendHighI8x16U:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsWiden(v1, ssa.VecLaneI8x16, vecOp == wasm.OpcodeVecI16x8ExtendHighI8x16S, false).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI32x4ExtendLowI16x8S, wasm.OpcodeVecI32x4ExtendLowI16x8U:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsWiden(v1, ssa.VecLaneI16x8, vecOp == wasm.OpcodeVecI32x4ExtendLowI16x8S, true).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI32x4ExtendHighI16x8S, wasm.OpcodeVecI32x4ExtendHighI16x8U:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsWiden(v1, ssa.VecLaneI16x8, vecOp == wasm.OpcodeVecI32x4ExtendHighI16x8S, false).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI64x2ExtendLowI32x4S, wasm.OpcodeVecI64x2ExtendLowI32x4U:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsWiden(v1, ssa.VecLaneI32x4, vecOp == wasm.OpcodeVecI64x2ExtendLowI32x4S, true).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI64x2ExtendHighI32x4S, wasm.OpcodeVecI64x2ExtendHighI32x4U:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsWiden(v1, ssa.VecLaneI32x4, vecOp == wasm.OpcodeVecI64x2ExtendHighI32x4S, false).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecF64x2PromoteLowF32x4Zero:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsFvpromoteLow(v1, ssa.VecLaneF32x4).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecF32x4DemoteF64x2Zero:
			if state.unreachable {
				break
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().
				AsFvdemote(v1, ssa.VecLaneF64x2).
				Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16Shl, wasm.OpcodeVecI16x8Shl, wasm.OpcodeVecI32x4Shl, wasm.OpcodeVecI64x2Shl:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16Shl:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8Shl:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4Shl:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2Shl:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVIshl(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16ShrS, wasm.OpcodeVecI16x8ShrS, wasm.OpcodeVecI32x4ShrS, wasm.OpcodeVecI64x2ShrS:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16ShrS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8ShrS:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4ShrS:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2ShrS:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVSshr(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16ShrU, wasm.OpcodeVecI16x8ShrU, wasm.OpcodeVecI32x4ShrU, wasm.OpcodeVecI64x2ShrU:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16ShrU:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8ShrU:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4ShrU:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2ShrU:
				lane = ssa.VecLaneI64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsVUshr(v1, v2, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecI8x16ExtractLaneS, wasm.OpcodeVecI16x8ExtractLaneS:
			state.pc++
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16ExtractLaneS:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8ExtractLaneS:
				lane = ssa.VecLaneI16x8
			}
			v1 := state.pop()
			index := c.wasmFunctionBody[state.pc]
			ext := builder.AllocateInstruction().AsExtractlane(v1, index, lane, true).Insert(builder).Return()
			state.push(ext, wasm.ValueTypeI32)
		case wasm.OpcodeVecI8x16ExtractLaneU, wasm.OpcodeVecI16x8ExtractLaneU,
			wasm.OpcodeVecI32x4ExtractLane, wasm.OpcodeVecI64x2ExtractLane,
			wasm.OpcodeVecF32x4ExtractLane, wasm.OpcodeVecF64x2ExtractLane:
			state.pc++ // Skip the immediate value.
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			var vt wasm.ValueType
			switch vecOp {
			case wasm.OpcodeVecI8x16ExtractLaneU:
				lane, vt = ssa.VecLaneI8x16, wasm.ValueTypeI32
			case wasm.OpcodeVecI16x8ExtractLaneU:
				lane, vt = ssa.VecLaneI16x8, wasm.ValueTypeI32
			case wasm.OpcodeVecI32x4ExtractLane:
				lane, vt = ssa.VecLaneI32x4, wasm.ValueTypeI32
			case wasm.OpcodeVecI64x2ExtractLane:
				lane, vt = ssa.VecLaneI64x2, wasm.ValueTypeI64
			case wasm.OpcodeVecF32x4ExtractLane:
				lane, vt = ssa.VecLaneF32x4, wasm.ValueTypeF32
			case wasm.OpcodeVecF64x2ExtractLane:
				lane, vt = ssa.VecLaneF64x2, wasm.ValueTypeF64
			}
			v1 := state.pop()
			index := c.wasmFunctionBody[state.pc]
			ext := builder.AllocateInstruction().AsExtractlane(v1, index, lane, false).Insert(builder).Return()
			state.push(ext, vt)
		case wasm.OpcodeVecI8x16ReplaceLane, wasm.OpcodeVecI16x8ReplaceLane,
			wasm.OpcodeVecI32x4ReplaceLane, wasm.OpcodeVecI64x2ReplaceLane,
			wasm.OpcodeVecF32x4ReplaceLane, wasm.OpcodeVecF64x2ReplaceLane:
			state.pc++
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16ReplaceLane:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8ReplaceLane:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4ReplaceLane:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2ReplaceLane:
				lane = ssa.VecLaneI64x2
			case wasm.OpcodeVecF32x4ReplaceLane:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2ReplaceLane:
				lane = ssa.VecLaneF64x2
			}
			v2 := state.pop()
			v1 := state.pop()
			index := c.wasmFunctionBody[state.pc]
			ret := builder.AllocateInstruction().AsInsertlane(v1, v2, index, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)
		case wasm.OpcodeVecV128i8x16Shuffle:
			state.pc++
			laneIndexes := c.wasmFunctionBody[state.pc : state.pc+16]
			state.pc += 15
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsShuffle(v1, v2, laneIndexes).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI8x16Swizzle:
			if state.unreachable {
				break
			}
			v2 := state.pop()
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsSwizzle(v1, v2, ssa.VecLaneI8x16).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		case wasm.OpcodeVecI8x16Splat,
			wasm.OpcodeVecI16x8Splat,
			wasm.OpcodeVecI32x4Splat,
			wasm.OpcodeVecI64x2Splat,
			wasm.OpcodeVecF32x4Splat,
			wasm.OpcodeVecF64x2Splat:
			if state.unreachable {
				break
			}
			var lane ssa.VecLane
			switch vecOp {
			case wasm.OpcodeVecI8x16Splat:
				lane = ssa.VecLaneI8x16
			case wasm.OpcodeVecI16x8Splat:
				lane = ssa.VecLaneI16x8
			case wasm.OpcodeVecI32x4Splat:
				lane = ssa.VecLaneI32x4
			case wasm.OpcodeVecI64x2Splat:
				lane = ssa.VecLaneI64x2
			case wasm.OpcodeVecF32x4Splat:
				lane = ssa.VecLaneF32x4
			case wasm.OpcodeVecF64x2Splat:
				lane = ssa.VecLaneF64x2
			}
			v1 := state.pop()
			ret := builder.AllocateInstruction().AsSplat(v1, lane).Insert(builder).Return()
			state.push(ret, wasm.ValueTypeV128)

		default:
			panic("TODO: unsupported vector instruction: " + wasm.VectorInstructionName(vecOp))
		}
	case wasm.OpcodeAtomicPrefix:
		state.pc++
		atomicOp := c.wasmFunctionBody[state.pc]
		switch atomicOp {
		case wasm.OpcodeAtomicMemoryWait32, wasm.OpcodeAtomicMemoryWait64:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}

			c.storeCallerModuleContext()

			var opSize uint64
			var trampoline wazevoapi.Offset
			var sig *ssa.Signature
			switch atomicOp {
			case wasm.OpcodeAtomicMemoryWait32:
				opSize = 4
				trampoline = wazevoapi.ExecutionContextOffsetMemoryWait32TrampolineAddress
				sig = &c.memoryWait32Sig
			case wasm.OpcodeAtomicMemoryWait64:
				opSize = 8
				trampoline = wazevoapi.ExecutionContextOffsetMemoryWait64TrampolineAddress
				sig = &c.memoryWait64Sig
			}

			timeout := state.pop()
			exp := state.pop()
			baseAddr := state.pop()
			addr := c.atomicMemOpSetup(baseAddr, uint64(offset), opSize)

			memoryWaitPtr := builder.AllocateInstruction().
				AsLoad(c.execCtxPtrValue,
					trampoline.U32(),
					ssa.TypeI64,
				).Insert(builder).Return()

			args := c.allocateVarLengthValues(4, c.execCtxPtrValue, timeout, exp, addr)
			memoryWaitRet := builder.AllocateInstruction().
				AsCallIndirect(memoryWaitPtr, sig, args).
				Insert(builder).Return()
			state.push(memoryWaitRet, wasm.ValueTypeI32)
		case wasm.OpcodeAtomicMemoryNotify:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}

			c.storeCallerModuleContext()
			count := state.pop()
			baseAddr := state.pop()
			addr := c.atomicMemOpSetup(baseAddr, uint64(offset), 4)

			memoryNotifyPtr := builder.AllocateInstruction().
				AsLoad(c.execCtxPtrValue,
					wazevoapi.ExecutionContextOffsetMemoryNotifyTrampolineAddress.U32(),
					ssa.TypeI64,
				).Insert(builder).Return()
			args := c.allocateVarLengthValues(3, c.execCtxPtrValue, count, addr)
			memoryNotifyRet := builder.AllocateInstruction().
				AsCallIndirect(memoryNotifyPtr, &c.memoryNotifySig, args).
				Insert(builder).Return()
			state.push(memoryNotifyRet, wasm.ValueTypeI32)
		case wasm.OpcodeAtomicI32Load, wasm.OpcodeAtomicI64Load, wasm.OpcodeAtomicI32Load8U, wasm.OpcodeAtomicI32Load16U, wasm.OpcodeAtomicI64Load8U, wasm.OpcodeAtomicI64Load16U, wasm.OpcodeAtomicI64Load32U:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}

			baseAddr := state.pop()

			var size uint64
			switch atomicOp {
			case wasm.OpcodeAtomicI64Load:
				size = 8
			case wasm.OpcodeAtomicI32Load, wasm.OpcodeAtomicI64Load32U:
				size = 4
			case wasm.OpcodeAtomicI32Load16U, wasm.OpcodeAtomicI64Load16U:
				size = 2
			case wasm.OpcodeAtomicI32Load8U, wasm.OpcodeAtomicI64Load8U:
				size = 1
			}

			var typ wasm.ValueType
			switch atomicOp {
			case wasm.OpcodeAtomicI64Load, wasm.OpcodeAtomicI64Load32U, wasm.OpcodeAtomicI64Load16U, wasm.OpcodeAtomicI64Load8U:
				typ = wasm.ValueTypeI64
			case wasm.OpcodeAtomicI32Load, wasm.OpcodeAtomicI32Load16U, wasm.OpcodeAtomicI32Load8U:
				typ = wasm.ValueTypeI32
			}

			addr := c.atomicMemOpSetup(baseAddr, uint64(offset), size)
			res := builder.AllocateInstruction().
				AsAtomicLoad(addr, size, WasmTypeToSSAType(typ)).Insert(builder).Return()
			state.push(res, typ)
		case wasm.OpcodeAtomicI32Store, wasm.OpcodeAtomicI64Store, wasm.OpcodeAtomicI32Store8, wasm.OpcodeAtomicI32Store16, wasm.OpcodeAtomicI64Store8, wasm.OpcodeAtomicI64Store16, wasm.OpcodeAtomicI64Store32:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}

			val := state.pop()
			baseAddr := state.pop()

			var size uint64
			switch atomicOp {
			case wasm.OpcodeAtomicI64Store:
				size = 8
			case wasm.OpcodeAtomicI32Store, wasm.OpcodeAtomicI64Store32:
				size = 4
			case wasm.OpcodeAtomicI32Store16, wasm.OpcodeAtomicI64Store16:
				size = 2
			case wasm.OpcodeAtomicI32Store8, wasm.OpcodeAtomicI64Store8:
				size = 1
			}

			addr := c.atomicMemOpSetup(baseAddr, uint64(offset), size)
			builder.AllocateInstruction().AsAtomicStore(addr, val, size).Insert(builder)
		case wasm.OpcodeAtomicI32RmwAdd, wasm.OpcodeAtomicI64RmwAdd, wasm.OpcodeAtomicI32Rmw8AddU, wasm.OpcodeAtomicI32Rmw16AddU, wasm.OpcodeAtomicI64Rmw8AddU, wasm.OpcodeAtomicI64Rmw16AddU, wasm.OpcodeAtomicI64Rmw32AddU,
			wasm.OpcodeAtomicI32RmwSub, wasm.OpcodeAtomicI64RmwSub, wasm.OpcodeAtomicI32Rmw8SubU, wasm.OpcodeAtomicI32Rmw16SubU, wasm.OpcodeAtomicI64Rmw8SubU, wasm.OpcodeAtomicI64Rmw16SubU, wasm.OpcodeAtomicI64Rmw32SubU,
			wasm.OpcodeAtomicI32RmwAnd, wasm.OpcodeAtomicI64RmwAnd, wasm.OpcodeAtomicI32Rmw8AndU, wasm.OpcodeAtomicI32Rmw16AndU, wasm.OpcodeAtomicI64Rmw8AndU, wasm.OpcodeAtomicI64Rmw16AndU, wasm.OpcodeAtomicI64Rmw32AndU,
			wasm.OpcodeAtomicI32RmwOr, wasm.OpcodeAtomicI64RmwOr, wasm.OpcodeAtomicI32Rmw8OrU, wasm.OpcodeAtomicI32Rmw16OrU, wasm.OpcodeAtomicI64Rmw8OrU, wasm.OpcodeAtomicI64Rmw16OrU, wasm.OpcodeAtomicI64Rmw32OrU,
			wasm.OpcodeAtomicI32RmwXor, wasm.OpcodeAtomicI64RmwXor, wasm.OpcodeAtomicI32Rmw8XorU, wasm.OpcodeAtomicI32Rmw16XorU, wasm.OpcodeAtomicI64Rmw8XorU, wasm.OpcodeAtomicI64Rmw16XorU, wasm.OpcodeAtomicI64Rmw32XorU,
			wasm.OpcodeAtomicI32RmwXchg, wasm.OpcodeAtomicI64RmwXchg, wasm.OpcodeAtomicI32Rmw8XchgU, wasm.OpcodeAtomicI32Rmw16XchgU, wasm.OpcodeAtomicI64Rmw8XchgU, wasm.OpcodeAtomicI64Rmw16XchgU, wasm.OpcodeAtomicI64Rmw32XchgU:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}

			val := state.popTyped()
			baseAddr := state.pop()

			var rmwOp ssa.AtomicRmwOp
			var size uint64
			switch atomicOp {
			case wasm.OpcodeAtomicI32RmwAdd, wasm.OpcodeAtomicI64RmwAdd, wasm.OpcodeAtomicI32Rmw8AddU, wasm.OpcodeAtomicI32Rmw16AddU, wasm.OpcodeAtomicI64Rmw8AddU, wasm.OpcodeAtomicI64Rmw16AddU, wasm.OpcodeAtomicI64Rmw32AddU:
				rmwOp = ssa.AtomicRmwOpAdd
				switch atomicOp {
				case wasm.OpcodeAtomicI64RmwAdd:
					size = 8
				case wasm.OpcodeAtomicI32RmwAdd, wasm.OpcodeAtomicI64Rmw32AddU:
					size = 4
				case wasm.OpcodeAtomicI32Rmw16AddU, wasm.OpcodeAtomicI64Rmw16AddU:
					size = 2
				case wasm.OpcodeAtomicI32Rmw8AddU, wasm.OpcodeAtomicI64Rmw8AddU:
					size = 1
				}
			case wasm.OpcodeAtomicI32RmwSub, wasm.OpcodeAtomicI64RmwSub, wasm.OpcodeAtomicI32Rmw8SubU, wasm.OpcodeAtomicI32Rmw16SubU, wasm.OpcodeAtomicI64Rmw8SubU, wasm.OpcodeAtomicI64Rmw16SubU, wasm.OpcodeAtomicI64Rmw32SubU:
				rmwOp = ssa.AtomicRmwOpSub
				switch atomicOp {
				case wasm.OpcodeAtomicI64RmwSub:
					size = 8
				case wasm.OpcodeAtomicI32RmwSub, wasm.OpcodeAtomicI64Rmw32SubU:
					size = 4
				case wasm.OpcodeAtomicI32Rmw16SubU, wasm.OpcodeAtomicI64Rmw16SubU:
					size = 2
				case wasm.OpcodeAtomicI32Rmw8SubU, wasm.OpcodeAtomicI64Rmw8SubU:
					size = 1
				}
			case wasm.OpcodeAtomicI32RmwAnd, wasm.OpcodeAtomicI64RmwAnd, wasm.OpcodeAtomicI32Rmw8AndU, wasm.OpcodeAtomicI32Rmw16AndU, wasm.OpcodeAtomicI64Rmw8AndU, wasm.OpcodeAtomicI64Rmw16AndU, wasm.OpcodeAtomicI64Rmw32AndU:
				rmwOp = ssa.AtomicRmwOpAnd
				switch atomicOp {
				case wasm.OpcodeAtomicI64RmwAnd:
					size = 8
				case wasm.OpcodeAtomicI32RmwAnd, wasm.OpcodeAtomicI64Rmw32AndU:
					size = 4
				case wasm.OpcodeAtomicI32Rmw16AndU, wasm.OpcodeAtomicI64Rmw16AndU:
					size = 2
				case wasm.OpcodeAtomicI32Rmw8AndU, wasm.OpcodeAtomicI64Rmw8AndU:
					size = 1
				}
			case wasm.OpcodeAtomicI32RmwOr, wasm.OpcodeAtomicI64RmwOr, wasm.OpcodeAtomicI32Rmw8OrU, wasm.OpcodeAtomicI32Rmw16OrU, wasm.OpcodeAtomicI64Rmw8OrU, wasm.OpcodeAtomicI64Rmw16OrU, wasm.OpcodeAtomicI64Rmw32OrU:
				rmwOp = ssa.AtomicRmwOpOr
				switch atomicOp {
				case wasm.OpcodeAtomicI64RmwOr:
					size = 8
				case wasm.OpcodeAtomicI32RmwOr, wasm.OpcodeAtomicI64Rmw32OrU:
					size = 4
				case wasm.OpcodeAtomicI32Rmw16OrU, wasm.OpcodeAtomicI64Rmw16OrU:
					size = 2
				case wasm.OpcodeAtomicI32Rmw8OrU, wasm.OpcodeAtomicI64Rmw8OrU:
					size = 1
				}
			case wasm.OpcodeAtomicI32RmwXor, wasm.OpcodeAtomicI64RmwXor, wasm.OpcodeAtomicI32Rmw8XorU, wasm.OpcodeAtomicI32Rmw16XorU, wasm.OpcodeAtomicI64Rmw8XorU, wasm.OpcodeAtomicI64Rmw16XorU, wasm.OpcodeAtomicI64Rmw32XorU:
				rmwOp = ssa.AtomicRmwOpXor
				switch atomicOp {
				case wasm.OpcodeAtomicI64RmwXor:
					size = 8
				case wasm.OpcodeAtomicI32RmwXor, wasm.OpcodeAtomicI64Rmw32XorU:
					size = 4
				case wasm.OpcodeAtomicI32Rmw16XorU, wasm.OpcodeAtomicI64Rmw16XorU:
					size = 2
				case wasm.OpcodeAtomicI32Rmw8XorU, wasm.OpcodeAtomicI64Rmw8XorU:
					size = 1
				}
			case wasm.OpcodeAtomicI32RmwXchg, wasm.OpcodeAtomicI64RmwXchg, wasm.OpcodeAtomicI32Rmw8XchgU, wasm.OpcodeAtomicI32Rmw16XchgU, wasm.OpcodeAtomicI64Rmw8XchgU, wasm.OpcodeAtomicI64Rmw16XchgU, wasm.OpcodeAtomicI64Rmw32XchgU:
				rmwOp = ssa.AtomicRmwOpXchg
				switch atomicOp {
				case wasm.OpcodeAtomicI64RmwXchg:
					size = 8
				case wasm.OpcodeAtomicI32RmwXchg, wasm.OpcodeAtomicI64Rmw32XchgU:
					size = 4
				case wasm.OpcodeAtomicI32Rmw16XchgU, wasm.OpcodeAtomicI64Rmw16XchgU:
					size = 2
				case wasm.OpcodeAtomicI32Rmw8XchgU, wasm.OpcodeAtomicI64Rmw8XchgU:
					size = 1
				}
			}

			addr := c.atomicMemOpSetup(baseAddr, uint64(offset), size)
			res := builder.AllocateInstruction().AsAtomicRmw(rmwOp, addr, val.v, size).Insert(builder).Return()
			state.push(res, val.t)
		case wasm.OpcodeAtomicI32RmwCmpxchg, wasm.OpcodeAtomicI64RmwCmpxchg, wasm.OpcodeAtomicI32Rmw8CmpxchgU, wasm.OpcodeAtomicI32Rmw16CmpxchgU, wasm.OpcodeAtomicI64Rmw8CmpxchgU, wasm.OpcodeAtomicI64Rmw16CmpxchgU, wasm.OpcodeAtomicI64Rmw32CmpxchgU:
			_, offset := c.readMemArg()
			if state.unreachable {
				break
			}

			repl := state.popTyped()
			exp := state.pop()
			baseAddr := state.pop()

			var size uint64
			switch atomicOp {
			case wasm.OpcodeAtomicI64RmwCmpxchg:
				size = 8
			case wasm.OpcodeAtomicI32RmwCmpxchg, wasm.OpcodeAtomicI64Rmw32CmpxchgU:
				size = 4
			case wasm.OpcodeAtomicI32Rmw16CmpxchgU, wasm.OpcodeAtomicI64Rmw16CmpxchgU:
				size = 2
			case wasm.OpcodeAtomicI32Rmw8CmpxchgU, wasm.OpcodeAtomicI64Rmw8CmpxchgU:
				size = 1
			}
			addr := c.atomicMemOpSetup(baseAddr, uint64(offset), size)
			res := builder.AllocateInstruction().AsAtomicCas(addr, exp, repl.v, size).Insert(builder).Return()
			state.push(res, repl.t)
		case wasm.OpcodeAtomicFence:
			order := c.readByte()
			if state.unreachable {
				break
			}
			if c.needMemory {
				builder.AllocateInstruction().AsFence(order).Insert(builder)
			}
		default:
			panic("TODO: unsupported atomic instruction: " + wasm.AtomicInstructionName(atomicOp))
		}
	case wasm.OpcodeRefFunc:
		funcIndex := c.readI32u()
		if state.unreachable {
			break
		}

		c.storeCallerModuleContext()

		funcIndexVal := builder.AllocateInstruction().AsIconst32(funcIndex).Insert(builder).Return()

		refFuncPtr := builder.AllocateInstruction().
			AsLoad(c.execCtxPtrValue,
				wazevoapi.ExecutionContextOffsetRefFuncTrampolineAddress.U32(),
				ssa.TypeI64,
			).Insert(builder).Return()

		args := c.allocateVarLengthValues(2, c.execCtxPtrValue, funcIndexVal)
		refFuncRet := builder.
			AllocateInstruction().
			AsCallIndirect(refFuncPtr, &c.refFuncSig, args).
			Insert(builder).Return()
		state.push(refFuncRet, wasm.ValueTypeFuncref)

	case wasm.OpcodeRefNull:
		var nullType wasm.ValueType
		switch reftype := c.wasmFunctionBody[c.loweringState.pc+1]; wasm.ValueType(reftype) {
		case wasm.ValueTypeFuncref, wasm.ValueTypeExternref, wasm.ValueTypeExnref:
			nullType = wasm.ValueType(reftype)
			c.loweringState.pc++
		default:
			nullType = wasm.ValueTypeConcreteRef(c.readI32u(), true)
		}
		if state.unreachable {
			break
		}
		ret := builder.AllocateInstruction().AsIconst64(0).Insert(builder).Return()
		state.push(ret, nullType)
	case wasm.OpcodeRefIsNull:
		if state.unreachable {
			break
		}
		r := state.popTyped()
		zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder)
		icmp := builder.AllocateInstruction().
			AsIcmp(r.v, zero.Return(), ssa.IntegerCmpCondEqual).
			Insert(builder).
			Return()
		if wasm.IsExnref(r.t) {
			c.adjustExnrefs(ssa.ValueInvalid, r.v)
		}
		state.push(icmp, wasm.ValueTypeI32)
	case wasm.OpcodeTableSet:
		tableIndex := c.readI32u()
		if state.unreachable {
			break
		}
		r := state.pop()
		targetOffsetInTable := state.pop()

		elementAddr := c.lowerAccessTableWithBoundsCheck(tableIndex, targetOffsetInTable)
		if c.exnrefTable(tableIndex) {
			c.storeExnrefSlot(elementAddr, r)
			break
		}
		builder.AllocateInstruction().AsStore(ssa.OpcodeStore, r, elementAddr, 0).Insert(builder)

	case wasm.OpcodeTableGet:
		tableIndex := c.readI32u()
		if state.unreachable {
			break
		}
		targetOffsetInTable := state.pop()
		elementAddr := c.lowerAccessTableWithBoundsCheck(tableIndex, targetOffsetInTable)
		if c.exnrefTable(tableIndex) {
			state.push(c.loadExnrefSlot(elementAddr), wasm.ValueTypeExnref)
			break
		}
		loaded := builder.AllocateInstruction().AsLoad(elementAddr, 0, ssa.TypeI64).Insert(builder).Return()
		state.push(loaded, c.tableType(tableIndex))

	case wasm.OpcodeTailCallReturnCallIndirect:
		typeIndex := c.readI32u()
		tableIndex := c.readI32u()
		if state.unreachable {
			break
		}
		_, _ = typeIndex, tableIndex
		c.lowerTailCallReturnCallIndirect(typeIndex, tableIndex)
		state.unreachable = true

	case wasm.OpcodeTailCallReturnCall:
		fnIndex := c.readI32u()
		if state.unreachable {
			break
		}
		c.lowerTailCallReturnCall(fnIndex)
		state.unreachable = true

	case wasm.OpcodeThrow:
		tagIndex := c.readI32u()
		if state.unreachable {
			break
		}
		tagType := c.resolveTagType(tagIndex)
		// Pop the tag's param values from the stack.
		throwParams := make([]ssa.Value, len(tagType.Params))
		for i := len(tagType.Params) - 1; i >= 0; i-- {
			throwParams[i] = state.pop()
		}

		c.storeCallerModuleContext()

		tagIdxVal := builder.AllocateInstruction().AsIconst64(uint64(tagIndex)).Insert(builder).Return()

		// Each tag has its own number of params, so Go allocates the buffer: the
		// trampoline records the raise and returns the buffer for the stores below.
		allocExceptionPtr := builder.AllocateInstruction().
			AsLoad(c.execCtxPtrValue,
				wazevoapi.ExecutionContextOffsetAllocExceptionTrampolineAddress.U32(),
				ssa.TypeI64,
			).Insert(builder).Return()
		allocExceptionArgs := c.allocateVarLengthValues(2, c.execCtxPtrValue, tagIdxVal)
		paramsPtr := builder.AllocateInstruction().
			AsCallIndirect(allocExceptionPtr, &c.allocExceptionSig, allocExceptionArgs).
			Insert(builder).Return()

		// Reload memory pointers invalidated by the Go call.
		c.reloadAfterCall()

		// We can now store each param directly into that buffer.
		if len(throwParams) > 0 {
			for i, v := range throwParams {
				switch v.Type() {
				case ssa.TypeF32:
					v = builder.AllocateInstruction().AsBitcast(v, ssa.TypeI32).Insert(builder).Return()
				case ssa.TypeF64:
					v = builder.AllocateInstruction().AsBitcast(v, ssa.TypeI64).Insert(builder).Return()
				}
				builder.AllocateInstruction().
					AsStore(ssa.OpcodeStore, v, paramsPtr, uint32(i)*8).
					Insert(builder)
			}
		}

		// The allocate-exception trampoline already recorded it as in flight.
		c.emitRaise()
		state.unreachable = true

	case wasm.OpcodeThrowRef:
		if state.unreachable {
			break
		}
		exnref := state.pop()
		// Check for null exnref.
		zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder).Return()
		isNull := builder.AllocateInstruction()
		isNull.AsIcmp(exnref, zero, ssa.IntegerCmpCondEqual)
		builder.InsertInstruction(isNull)
		exitIfNull := builder.AllocateInstruction()
		exitIfNull.AsExitIfTrueWithCode(c.execCtxPtrValue, isNull.Return(), wazevoapi.ExitCodeNullReference)
		builder.InsertInstruction(exitIfNull)

		// Hand the exception to the runtime as the one in flight, then raise it.
		c.emitRaiseRef(exnref)
		state.unreachable = true

	case wasm.OpcodeTryTable:
		bt := c.readBlockType()

		if state.unreachable {
			state.unreachableDepth++
			// Still need to skip the catch clause bytes in the unreachable case.
			c.skipTryTableCatchClauses()
			break
		}

		// Parse catch clauses.
		c.loweringState.pc++
		catchCount, catchNum, _ := leb128.LoadUint32(c.wasmFunctionBody[c.loweringState.pc:])
		c.loweringState.pc += int(catchNum) - 1

		var catchClauses []catchClause
		for i := uint32(0); i < catchCount; i++ {
			c.loweringState.pc++
			kind := c.wasmFunctionBody[c.loweringState.pc]
			var tagIdx uint32
			switch kind {
			case wasm.CatchKindCatch, wasm.CatchKindCatchRef:
				c.loweringState.pc++
				var n uint64
				tagIdx, n, _ = leb128.LoadUint32(c.wasmFunctionBody[c.loweringState.pc:])
				c.loweringState.pc += int(n) - 1
			case wasm.CatchKindCatchAll, wasm.CatchKindCatchAllRef:
				// No tagIdx for catch_all variants.
			}
			c.loweringState.pc++
			labelIdx, n, _ := leb128.LoadUint32(c.wasmFunctionBody[c.loweringState.pc:])
			c.loweringState.pc += int(n) - 1
			catchClauses = append(catchClauses, catchClause{kind: kind, tagIndex: tagIdx, labelIdx: labelIdx})
		}

		// Register try_table metadata and get the try_table ID. Only the catch
		// clauses are needed at runtime: matchException uses them to pick a
		// handler. Locals reach handlers through ordinary SSA now, so there is no
		// locals save area.
		var clauseInstances []wazevoapi.CatchClauseInstance
		for _, cc := range catchClauses {
			clauseInstances = append(clauseInstances, wazevoapi.CatchClauseInstance{
				Kind:     cc.kind,
				TagIndex: cc.tagIndex,
			})
		}
		// The ordinal within this function, paired with the function index at the point
		// the dispatch block is built, identifies this try_table at runtime.
		tryTableOrdinal := len(c.tryTables)
		c.tryTables = append(c.tryTables, wazevoapi.TryTableInfo{
			CatchClauses: clauseInstances,
		})

		// Allocate the following block (after try_table end) and body block.
		followingBlk := builder.AllocateBasicBlock()
		c.addBlockParamsFromWasmTypes(bt.Results, followingBlk)
		bodyBlk := builder.AllocateBasicBlock()

		// Resolve each catch clause's branch target now. Catch label indices are
		// relative to the scope enclosing the try_table (the try_table is not yet
		// on the control stack, per spec), so they must be resolved here, before
		// the frame is pushed. The dispatch and handler blocks themselves are built
		// lazily (see ensureDispatchBlock) only if the body can actually raise, so
		// a body that never throws produces no dead blocks.
		var catches []resolvedCatch
		if len(catchClauses) > 0 {
			catches = make([]resolvedCatch, len(catchClauses))
			for i, cc := range catchClauses {
				targetBlk, _ := state.brTargetArgNumFor(cc.labelIdx)
				catches[i] = resolvedCatch{
					clause:    cc,
					targetBlk: targetBlk,
					// Recorded here for the same reason the target block is: the label is
					// relative to this scope, which the handler blocks are not built in.
					targetHeight: state.ctrlPeekAt(int(cc.labelIdx)).originalStackLenWithoutParam,
				}
			}
		}

		// Normal entry simply falls into the body; exception dispatch happens only
		// on the (lazily built) raise path.
		c.insertJumpToBlock(ssa.ValuesNil, bodyBlk)
		builder.Seal(bodyBlk)
		builder.SetCurrentBlock(bodyBlk)

		// Push the try_table control frame AFTER resolving catch labels.
		kind := controlFrameKind(controlFrameKindTryTable)
		if len(catchClauses) > 0 {
			kind = controlFrameKindTryTableWithCatch
		}
		state.ctrlPush(controlFrame{
			kind:                         kind,
			originalStackLenWithoutParam: len(state.values) - len(bt.Params),
			followingBlock:               followingBlk,
			blockType:                    bt,
			tryTableOrdinal:              tryTableOrdinal,
			catches:                      catches,
		})

	case wasm.OpcodeRefAsNonNull:
		if state.unreachable {
			break
		}
		r := state.popTyped()
		zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder)
		checkNull := builder.AllocateInstruction().
			AsIcmp(r.v, zero.Return(), ssa.IntegerCmpCondEqual).
			Insert(builder).Return()
		exitIfNull := builder.AllocateInstruction()
		exitIfNull.AsExitIfTrueWithCode(c.execCtxPtrValue, checkNull, wazevoapi.ExitCodeNullReference)
		builder.InsertInstruction(exitIfNull)
		state.push(r.v, r.t)

	case wasm.OpcodeBrOnNull:
		labelIndex := c.readI32u()
		if state.unreachable {
			break
		}

		r := state.popTyped()
		zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder)
		isNull := builder.AllocateInstruction().
			AsIcmp(r.v, zero.Return(), ssa.IntegerCmpCondEqual).
			Insert(builder).Return()

		targetBlk, argNum := state.brTargetArgNumFor(labelIndex)
		args := c.nPeekDup(argNum)
		// The branch carries argNum values off the stack; the operand it popped is null on the
		// edge it is taken on, so it is not one of them and has no reference to release.
		targetBlk, args, sealTargetBlk := c.takenEdgeTarget(labelIndex, argNum, targetBlk, args)

		brnz := builder.AllocateInstruction()
		brnz.AsBrnz(isNull, args, targetBlk)
		builder.InsertInstruction(brnz)

		if sealTargetBlk {
			builder.Seal(targetBlk)
		}

		// Fall-through: ref is non-null, push it back.
		elseBlk := builder.AllocateBasicBlock()
		c.insertJumpToBlock(ssa.ValuesNil, elseBlk)
		builder.Seal(elseBlk)
		builder.SetCurrentBlock(elseBlk)
		state.push(r.v, r.t)

	case wasm.OpcodeBrOnNonNull:
		labelIndex := c.readI32u()
		if state.unreachable {
			break
		}

		r := state.pop()
		zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder)
		isNonNull := builder.AllocateInstruction().
			AsIcmp(r, zero.Return(), ssa.IntegerCmpCondNotEqual).
			Insert(builder).Return()

		// When non-null, branch to label with args + the non-null ref.
		targetBlk, argNum := state.brTargetArgNumFor(labelIndex)
		// The branch delivers argNum-1 values from the stack plus the ref.
		// The ref is the last value delivered to the label target.
		args := c.nPeekDup(argNum - 1)
		args = args.Append(builder.VarLengthPool(), r)
		// Only argNum-1 of the label's values come off the stack, so one more slot than for an
		// ordinary branch is discarded here. The ref itself travels to the label, so its
		// reference travels with it.
		targetBlk, args, sealTargetBlk := c.takenEdgeTarget(labelIndex, argNum-1, targetBlk, args)

		brnz := builder.AllocateInstruction()
		brnz.AsBrnz(isNonNull, args, targetBlk)
		builder.InsertInstruction(brnz)

		if sealTargetBlk {
			builder.Seal(targetBlk)
		}

		// Fall-through: ref is null, nothing extra pushed.
		elseBlk := builder.AllocateBasicBlock()
		c.insertJumpToBlock(ssa.ValuesNil, elseBlk)
		builder.Seal(elseBlk)
		builder.SetCurrentBlock(elseBlk)

	case wasm.OpcodeCallRef:
		typeIndex := c.readI32u()
		if state.unreachable {
			break
		}
		c.lowerCallRef(typeIndex)

	case wasm.OpcodeReturnCallRef:
		typeIndex := c.readI32u()
		if state.unreachable {
			break
		}
		c.lowerTailCallReturnCallRef(typeIndex)
		state.unreachable = true

	default:
		panic("TODO: unsupported in wazevo yet: " + wasm.InstructionName(op))
	}

	if wazevoapi.FrontEndLoggingEnabled {
		fmt.Println("--------- Translated " + wasm.InstructionName(op) + " --------")
		fmt.Println("state: " + c.loweringState.String())
		fmt.Println(c.formatBuilder())
		fmt.Println("--------------------------")
	}
	c.loweringState.pc++
}

func (c *Compiler) lowerReturn(builder ssa.Builder) {
	results := c.nPeekDup(c.results())
	from, to := c.frameExitRange()
	c.releaseExnrefs(from, to, true)
	instr := builder.AllocateInstruction()

	instr.AsReturn(results)
	builder.InsertInstruction(instr)
}

// lowerTailCallReturn emits the return path for a return_call: under exception handling
// the landing pad its return site needs, then the fallback return that makes the callee's
// results this function's results verbatim.
//
// Both are emitted unconditionally, whether or not the backend ends up replacing this
// frame with the callee's — the backend drops what it does not need. For a real tail call
// this frame is gone by the time the callee runs, so neither the return nor the landing
// pad is reachable: the callee returns to, and propagates into, whatever called this
// function.
func (c *Compiler) lowerTailCallReturn(builder ssa.Builder, call *ssa.Instruction) {
	if c.ehEnabled {
		c.emitTailCallExceptionEdge()
	}
	first, rest := call.Returns()
	var vs []ssa.Value
	if first.Valid() {
		vs = append(vs, first)
	}
	vs = append(vs, rest...)
	instr := builder.AllocateInstruction()
	instr.AsReturn(c.allocateVarLengthValues(len(vs), vs...))
	builder.InsertInstruction(instr)
}

func (c *Compiler) lowerExtMul(v1, v2 ssa.Value, from, to ssa.VecLane, signed, low bool) ssa.Value {
	// TODO: The sequence `Widen; Widen; VIMul` can be substituted for a single instruction on some ISAs.
	builder := c.ssaBuilder

	v1lo := builder.AllocateInstruction().AsWiden(v1, from, signed, low).Insert(builder).Return()
	v2lo := builder.AllocateInstruction().AsWiden(v2, from, signed, low).Insert(builder).Return()

	return builder.AllocateInstruction().AsVImul(v1lo, v2lo, to).Insert(builder).Return()
}

const (
	tableInstanceBaseAddressOffset = 0
	tableInstanceLenOffset         = tableInstanceBaseAddressOffset + 8
)

func (c *Compiler) lowerAccessTableWithBoundsCheck(tableIndex uint32, elementOffsetInTable ssa.Value) (elementAddress ssa.Value) {
	builder := c.ssaBuilder

	// Load the table.
	loadTableInstancePtr := builder.AllocateInstruction()
	loadTableInstancePtr.AsLoad(c.moduleCtxPtrValue, c.offset.TableOffset(int(tableIndex)).U32(), ssa.TypeI64)
	builder.InsertInstruction(loadTableInstancePtr)
	tableInstancePtr := loadTableInstancePtr.Return()

	// Load the table's length.
	loadTableLen := builder.AllocateInstruction()
	loadTableLen.AsLoad(tableInstancePtr, tableInstanceLenOffset, ssa.TypeI32)
	builder.InsertInstruction(loadTableLen)
	tableLen := loadTableLen.Return()

	// Compare the length and the target, and trap if out of bounds.
	checkOOB := builder.AllocateInstruction()
	checkOOB.AsIcmp(elementOffsetInTable, tableLen, ssa.IntegerCmpCondUnsignedGreaterThanOrEqual)
	builder.InsertInstruction(checkOOB)
	exitIfOOB := builder.AllocateInstruction()
	exitIfOOB.AsExitIfTrueWithCode(c.execCtxPtrValue, checkOOB.Return(), wazevoapi.ExitCodeTableOutOfBounds)
	builder.InsertInstruction(exitIfOOB)

	// Get the base address of wasm.TableInstance.References.
	loadTableBaseAddress := builder.AllocateInstruction()
	loadTableBaseAddress.AsLoad(tableInstancePtr, tableInstanceBaseAddressOffset, ssa.TypeI64)
	builder.InsertInstruction(loadTableBaseAddress)
	tableBase := loadTableBaseAddress.Return()

	// Calculate the address of the target function. First we need to multiply targetOffsetInTable by 8 (pointer size).
	multiplyBy8 := builder.AllocateInstruction()
	three := builder.AllocateInstruction()
	three.AsIconst64(3)
	builder.InsertInstruction(three)
	multiplyBy8.AsIshl(elementOffsetInTable, three.Return())
	builder.InsertInstruction(multiplyBy8)
	targetOffsetInTableMultipliedBy8 := multiplyBy8.Return()

	// Then add the multiplied value to the base which results in the address of the target function (*wazevo.functionInstance)
	calcElementAddressInTable := builder.AllocateInstruction()
	calcElementAddressInTable.AsIadd(tableBase, targetOffsetInTableMultipliedBy8)
	builder.InsertInstruction(calcElementAddressInTable)
	return calcElementAddressInTable.Return()
}

func (c *Compiler) prepareCall(fnIndex uint32) (isIndirect bool, typ *wasm.FunctionType, sig *ssa.Signature, args ssa.Values, funcRefOrPtrValue uint64) {
	builder := c.ssaBuilder
	var typIndex wasm.Index
	if fnIndex < c.m.ImportFunctionCount {
		// Before transfer the control to the callee, we have to store the current module's moduleContextPtr
		// into execContext.callerModuleContextPtr in case when the callee is a Go function.
		c.storeCallerModuleContext()
		var fi int
		for i := range c.m.ImportSection {
			imp := &c.m.ImportSection[i]
			if imp.Type == wasm.ExternTypeFunc {
				if fi == int(fnIndex) {
					typIndex = imp.DescFunc
					break
				}
				fi++
			}
		}
	} else {
		typIndex = c.m.FunctionSection[fnIndex-c.m.ImportFunctionCount]
	}
	typ = &c.m.TypeSection[typIndex]

	argN := len(typ.Params)
	args = c.allocateVarLengthValues(2+argN, c.execCtxPtrValue)

	sig = c.signatures[typ]
	if fnIndex >= c.m.ImportFunctionCount {
		args = args.Append(builder.VarLengthPool(), c.moduleCtxPtrValue) // This case the callee module is itself.
		args = c.nPopInto(args, argN)
		return false, typ, sig, args, uint64(FunctionIndexToFuncRef(fnIndex))
	} else {
		// This case we have to read the address of the imported function from the module context.
		moduleCtx := c.moduleCtxPtrValue
		loadFuncPtr, loadModuleCtxPtr := builder.AllocateInstruction(), builder.AllocateInstruction()
		funcPtrOffset, moduleCtxPtrOffset, _ := c.offset.ImportedFunctionOffset(fnIndex)
		loadFuncPtr.AsLoad(moduleCtx, funcPtrOffset.U32(), ssa.TypeI64)
		loadModuleCtxPtr.AsLoad(moduleCtx, moduleCtxPtrOffset.U32(), ssa.TypeI64)
		builder.InsertInstruction(loadFuncPtr)
		builder.InsertInstruction(loadModuleCtxPtr)

		args = args.Append(builder.VarLengthPool(), loadModuleCtxPtr.Return())
		args = c.nPopInto(args, argN)

		return true, typ, sig, args, uint64(loadFuncPtr.Return())
	}
}

func (c *Compiler) lowerCall(fnIndex uint32) {
	builder := c.ssaBuilder
	isIndirect, typ, sig, args, funcRefOrPtrValue := c.prepareCall(fnIndex)

	call := builder.AllocateInstruction()
	if isIndirect {
		call.AsCallIndirect(ssa.Value(funcRefOrPtrValue), sig, args)
	} else {
		call.AsCall(ssa.FuncRef(funcRefOrPtrValue), sig, args)
	}
	builder.InsertInstruction(call)

	// Exception handling: make this call's return site a landing pad so a throw from the
	// callee lands in the right handler. What a raise abandons is read before the results go
	// on the stack -- on that path the callee returned none, so those slots hold nothing.
	var abandoned []stackValue
	if c.ehEnabled {
		abandoned = c.abandonedByRaise()
	}
	c.pushCallResults(call, typ.Results)
	if c.ehEnabled {
		c.emitCallExceptionEdge(abandoned)
	}

	c.reloadAfterCall()
}

func (c *Compiler) prepareCallIndirect(typeIndex, tableIndex uint32) (ssa.Value, *wasm.FunctionType, ssa.Values) {
	builder := c.ssaBuilder
	state := c.state()

	elementOffsetInTable := state.pop()
	functionInstancePtrAddress := c.lowerAccessTableWithBoundsCheck(tableIndex, elementOffsetInTable)
	loadFunctionInstancePtr := builder.AllocateInstruction()
	loadFunctionInstancePtr.AsLoad(functionInstancePtrAddress, 0, ssa.TypeI64)
	builder.InsertInstruction(loadFunctionInstancePtr)
	functionInstancePtr := loadFunctionInstancePtr.Return()

	// Check if it is not the null pointer.
	zero := builder.AllocateInstruction()
	zero.AsIconst64(0)
	builder.InsertInstruction(zero)
	checkNull := builder.AllocateInstruction()
	checkNull.AsIcmp(functionInstancePtr, zero.Return(), ssa.IntegerCmpCondEqual)
	builder.InsertInstruction(checkNull)
	exitIfNull := builder.AllocateInstruction()
	exitIfNull.AsExitIfTrueWithCode(c.execCtxPtrValue, checkNull.Return(), wazevoapi.ExitCodeIndirectCallNullPointer)
	builder.InsertInstruction(exitIfNull)

	// We need to do the type check. First, load the target function instance's typeID.
	loadTypeID := builder.AllocateInstruction()
	loadTypeID.AsLoad(functionInstancePtr, wazevoapi.FunctionInstanceTypeIDOffset, ssa.TypeI32)
	builder.InsertInstruction(loadTypeID)
	actualTypeID := loadTypeID.Return()

	// Next, we load the expected TypeID:
	loadTypeIDsBegin := builder.AllocateInstruction()
	loadTypeIDsBegin.AsLoad(c.moduleCtxPtrValue, c.offset.TypeIDs1stElement.U32(), ssa.TypeI64)
	builder.InsertInstruction(loadTypeIDsBegin)
	typeIDsBegin := loadTypeIDsBegin.Return()

	loadExpectedTypeID := builder.AllocateInstruction()
	loadExpectedTypeID.AsLoad(typeIDsBegin, uint32(typeIndex)*4 /* size of wasm.FunctionTypeID */, ssa.TypeI32)
	builder.InsertInstruction(loadExpectedTypeID)
	expectedTypeID := loadExpectedTypeID.Return()

	// Check if the type ID matches.
	checkTypeID := builder.AllocateInstruction()
	checkTypeID.AsIcmp(actualTypeID, expectedTypeID, ssa.IntegerCmpCondNotEqual)
	builder.InsertInstruction(checkTypeID)
	exitIfNotMatch := builder.AllocateInstruction()
	exitIfNotMatch.AsExitIfTrueWithCode(c.execCtxPtrValue, checkTypeID.Return(), wazevoapi.ExitCodeIndirectCallTypeMismatch)
	builder.InsertInstruction(exitIfNotMatch)

	// Now ready to call the function. Load the executable and moduleContextOpaquePtr from the function instance.
	loadExecutablePtr := builder.AllocateInstruction()
	loadExecutablePtr.AsLoad(functionInstancePtr, wazevoapi.FunctionInstanceExecutableOffset, ssa.TypeI64)
	builder.InsertInstruction(loadExecutablePtr)
	executablePtr := loadExecutablePtr.Return()
	loadModuleContextOpaquePtr := builder.AllocateInstruction()
	loadModuleContextOpaquePtr.AsLoad(functionInstancePtr, wazevoapi.FunctionInstanceModuleContextOpaquePtrOffset, ssa.TypeI64)
	builder.InsertInstruction(loadModuleContextOpaquePtr)
	moduleContextOpaquePtr := loadModuleContextOpaquePtr.Return()

	typ := &c.m.TypeSection[typeIndex]
	args := c.allocateVarLengthValues(2+len(typ.Params), c.execCtxPtrValue, moduleContextOpaquePtr)
	args = c.nPopInto(args, len(typ.Params))

	// Before transfer the control to the callee, we have to store the current module's moduleContextPtr
	// into execContext.callerModuleContextPtr in case when the callee is a Go function.
	c.storeCallerModuleContext()

	return executablePtr, typ, args
}

func (c *Compiler) lowerCallIndirect(typeIndex, tableIndex uint32) {
	builder := c.ssaBuilder
	executablePtr, typ, args := c.prepareCallIndirect(typeIndex, tableIndex)

	call := builder.AllocateInstruction()
	call.AsCallIndirect(executablePtr, c.signatures[typ], args)
	builder.InsertInstruction(call)

	// Exception handling: make this call's return site a landing pad so a throw from the
	// callee lands in the right handler. What a raise abandons is read before the results go
	// on the stack.
	var abandoned []stackValue
	if c.ehEnabled {
		abandoned = c.abandonedByRaise()
	}
	c.pushCallResults(call, typ.Results)
	if c.ehEnabled {
		c.emitCallExceptionEdge(abandoned)
	}

	c.reloadAfterCall()
}

func (c *Compiler) lowerTailCallReturnCall(fnIndex uint32) {
	isIndirect, typ, sig, args, funcRefOrPtrValue := c.prepareCall(fnIndex)
	builder := c.ssaBuilder
	c.releaseExnrefsOnTailCall()

	call := builder.AllocateInstruction()
	if isIndirect {
		call.AsTailCallReturnCallIndirect(ssa.Value(funcRefOrPtrValue), sig, args)
	} else {
		call.AsTailCallReturnCall(ssa.FuncRef(funcRefOrPtrValue), sig, args)
	}
	builder.InsertInstruction(call)

	// In a proper tail call, the following code is unreachable since execution
	// transfers to the callee. However, sometimes the backend might need to fall back to
	// a regular call, so we include return handling and let the backend delete it
	// when redundant.
	// For details, see internal/engine/RATIONALE.md
	c.pushCallResults(call, typ.Results)

	c.reloadAfterCall()
	c.lowerTailCallReturn(builder, call)
}

func (c *Compiler) lowerTailCallReturnCallIndirect(typeIndex, tableIndex uint32) {
	builder := c.ssaBuilder
	executablePtr, typ, args := c.prepareCallIndirect(typeIndex, tableIndex)
	c.releaseExnrefsOnTailCall()

	call := builder.AllocateInstruction()
	call.AsTailCallReturnCallIndirect(executablePtr, c.signatures[typ], args)
	builder.InsertInstruction(call)

	// In a proper tail call, the following code is unreachable since execution
	// transfers to the callee. However, sometimes the backend might need to fall back to
	// a regular call, so we include return handling and let the backend delete it
	// when redundant.
	// For details, see internal/engine/RATIONALE.md
	c.pushCallResults(call, typ.Results)

	c.reloadAfterCall()
	c.lowerTailCallReturn(builder, call)
}

func (c *Compiler) prepareCallRef(typeIndex uint32) (ssa.Value, *wasm.FunctionType, ssa.Values) {
	builder := c.ssaBuilder
	state := c.state()

	functionInstancePtr := state.pop()

	// Check if it is not the null pointer.
	zero := builder.AllocateInstruction()
	zero.AsIconst64(0)
	builder.InsertInstruction(zero)
	checkNull := builder.AllocateInstruction()
	checkNull.AsIcmp(functionInstancePtr, zero.Return(), ssa.IntegerCmpCondEqual)
	builder.InsertInstruction(checkNull)
	exitIfNull := builder.AllocateInstruction()
	exitIfNull.AsExitIfTrueWithCode(c.execCtxPtrValue, checkNull.Return(), wazevoapi.ExitCodeNullReference)
	builder.InsertInstruction(exitIfNull)

	// Load the executable and moduleContextOpaquePtr from the function instance.
	loadExecutablePtr := builder.AllocateInstruction()
	loadExecutablePtr.AsLoad(functionInstancePtr, wazevoapi.FunctionInstanceExecutableOffset, ssa.TypeI64)
	builder.InsertInstruction(loadExecutablePtr)
	executablePtr := loadExecutablePtr.Return()
	loadModuleContextOpaquePtr := builder.AllocateInstruction()
	loadModuleContextOpaquePtr.AsLoad(functionInstancePtr, wazevoapi.FunctionInstanceModuleContextOpaquePtrOffset, ssa.TypeI64)
	builder.InsertInstruction(loadModuleContextOpaquePtr)
	moduleContextOpaquePtr := loadModuleContextOpaquePtr.Return()

	typ := &c.m.TypeSection[typeIndex]
	args := c.allocateVarLengthValues(2+len(typ.Params), c.execCtxPtrValue, moduleContextOpaquePtr)
	args = c.nPopInto(args, len(typ.Params))

	c.storeCallerModuleContext()

	return executablePtr, typ, args
}

func (c *Compiler) lowerCallRef(typeIndex uint32) {
	builder := c.ssaBuilder
	executablePtr, typ, args := c.prepareCallRef(typeIndex)

	call := builder.AllocateInstruction()
	call.AsCallIndirect(executablePtr, c.signatures[typ], args)
	builder.InsertInstruction(call)

	// Exception handling: make this call's return site a landing pad so a throw from the
	// callee lands in the right handler. What a raise abandons is read before the results go
	// on the stack -- on that path the callee returned none, so those slots hold nothing.
	// What a raise abandons is read before the results go on the stack: on that path the
	// callee returned none, so those slots hold nothing. The arguments are not here either --
	// their references went to the callee with them.
	var abandoned []stackValue
	if c.ehEnabled {
		abandoned = c.abandonedByRaise()
	}
	c.pushCallResults(call, typ.Results)
	if c.ehEnabled {
		c.emitCallExceptionEdge(abandoned)
	}

	c.reloadAfterCall()
}

func (c *Compiler) lowerTailCallReturnCallRef(typeIndex uint32) {
	builder := c.ssaBuilder
	executablePtr, typ, args := c.prepareCallRef(typeIndex)
	c.releaseExnrefsOnTailCall()

	call := builder.AllocateInstruction()
	call.AsTailCallReturnCallIndirect(executablePtr, c.signatures[typ], args)
	builder.InsertInstruction(call)

	// In a proper tail call, the following code is unreachable since execution
	// transfers to the callee. However, sometimes the backend might need to fall back to
	// a regular call, so we include return handling and let the backend delete it
	// when redundant.
	// For details, see internal/engine/RATIONALE.md
	c.pushCallResults(call, typ.Results)

	c.reloadAfterCall()
	c.lowerTailCallReturn(builder, call)
}

// memOpSetup inserts the bounds check and calculates the address of the memory operation (loads/stores).
func (c *Compiler) memOpSetup(baseAddr ssa.Value, constOffset, operationSizeInBytes uint64) (address ssa.Value) {
	address = ssa.ValueInvalid
	builder := c.ssaBuilder

	baseAddrID := baseAddr.ID()
	ceil := constOffset + operationSizeInBytes
	if known := c.getKnownSafeBound(baseAddrID); known.valid() {
		// We reuse the calculated absolute address even if the bound is not known to be safe.
		address = known.absoluteAddr
		if ceil <= known.bound {
			if !address.Valid() {
				// This means that, the bound is known to be safe, but the memory base might have changed.
				// So, we re-calculate the address.
				memBase := c.getMemoryBaseValue(false)
				extBaseAddr := builder.AllocateInstruction().
					AsUExtend(baseAddr, 32, 64).
					Insert(builder).
					Return()
				address = builder.AllocateInstruction().
					AsIadd(memBase, extBaseAddr).Insert(builder).Return()
				known.absoluteAddr = address // Update the absolute address for the subsequent memory access.
			}
			return
		}
	}

	ceilConst := builder.AllocateInstruction()
	ceilConst.AsIconst64(ceil)
	builder.InsertInstruction(ceilConst)

	// We calculate the offset in 64-bit space.
	extBaseAddr := builder.AllocateInstruction().
		AsUExtend(baseAddr, 32, 64).
		Insert(builder).
		Return()

	// Note: memLen is already zero extended to 64-bit space at the load time.
	memLen := c.getMemoryLenValue(false)

	// baseAddrPlusCeil = baseAddr + ceil
	baseAddrPlusCeil := builder.AllocateInstruction()
	baseAddrPlusCeil.AsIadd(extBaseAddr, ceilConst.Return())
	builder.InsertInstruction(baseAddrPlusCeil)

	// Check for out of bounds memory access: `memLen >= baseAddrPlusCeil`.
	cmp := builder.AllocateInstruction()
	cmp.AsIcmp(memLen, baseAddrPlusCeil.Return(), ssa.IntegerCmpCondUnsignedLessThan)
	builder.InsertInstruction(cmp)
	exitIfNZ := builder.AllocateInstruction()
	exitIfNZ.AsExitIfTrueWithCode(c.execCtxPtrValue, cmp.Return(), wazevoapi.ExitCodeMemoryOutOfBounds)
	builder.InsertInstruction(exitIfNZ)

	// Load the value from memBase + extBaseAddr.
	if address == ssa.ValueInvalid { // Reuse the value if the memBase is already calculated at this point.
		memBase := c.getMemoryBaseValue(false)
		address = builder.AllocateInstruction().
			AsIadd(memBase, extBaseAddr).Insert(builder).Return()
	}

	// Record the bound ceil for this baseAddr is known to be safe for the subsequent memory access in the same block.
	c.recordKnownSafeBound(baseAddrID, ceil, address)
	return
}

// atomicMemOpSetup inserts the bounds check and calculates the address of the memory operation (loads/stores), including
// the constant offset and performs an alignment check on the final address.
func (c *Compiler) atomicMemOpSetup(baseAddr ssa.Value, constOffset, operationSizeInBytes uint64) (address ssa.Value) {
	builder := c.ssaBuilder

	addrWithoutOffset := c.memOpSetup(baseAddr, constOffset, operationSizeInBytes)
	var addr ssa.Value
	if constOffset == 0 {
		addr = addrWithoutOffset
	} else {
		offset := builder.AllocateInstruction().AsIconst64(constOffset).Insert(builder).Return()
		addr = builder.AllocateInstruction().AsIadd(addrWithoutOffset, offset).Insert(builder).Return()
	}

	c.memAlignmentCheck(addr, operationSizeInBytes)

	return addr
}

func (c *Compiler) memAlignmentCheck(addr ssa.Value, operationSizeInBytes uint64) {
	if operationSizeInBytes == 1 {
		return // No alignment restrictions when accessing a byte
	}
	var checkBits uint64
	switch operationSizeInBytes {
	case 2:
		checkBits = 0b1
	case 4:
		checkBits = 0b11
	case 8:
		checkBits = 0b111
	}

	builder := c.ssaBuilder

	mask := builder.AllocateInstruction().AsIconst64(checkBits).Insert(builder).Return()
	masked := builder.AllocateInstruction().AsBand(addr, mask).Insert(builder).Return()
	zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder).Return()
	cmp := builder.AllocateInstruction().AsIcmp(masked, zero, ssa.IntegerCmpCondNotEqual).Insert(builder).Return()
	builder.AllocateInstruction().AsExitIfTrueWithCode(c.execCtxPtrValue, cmp, wazevoapi.ExitCodeUnalignedAtomic).Insert(builder)
}

func (c *Compiler) callMemmove(dst, src, size ssa.Value) {
	args := c.allocateVarLengthValues(3, dst, src, size)
	if size.Type() != ssa.TypeI64 {
		panic("TODO: memmove size must be i64")
	}

	builder := c.ssaBuilder
	memmovePtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetMemmoveAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	builder.AllocateInstruction().AsCallGoRuntimeMemmove(memmovePtr, &c.memmoveSig, args).Insert(builder)
}

func (c *Compiler) reloadAfterCall() {
	// Note that when these are not used in the following instructions, they will be optimized out.
	// So in any ways, we define them!

	// After calling any function, memory buffer might have changed. So we need to re-define the variable.
	// However, if the memory is shared, we don't need to reload the memory base and length as the base will never change.
	if c.needMemory && !c.memoryShared {
		c.reloadMemoryBaseLen()
	}

	// Also, any mutable Global can change.
	for _, index := range c.mutableGlobalVariablesIndexes {
		_ = c.getWasmGlobalValue(index, true)
	}
}

func (c *Compiler) reloadMemoryBaseLen() {
	_ = c.getMemoryBaseValue(true)
	_ = c.getMemoryLenValue(true)

	// This function being called means that the memory base might have changed.
	// Therefore, we need to clear the absolute addresses recorded in the known safe bounds
	// because we cache the absolute address of the memory access per each base offset.
	c.resetAbsoluteAddressInSafeBounds()
}

// globalType returns the value type of the global at index, imported or defined here.
func (c *Compiler) globalType(index wasm.Index) wasm.ValueType {
	if index < c.m.ImportGlobalCount {
		var seen wasm.Index
		for i := range c.m.ImportSection {
			imp := &c.m.ImportSection[i]
			if imp.Type != wasm.ExternTypeGlobal {
				continue
			}
			if seen == index {
				return imp.DescGlobal.ValType
			}
			seen++
		}
		panic("BUG: global index out of range of imported globals")
	}
	return c.m.GlobalSection[index-c.m.ImportGlobalCount].Type.ValType
}

// localType returns the value type of the local at index, which is a parameter first and one
// of the function's own declared locals after those.
func (c *Compiler) localType(index wasm.Index) wasm.ValueType {
	if params := c.wasmFunctionTyp.Params; index < wasm.Index(len(params)) {
		return params[index]
	}
	return c.wasmFunctionLocalTypes[index-wasm.Index(len(c.wasmFunctionTyp.Params))]
}

// exnrefGlobal reports whether the global at index holds exnrefs.
func (c *Compiler) exnrefGlobal(index wasm.Index) bool {
	return wasm.IsExnref(c.globalType(index))
}

// tableType returns the element type of the table at index, imported or defined here.
func (c *Compiler) tableType(index wasm.Index) wasm.ValueType {
	if index < c.m.ImportTableCount {
		var seen wasm.Index
		for i := range c.m.ImportSection {
			imp := &c.m.ImportSection[i]
			if imp.Type != wasm.ExternTypeTable {
				continue
			}
			if seen == index {
				return imp.DescTable.Type
			}
			seen++
		}
		panic("BUG: table index out of range of imported tables")
	}
	return c.m.TableSection[index-c.m.ImportTableCount].Type
}

// exnrefTable reports whether the table at index holds exnrefs.
func (c *Compiler) exnrefTable(index wasm.Index) bool {
	return wasm.IsExnref(c.tableType(index))
}

// wasmGlobalAddr returns the address of a global's value: inline in the module context for
// one this module defines, behind a pointer for an imported one.
func (c *Compiler) wasmGlobalAddr(index wasm.Index) ssa.Value {
	builder := c.ssaBuilder
	opaqueOffset := c.offset.GlobalInstanceOffset(index)
	if index < c.m.ImportGlobalCount {
		return builder.AllocateInstruction().
			AsLoad(c.moduleCtxPtrValue, uint32(opaqueOffset), ssa.TypeI64).
			Insert(builder).Return()
	}
	offset := builder.AllocateInstruction().AsIconst64(uint64(opaqueOffset)).Insert(builder).Return()
	return builder.AllocateInstruction().
		AsIadd(c.moduleCtxPtrValue, offset).Insert(builder).Return()
}

// loadExnrefSlot reads an exnref-typed slot through the runtime's read barrier, which pins
// what it names before compiled code gets the handle.
func (c *Compiler) loadExnrefSlot(addr ssa.Value) ssa.Value {
	builder := c.ssaBuilder
	c.storeCallerModuleContext()
	trampoline := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetExnrefSlotLoadTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	args := c.allocateVarLengthValues(2, c.execCtxPtrValue, addr)
	v := builder.AllocateInstruction().
		AsCallIndirect(trampoline, &c.exnrefSlotLoadSig, args).Insert(builder).Return()
	c.reloadAfterCall()
	return v
}

// fillExnrefSlots writes count exnref-typed slots at addr through the runtime's barrier.
func (c *Compiler) fillExnrefSlots(addr, value, count ssa.Value) {
	c.callExnrefSlotRun(wazevoapi.ExecutionContextOffsetExnrefSlotFillTrampolineAddress.U32(),
		&c.exnrefSlotFillSig, addr, value, count)
}

// copyExnrefSlots copies count exnref-typed slots from src to dst through the runtime's
// barrier, for table.copy and table.init.
func (c *Compiler) copyExnrefSlots(dst, src, count ssa.Value) {
	c.callExnrefSlotRun(wazevoapi.ExecutionContextOffsetExnrefSlotCopyTrampolineAddress.U32(),
		&c.exnrefSlotCopySig, dst, src, count)
}

func (c *Compiler) callExnrefSlotRun(trampolineOffset uint32, sig *ssa.Signature, a, b, count ssa.Value) {
	builder := c.ssaBuilder
	c.storeCallerModuleContext()
	trampoline := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue, trampolineOffset, ssa.TypeI64).Insert(builder).Return()
	args := c.allocateVarLengthValues(4, c.execCtxPtrValue, a, b, count)
	builder.AllocateInstruction().AsCallIndirect(trampoline, sig, args).Insert(builder)
	c.reloadAfterCall()
}

// adjustExnrefs emits the reference count adjustment for one exnref moving between an operand
// stack slot and a local: inc gains a reference, dec loses one. Either may be ssa.ValueInvalid
// for "nothing".
//
// The call is guarded on the handles being non-null, so a local that holds `ref.null exn` --
// which is every exnref local until something catches -- costs a compare and a not-taken
// branch and no exit. That is what keeps a function that never sees an exception free of this
// even when it has exnref locals.
func (c *Compiler) adjustExnrefs(inc, dec ssa.Value) {
	builder := c.ssaBuilder
	zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder).Return()

	// Non-null if either handle is, which is one test for the pair.
	var probe ssa.Value
	switch {
	case inc.Valid() && dec.Valid():
		or := builder.AllocateInstruction()
		or.AsBor(inc, dec)
		probe = or.Insert(builder).Return()
	case inc.Valid():
		probe = inc
	default:
		probe = dec
	}
	isNull := builder.AllocateInstruction().
		AsIcmp(probe, zero, ssa.IntegerCmpCondEqual).Insert(builder).Return()

	adjustBlk, contBlk := builder.AllocateBasicBlock(), builder.AllocateBasicBlock()
	builder.InsertInstruction(builder.AllocateInstruction().AsBrnz(isNull, ssa.ValuesNil, contBlk))
	c.insertJumpToBlock(ssa.ValuesNil, adjustBlk)

	builder.SetCurrentBlock(adjustBlk)
	incArg, decArg := inc, dec
	if !incArg.Valid() {
		incArg = zero
	}
	if !decArg.Valid() {
		decArg = zero
	}
	trampoline := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetAdjustExnrefsTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	args := c.allocateVarLengthValues(3, c.execCtxPtrValue, incArg, decArg)
	builder.AllocateInstruction().
		AsCallIndirect(trampoline, &c.adjustExnrefsSig, args).Insert(builder)
	c.insertJumpToBlock(ssa.ValuesNil, contBlk)
	builder.Seal(adjustBlk)

	builder.SetCurrentBlock(contBlk)
	builder.Seal(contBlk)
}

// The lowering releases exnref references at every point control leaves for somewhere that
// resumes with a shallower operand stack. Which slots those are is always a half-open range
// between two recorded heights, so every release site below reduces to releaseExnrefs.
//
// The height control resumes at is a compile-time constant for every transfer but one. A raise
// is the exception: which clause matches is decided at runtime by matchException, so a raise
// releases in two steps -- everything above the try_table at the raise site, then the rest at
// whichever dispatch arm is taken. That is the only place `to` below is not the stack top.

// releaseExnrefSlots releases the reference each exnref-typed slot holds. Every release in the
// lowering funnels through here.
func (c *Compiler) releaseExnrefSlots(svs []stackValue) {
	for _, sv := range svs {
		if wasm.IsExnref(sv.t) {
			c.adjustExnrefs(ssa.ValueInvalid, sv.v)
		}
	}
}

// releaseExnrefs releases what the frame stops owning as control leaves: the operand stack
// slots in [from, to), and -- when the frame itself does not survive the transfer -- what its
// exnref locals hold.
func (c *Compiler) releaseExnrefs(from, to int, withLocals bool) {
	c.releaseExnrefSlots(c.state().values[from:to])
	if withLocals {
		c.releaseExnrefLocals()
	}
}

// anyExnrefIn reports whether releaseExnrefs over the same range would emit anything, so that
// a conditional transfer only pays for a block of its own when there is something to release.
// Taking the same bounds is what keeps the question and the answer from drifting apart.
func (c *Compiler) anyExnrefIn(from, to int, withLocals bool) bool {
	for _, sv := range c.state().values[from:to] {
		if wasm.IsExnref(sv.t) {
			return true
		}
	}
	if withLocals {
		for i := 0; i < len(c.wasmFunctionTyp.Params)+len(c.wasmFunctionLocalTypes); i++ {
			if wasm.IsExnref(c.localType(wasm.Index(i))) {
				return true
			}
		}
	}
	return false
}

// branchRange is what a branch to labelIndex discards: everything above its label's height
// except the carried values it delivers from the top of the stack. Per the spec a branch
// unwinds the operand stack to its label's height, so those slots simply cease to exist.
//
// carried is a parameter rather than the label's own arity because br_on_non_null delivers one
// of the label's values from the operand it popped, so one fewer comes off the stack.
func (c *Compiler) branchRange(labelIndex uint32, carried int) (from, to int) {
	state := c.state()
	return state.ctrlPeekAt(int(labelIndex)).originalStackLenWithoutParam, len(state.values) - carried
}

// frameExitRange is what leaving the frame discards: every operand slot the return does not
// carry. Pair it with withLocals, since a frame's locals cease to exist with it.
func (c *Compiler) frameExitRange() (from, to int) {
	return 0, len(c.state().values) - c.results()
}

// takenEdgeTarget is the block a conditional branch to labelIndex should target, and the
// arguments to carry there. A branch discards operand stack slots, and leaving the frame
// discards its locals too, but only when the branch is taken -- so when there is anything to
// release, the branch is routed through a block of its own that releases and then jumps on.
// The third result reports whether that block was allocated here and so needs sealing.
//
// Every conditional branch shares this: br_if, br_on_null and br_on_non_null all discard the
// same way, and having said it once is what keeps them from drifting apart.
func (c *Compiler) takenEdgeTarget(
	labelIndex uint32, carried int, targetBlk ssa.BasicBlock, args ssa.Values,
) (ssa.BasicBlock, ssa.Values, bool) {
	builder := c.ssaBuilder
	isRet := targetBlk.ReturnBlock()

	// The listener has to be called before returning, which needs a block of its own even
	// when there is nothing to release.
	restructure := isRet && c.needListener
	from, to := c.branchRange(labelIndex, carried)
	if isRet {
		from, to = c.frameExitRange()
	}
	if !restructure && !c.anyExnrefIn(from, to, isRet) {
		return targetBlk, args, false
	}

	current := builder.CurrentBlock()
	tramp := builder.AllocateBasicBlock()
	builder.SetCurrentBlock(tramp)
	if !isRet {
		c.releaseExnrefs(from, to, false)
	}
	// A jump to the return block lowers as a return, carrying its arguments as the results,
	// and insertJumpToBlock is what calls the listener and releases the frame on that path.
	c.insertJumpToBlock(args, targetBlk)
	builder.SetCurrentBlock(current)
	return tramp, ssa.ValuesNil, true
}

// releaseExnrefsOnTailCall releases every reference the frame holds as a return_call replaces
// it: its exnref locals, and everything still on the operand stack, which the tail call
// discards in full. The arguments are not among them -- their references left with them, into
// the callee's parameters -- so this has to run after they have been popped.
//
// It also has to run *before* the tail call itself. A real tail call is a jump, so anything
// emitted after it only runs when the backend falls back to a regular call, and the frame it
// belongs to would leave without releasing anything. Releasing this early is safe because an
// argument the frame also keeps in a local was copied there by a local.get, which took a
// reference of its own.
func (c *Compiler) releaseExnrefsOnTailCall() {
	c.releaseExnrefs(0, len(c.state().values), true)
}

// releaseExnrefLocals releases what this frame's exnref locals hold, parameters included. A
// parameter is owned, not borrowed: the caller's reference moves into it when the call is made,
// so this frame is the one that has to let go. That is what makes a return_call work, where
// there is no "after the call" for a caller to release anything in.
//
// Which locals these are is known at compile time, so a function with none emits nothing.
func (c *Compiler) releaseExnrefLocals() {
	builder := c.ssaBuilder
	for i := 0; i < len(c.wasmFunctionTyp.Params)+len(c.wasmFunctionLocalTypes); i++ {
		if !wasm.IsExnref(c.localType(wasm.Index(i))) {
			continue
		}
		c.adjustExnrefs(ssa.ValueInvalid, builder.MustFindValue(c.localVariable(wasm.Index(i))))
	}
}

// storeExnrefSlot writes an exnref-typed slot through the runtime's write barrier, which
// does the write itself so the slot and the runtime's count cannot disagree.
func (c *Compiler) storeExnrefSlot(addr, v ssa.Value) {
	builder := c.ssaBuilder
	c.storeCallerModuleContext()
	trampoline := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetExnrefSlotStoreTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	args := c.allocateVarLengthValues(3, c.execCtxPtrValue, addr, v)
	builder.AllocateInstruction().
		AsCallIndirect(trampoline, &c.exnrefSlotStoreSig, args).Insert(builder)
	c.reloadAfterCall()
}

func (c *Compiler) setWasmGlobalValue(index wasm.Index, v ssa.Value) {
	variable := c.globalVariables[index]
	opaqueOffset := c.offset.GlobalInstanceOffset(index)

	builder := c.ssaBuilder
	if index < c.m.ImportGlobalCount {
		loadGlobalInstPtr := builder.AllocateInstruction()
		loadGlobalInstPtr.AsLoad(c.moduleCtxPtrValue, uint32(opaqueOffset), ssa.TypeI64)
		builder.InsertInstruction(loadGlobalInstPtr)

		store := builder.AllocateInstruction()
		store.AsStore(ssa.OpcodeStore, v, loadGlobalInstPtr.Return(), uint32(0))
		builder.InsertInstruction(store)

	} else {
		store := builder.AllocateInstruction()
		store.AsStore(ssa.OpcodeStore, v, c.moduleCtxPtrValue, uint32(opaqueOffset))
		builder.InsertInstruction(store)
	}

	// The value has changed to `v`, so we record it.
	builder.DefineVariableInCurrentBB(variable, v)
}

func (c *Compiler) getWasmGlobalValue(index wasm.Index, forceLoad bool) ssa.Value {
	variable := c.globalVariables[index]
	typ := c.globalVariablesTypes[index]
	opaqueOffset := c.offset.GlobalInstanceOffset(index)

	builder := c.ssaBuilder
	if !forceLoad {
		if v := builder.FindValueInLinearPath(variable); v.Valid() {
			return v
		}
	}

	var load *ssa.Instruction
	if index < c.m.ImportGlobalCount {
		loadGlobalInstPtr := builder.AllocateInstruction()
		loadGlobalInstPtr.AsLoad(c.moduleCtxPtrValue, uint32(opaqueOffset), ssa.TypeI64)
		builder.InsertInstruction(loadGlobalInstPtr)
		load = builder.AllocateInstruction().
			AsLoad(loadGlobalInstPtr.Return(), uint32(0), typ)
	} else {
		load = builder.AllocateInstruction().
			AsLoad(c.moduleCtxPtrValue, uint32(opaqueOffset), typ)
	}

	v := load.Insert(builder).Return()
	builder.DefineVariableInCurrentBB(variable, v)
	return v
}

const (
	memoryInstanceBufOffset     = 0
	memoryInstanceBufSizeOffset = memoryInstanceBufOffset + 8
)

func (c *Compiler) getMemoryBaseValue(forceReload bool) ssa.Value {
	builder := c.ssaBuilder
	variable := c.memoryBaseVariable
	if !forceReload {
		if v := builder.FindValueInLinearPath(variable); v.Valid() {
			return v
		}
	}

	var ret ssa.Value
	if c.offset.LocalMemoryBegin < 0 {
		loadMemInstPtr := builder.AllocateInstruction()
		loadMemInstPtr.AsLoad(c.moduleCtxPtrValue, c.offset.ImportedMemoryBegin.U32(), ssa.TypeI64)
		builder.InsertInstruction(loadMemInstPtr)
		memInstPtr := loadMemInstPtr.Return()

		loadBufPtr := builder.AllocateInstruction()
		loadBufPtr.AsLoad(memInstPtr, memoryInstanceBufOffset, ssa.TypeI64)
		builder.InsertInstruction(loadBufPtr)
		ret = loadBufPtr.Return()
	} else {
		load := builder.AllocateInstruction()
		load.AsLoad(c.moduleCtxPtrValue, c.offset.LocalMemoryBase().U32(), ssa.TypeI64)
		builder.InsertInstruction(load)
		ret = load.Return()
	}

	builder.DefineVariableInCurrentBB(variable, ret)
	return ret
}

func (c *Compiler) getMemoryLenValue(forceReload bool) ssa.Value {
	variable := c.memoryLenVariable
	builder := c.ssaBuilder
	if !forceReload && !c.memoryShared {
		if v := builder.FindValueInLinearPath(variable); v.Valid() {
			return v
		}
	}

	var ret ssa.Value
	if c.offset.LocalMemoryBegin < 0 {
		loadMemInstPtr := builder.AllocateInstruction()
		loadMemInstPtr.AsLoad(c.moduleCtxPtrValue, c.offset.ImportedMemoryBegin.U32(), ssa.TypeI64)
		builder.InsertInstruction(loadMemInstPtr)
		memInstPtr := loadMemInstPtr.Return()

		loadBufSizePtr := builder.AllocateInstruction()
		if c.memoryShared {
			sizeOffset := builder.AllocateInstruction().AsIconst64(memoryInstanceBufSizeOffset).Insert(builder).Return()
			addr := builder.AllocateInstruction().AsIadd(memInstPtr, sizeOffset).Insert(builder).Return()
			loadBufSizePtr.AsAtomicLoad(addr, 8, ssa.TypeI64)
		} else {
			loadBufSizePtr.AsLoad(memInstPtr, memoryInstanceBufSizeOffset, ssa.TypeI64)
		}
		builder.InsertInstruction(loadBufSizePtr)

		ret = loadBufSizePtr.Return()
	} else {
		load := builder.AllocateInstruction()
		if c.memoryShared {
			lenOffset := builder.AllocateInstruction().AsIconst64(c.offset.LocalMemoryLen().U64()).Insert(builder).Return()
			addr := builder.AllocateInstruction().AsIadd(c.moduleCtxPtrValue, lenOffset).Insert(builder).Return()
			load.AsAtomicLoad(addr, 8, ssa.TypeI64)
		} else {
			load.AsExtLoad(ssa.OpcodeUload32, c.moduleCtxPtrValue, c.offset.LocalMemoryLen().U32(), true)
		}
		builder.InsertInstruction(load)
		ret = load.Return()
	}

	builder.DefineVariableInCurrentBB(variable, ret)
	return ret
}

func (c *Compiler) insertIcmp(cond ssa.IntegerCmpCond) {
	state, builder := c.state(), c.ssaBuilder
	y, x := state.pop(), state.pop()
	cmp := builder.AllocateInstruction()
	cmp.AsIcmp(x, y, cond)
	builder.InsertInstruction(cmp)
	value := cmp.Return()
	state.push(value, wasm.ValueTypeI32)
}

func (c *Compiler) insertFcmp(cond ssa.FloatCmpCond) {
	state, builder := c.state(), c.ssaBuilder
	y, x := state.pop(), state.pop()
	cmp := builder.AllocateInstruction()
	cmp.AsFcmp(x, y, cond)
	builder.InsertInstruction(cmp)
	value := cmp.Return()
	state.push(value, wasm.ValueTypeI32)
}

// storeCallerModuleContext stores the current module's moduleContextPtr into execContext.callerModuleContextPtr.
func (c *Compiler) storeCallerModuleContext() {
	builder := c.ssaBuilder
	execCtx := c.execCtxPtrValue
	store := builder.AllocateInstruction()
	store.AsStore(ssa.OpcodeStore,
		c.moduleCtxPtrValue, execCtx, wazevoapi.ExecutionContextOffsetCallerModuleContextPtr.U32())
	builder.InsertInstruction(store)
}

// resolveTagType returns the FunctionType for the tag at the given module-local index, which
// validation has already put in range.
func (c *Compiler) resolveTagType(tagIndex uint32) *wasm.FunctionType {
	if tagIndex < c.m.ImportTagCount {
		cur := uint32(0)
		for i := range c.m.ImportSection {
			imp := &c.m.ImportSection[i]
			if imp.Type != wasm.ExternTypeTag {
				continue
			}
			if tagIndex == cur {
				return &c.m.TypeSection[imp.DescTag]
			}
			cur++
		}
	} else if tagSectionIdx := tagIndex - c.m.ImportTagCount; tagSectionIdx < uint32(len(c.m.TagSection)) {
		return &c.m.TypeSection[c.m.TagSection[tagSectionIdx].Type]
	}
	panic("BUG: tag index out of range")
}

// currentRaiseTarget returns the block an in-flight exception must branch to from
// the current lowering point: the innermost enclosing try_table-with-catch's
// dispatch block, or — if there is none — the function's propagate block (which
// returns to propagate the exception to the caller). The dispatch block is built
// on demand here so that try_tables whose bodies never raise stay free of blocks.
func (c *Compiler) currentRaiseTarget() ssa.BasicBlock {
	return c.raiseTargetAbove(len(c.state().controlFrames))
}

// raiseTargetAbove returns the raise target for a point logically above control
// frame index `idx` (exclusive): the innermost enclosing try_table-with-catch's
// dispatch block, or the function propagate block if there is none.
func (c *Compiler) raiseTargetAbove(idx int) ssa.BasicBlock {
	state := c.state()
	for i := idx - 1; i >= 0; i-- {
		if state.controlFrames[i].isTryCatch() {
			return c.ensureDispatchBlock(i)
		}
	}
	return c.propagateBlock()
}

// raiseHeightAbove is the operand stack height control comes to rest at for a raise from a
// point logically above control frame index `idx`: the innermost enclosing try_table-with-
// catch's, or zero if there is none, since then the exception leaves the function. Everything
// above it is discarded by the raise, so it pairs with raiseTargetAbove -- what that returns
// is reached with the stack unwound to this.
func (c *Compiler) raiseHeightAbove(idx int) int {
	state := c.state()
	for i := idx - 1; i >= 0; i-- {
		if f := &state.controlFrames[i]; f.isTryCatch() {
			return f.originalStackLenWithoutParam
		}
	}
	return 0
}

// ensureDispatchBlock returns the dispatch block for the try_table-with-catch at
// control frame index `i`, building it (and its handler blocks) on first use.
func (c *Compiler) ensureDispatchBlock(i int) ssa.BasicBlock {
	f := &c.state().controlFrames[i]
	if f.dispatchBlock != nil {
		return f.dispatchBlock
	}
	builder := c.ssaBuilder
	cur := builder.CurrentBlock()

	// The no-match default re-raises to the next enclosing handler (or propagate).
	// Resolve it first; this may recursively build enclosing dispatch blocks, so
	// only handlers that can actually be reached are ever created.
	enclosingRaise := c.raiseTargetAbove(i)

	dispatchBlk := builder.AllocateBasicBlock()
	// The dispatch block is this try_table's shared raise target: it is reached both by
	// the per-call landing pads (emitCallExceptionEdge) and by compiled jumps (an
	// explicit throw inside the try, or an inner dispatch's no-match re-raise). It calls
	// matchException and branches to the matched catch handler or re-raises.
	f.dispatchBlock = dispatchBlk

	// Build the dispatch block first: ask Go to match the in-flight exception against
	// this try_table's clauses. matchException returns the matched clause index (for the
	// br_table below), the exnref, and the raise's params buffer -- the handlers consume
	// the last two directly, so they never read execCtx. On a match it ends the raise, so
	// a handler that returns normally is no longer mistaken for a propagating frame.
	builder.SetCurrentBlock(dispatchBlk)
	c.storeCallerModuleContext()
	matchPtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetMatchExceptionTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	tryTableIDVal := builder.AllocateInstruction().
		AsIconst64(wazevoapi.TryTableID(uint32(c.wasmLocalFunctionIndex), uint32(f.tryTableOrdinal))).
		Insert(builder).Return()
	matchArgs := c.allocateVarLengthValues(2, c.execCtxPtrValue, tryTableIDVal)
	clauseIdx, matchRest := builder.AllocateInstruction().
		AsCallIndirect(matchPtr, &c.matchExceptionSig, matchArgs).
		Insert(builder).Returns()
	exnref := matchRest[0]
	// The params live behind a pointer in execCtx rather than coming back as a result: the
	// field is a Go slice, so it is what keeps the buffer from being collected while the
	// handler reads through it. Loaded here so it dominates every handler block; each of
	// them consumes it immediately, which is what makes the next match free to overwrite it.
	paramsPtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetCaughtExceptionParams.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	c.reloadAfterCall()

	// Allocate the br_table's targets: one block per catch clause, plus a trampoline for
	// the no-match default. The default goes through a trampoline so the br_table is never
	// a direct predecessor of the enclosing dispatch block, which reads variables
	// (reloadAfterCall) and so can acquire phis -- and a phi's argument has to be attached
	// to each predecessor branch, which a br_table cannot carry.
	raiseTramp := builder.AllocateBasicBlock()
	varPool := builder.VarLengthPool()
	targets := varPool.Allocate(len(f.catches) + 1) // +1 for the default (no-match) target.
	handlers := make([]ssa.BasicBlock, len(f.catches))
	for i := range f.catches {
		handlers[i] = builder.AllocateBasicBlock()
		targets = targets.Append(varPool, ssa.Value(handlers[i].ID()))
	}
	// Last target is the no-match default (the trampoline to the enclosing raise
	// target). clauseIdx == -1 lands here via br_table clamping.
	targets = targets.Append(varPool, ssa.Value(raiseTramp.ID()))

	// Branch on the matched clause index, back in the dispatch block. This goes in before
	// the targets have anything in them, because inserting it is what registers the dispatch
	// block as their predecessor, and they cannot be sealed until it has.
	builder.SetCurrentBlock(dispatchBlk)
	brTable := builder.AllocateInstruction()
	brTable.AsBrTable(clauseIdx, targets)
	builder.InsertInstruction(brTable)

	// Seal the br_table target blocks: catch-clause handlers and the no-match trampoline.
	// Each has the dispatch block as its only predecessor, now wired, and none has been
	// written to yet -- so a variable a handler goes on to read (releasing an exnref local
	// reads all of them) resolves through the dispatch block, and the phi argument lands on
	// the ordinary jumps that reach it rather than on this br_table.
	//
	// The dispatch block itself is sealed at the matching End once its body predecessors are
	// lowered; the enclosing raise target is sealed elsewhere (its own End, or function End
	// for the propagate block).
	for _, targetID := range targets.View() {
		blk := builder.BasicBlock(ssa.BasicBlockID(targetID))
		if !blk.Sealed() {
			builder.Seal(blk)
		}
	}

	builder.SetCurrentBlock(raiseTramp)
	// No clause matched, so the exception carries on past this try_table to the enclosing
	// raise target, unwinding to whatever height that one comes to rest at. The slots between
	// there and this try_table's height go here: the landing pad only released what was above
	// this try_table, and an enclosing handler only releases what is below its own.
	c.releaseExnrefs(c.raiseHeightAbove(i), f.originalStackLenWithoutParam, false)
	c.insertJumpToBlock(ssa.ValuesNil, enclosingRaise)

	for i, rc := range f.catches {
		builder.SetCurrentBlock(handlers[i])

		// Load the exception params out of the buffer execCtx points at and jump to the
		// resolved wasm target. Both that pointer and the exnref are defined in the
		// dispatch block, which dominates this single-predecessor handler block.
		var brArgs []ssa.Value
		switch rc.clause.kind {
		case wasm.CatchKindCatch:
			brArgs = c.loadExceptionParams(paramsPtr, c.resolveTagType(rc.clause.tagIndex))
		case wasm.CatchKindCatchRef:
			brArgs = c.loadExceptionParams(paramsPtr, c.resolveTagType(rc.clause.tagIndex))
			brArgs = append(brArgs, exnref)
		case wasm.CatchKindCatchAll:
			// No values.
		case wasm.CatchKindCatchAllRef:
			brArgs = append(brArgs, exnref)
		}

		jmpArgs := c.allocateVarLengthValues(len(brArgs), brArgs...)
		c.branchToCatchTarget(rc, f.originalStackLenWithoutParam, jmpArgs)
	}

	builder.SetCurrentBlock(cur)
	return dispatchBlk
}

// branchToCatchTarget emits a matched catch clause's branch out of its handler block:
// whatever the branch unwinds past is released, then it jumps to the resolved target with
// the values the clause hands over.
//
// It spells this out rather than going through insertJumpToBlock, whose frame-exit handling
// reads the operand stack wherever lowering happens to be. That is the wrong stack here: the
// dispatch block is built lazily at the first raise inside the try body, which is not where
// control leaves from. What leaves is fixed by the try_table's height and the clause's label,
// and by nothing else.
func (c *Compiler) branchToCatchTarget(rc resolvedCatch, tryHeight int, args ssa.Values) {
	builder := c.ssaBuilder
	isRet := rc.targetBlk.ReturnBlock()
	if isRet && c.needListener {
		// The results are the ones the clause pushed, not the top of the operand stack:
		// this is not a fall-through return.
		c.callListenerAfterWith(args)
	}
	// isRet carries the locals: a label at the function's own depth unwinds to height zero,
	// so the range already covers every operand slot and only the locals remain.
	c.releaseExnrefs(rc.targetHeight, tryHeight, isRet)
	jmp := builder.AllocateInstruction()
	jmp.AsJump(args, rc.targetBlk)
	builder.InsertInstruction(jmp)
}

// propagateBlock returns the per-function block an uncaught exception returns through:
// it calls the propagate-exception trampoline (so the runtime redirects this return into
// the caller's landing pad) and returns. The result values are placeholders. Created lazily.
func (c *Compiler) propagateBlock() ssa.BasicBlock {
	if c.exceptionPropagateBlk == nil {
		c.exceptionPropagateBlk = c.buildPropagateBlock(true)
	}
	return c.exceptionPropagateBlk
}

// propagateBlockAfterFrameRelease is propagateBlock for a raise reaching a frame that has
// already let go of everything it held.
//
// A return_call releases its locals before the call, since a real tail call leaves no "after
// the call" to do it in. When the backend falls back to a plain call and the callee raises,
// the frame is still on the stack but owns nothing, so propagating through the ordinary block
// would release its locals a second time -- dropping references the frame no longer holds.
func (c *Compiler) propagateBlockAfterFrameRelease() ssa.BasicBlock {
	if c.exceptionPropagateAfterReleaseBlk == nil {
		c.exceptionPropagateAfterReleaseBlk = c.buildPropagateBlock(false)
	}
	return c.exceptionPropagateAfterReleaseBlk
}

// buildPropagateBlock builds a propagate block, releasing the frame's exnref locals on the
// way out unless the frame has already let go of them.
func (c *Compiler) buildPropagateBlock(releaseLocals bool) ssa.BasicBlock {
	builder := c.ssaBuilder
	cur := builder.CurrentBlock()
	blk := builder.AllocateBasicBlock()
	builder.SetCurrentBlock(blk)

	// Table-driven propagation, by return-address patching. The exception leaves this
	// function: we call the throw trampoline (an ordinary Go call — it saves/restores
	// the callee-saved file via the normal go-call ABI) and then RETURN normally. While
	// in the trampoline, the runtime overwrites THIS frame's saved return address with
	// the caller's exception landing-pad PC (see ExitCodeThrow). So our ordinary epilogue
	// restores the caller's registers exactly as a normal return would, and the final
	// `ret` lands in the caller's landing pad instead of its normal continuation — no
	// register reconstruction, no per-ISA EH prologue/epilogue. Reached by a COMPILED
	// jump (emitRaise dispatch no-match).
	//
	// If the exception propagates past the outermost wasm frame with no matching
	// handler, the patch finds no landing pad there, so this frame returns to the entry
	// normally and the top-level loop converts the pending exception into
	// ErrRuntimeUncaughtException. matchException clears the pending exception when
	// a clause matches.
	//
	// The frame is leaving without returning, so the releases a return would have run have to
	// happen here: its exnref locals cease to exist with it. Operand stack slots abandoned by
	// the raise are released by the landing pad it came through, which is the only place what
	// was on the stack at that point is known.
	if releaseLocals {
		c.releaseExnrefLocals()
	}

	c.storeCallerModuleContext()
	propagateExceptionPtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetPropagateExceptionTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	propagateExceptionArgs := c.allocateVarLengthValues(1, c.execCtxPtrValue)
	builder.AllocateInstruction().
		AsCallIndirect(propagateExceptionPtr, &c.propagateExceptionSig, propagateExceptionArgs).
		Insert(builder)

	// Return to the (patched) caller landing pad. The result values are placeholder but
	// a real return is what carries us into the caller with its registers restored.
	results := c.wasmFunctionTyp.Results
	var wasmRets ssa.Values
	if len(results) > 0 {
		vs := make([]ssa.Value, len(results))
		for i, vt := range results {
			vs[i] = c.zeroValue(WasmTypeToSSAType(vt))
		}
		wasmRets = c.allocateVarLengthValues(len(vs), vs...)
	} else {
		wasmRets = ssa.ValuesNil
	}
	ret := builder.AllocateInstruction()
	ret.AsReturn(wasmRets)
	builder.InsertInstruction(ret)
	// Sealed at function End, once all propagating predecessors are wired.
	builder.SetCurrentBlock(cur)
	return blk
}

// zeroValue emits a zero constant of the given SSA type.
func (c *Compiler) zeroValue(t ssa.Type) ssa.Value {
	builder := c.ssaBuilder
	instr := builder.AllocateInstruction()
	switch t {
	case ssa.TypeI32:
		instr.AsIconst32(0)
	case ssa.TypeI64:
		instr.AsIconst64(0)
	case ssa.TypeF32:
		instr.AsF32const(0)
	case ssa.TypeF64:
		instr.AsF64const(0)
	case ssa.TypeV128:
		instr.AsVconst(0, 0)
	default:
		panic("BUG: unsupported result type for exception propagation: " + t.String())
	}
	builder.InsertInstruction(instr)
	return instr.Return()
}

// emitRaise branches to the current raise target, which propagates the exception the
// runtime has recorded as in flight. A throw records it in the allocate-exception
// trampoline; throw_ref has to say so itself, which is what emitRaiseRef does first.
func (c *Compiler) emitRaise() {
	target := c.currentRaiseTarget()
	state := c.state()
	c.releaseExnrefs(c.raiseHeightAbove(len(state.controlFrames)), len(state.values), false)
	c.insertJumpToBlock(ssa.ValuesNil, target)
}

// emitRaiseRef records exnref as the exception in flight, then raises it.
func (c *Compiler) emitRaiseRef(exnref ssa.Value) {
	builder := c.ssaBuilder
	c.storeCallerModuleContext()
	trampoline := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetRaiseRefTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	args := c.allocateVarLengthValues(2, c.execCtxPtrValue, exnref)
	builder.AllocateInstruction().
		AsCallIndirect(trampoline, &c.raiseRefSig, args).Insert(builder)
	c.reloadAfterCall()
	c.emitRaise()
}

// pushCallResults pushes a call's wasm results onto the value stack, typed by the callee's
// signature -- which is the only thing that says whether a result is an i64 or a reference.
func (c *Compiler) pushCallResults(call *ssa.Instruction, results []wasm.ValueType) {
	state := c.state()
	first, rest := call.Returns()
	i := 0
	if first.Valid() {
		state.push(first, results[i])
		i++
	}
	for _, v := range rest {
		state.push(v, results[i])
		i++
	}
}

// emitCallExceptionEdge makes the just-emitted call's return site an exception landing
// pad, so a throw from the callee lands in this call's handler. It adds a phantom
// exception edge from the post-call block to a landing pad that routes to this call's
// catch dispatch (when the call is inside a try_table) or to the propagate block, then
// continues normal lowering in a fresh continuation block.
//
// The edge emits no instruction on the normal path. It exists so layout/liveness/regalloc
// treat the landing pad as a real successor (the values the handler needs stay live
// across the call), and so branch-lowering records this call's return PC -> landing-pad
// PC in the per-function exception table. On a throw the runtime patches the frame's
// saved return address to that landing pad, redirecting the call's ordinary return into
// the handler.
func (c *Compiler) emitCallExceptionEdge(abandoned []stackValue) {
	c.emitExceptionEdge(c.currentRaiseTarget(), abandoned)
}

// abandonedByRaise is the operand stack slots a raise from the current point throws away:
// everything above the height control resumes at, which is the innermost enclosing
// try_table-with-catch's, or the whole frame's if there is none, since then the exception
// leaves the function.
//
// The result aliases the value stack, so callers that go on to lower more instructions must
// use it before the stack moves under them.
func (c *Compiler) abandonedByRaise() []stackValue {
	state := c.state()
	return slices.Clone(state.values[c.raiseHeightAbove(len(state.controlFrames)):])
}

// emitTailCallExceptionEdge is emitCallExceptionEdge for a return_call. It matters when
// the backend falls back to a plain call — the callee then returns into this still-live
// frame rather than replacing it, so its return site needs a landing pad like any other
// call. For a real tail call the pad is unreachable dead code, since no live frame's
// return address can be inside a block whose call was lowered to a jump.
//
// The pad routes to the propagate block rather than to the current raise target: per the
// spec return_call has already returned from this function, so an exception raised by the
// callee must bypass any try_table the return_call is lexically inside.
func (c *Compiler) emitTailCallExceptionEdge() {
	// The frame is already gone as far as the spec is concerned, so the return_call's own exit
	// path released everything it held -- its locals and its whole operand stack alike -- before
	// making the call. That leaves this pad nothing of its own to release, and it has to
	// propagate through the entry that does not release the locals either.
	c.emitExceptionEdge(c.propagateBlockAfterFrameRelease(), nil)
}

// emitExceptionEdge wires the current block's trailing call to a landing pad routing to
// raiseTarget, then continues lowering in a fresh continuation block.
func (c *Compiler) emitExceptionEdge(raiseTarget ssa.BasicBlock, abandoned []stackValue) {
	builder := c.ssaBuilder

	// The landing pad is entered only by the runtime's redirected return; it just routes
	// to the shared dispatch (in a try_table) or propagate target.
	landingPad := builder.AllocateBasicBlock()

	// Post-call block: the phantom edge to the landing pad, then the fall-through jump to
	// the continuation. The edge registers the landing pad as a predecessor, so seal it
	// only afterwards.
	edge := builder.AllocateInstruction()
	edge.AsExceptionEdge(ssa.ValuesNil, landingPad)
	builder.InsertInstruction(edge)

	contBlk := builder.AllocateBasicBlock()
	c.insertJumpToBlock(ssa.ValuesNil, contBlk)

	builder.SetCurrentBlock(landingPad)
	// A raise out of this call abandons whatever the operand stack holds above where control
	// resumes, so their references have to go here -- this is the only place that knows the
	// stack shape at this particular call site. The values are live in the pad because the
	// phantom edge makes it a real successor of the call.
	c.releaseExnrefSlots(abandoned)
	c.insertJumpToBlock(ssa.ValuesNil, raiseTarget)
	builder.Seal(landingPad)

	builder.Seal(contBlk)
	builder.SetCurrentBlock(contBlk)
}

// catchClause holds a parsed catch clause from a try_table instruction.
type catchClause struct {
	kind     byte
	tagIndex uint32
	labelIdx uint32
}

// loadExceptionParams reads the caught exception's params out of paramsPtr, the buffer
// execCtx.caughtExceptionParams points at, one per param at [ptr + i*8], mirroring the
// stores emitted by the throw lowering. Float params were bitcast to integers at the throw site, so we load
// as integer and bitcast back to the original type.
func (c *Compiler) loadExceptionParams(paramsPtr ssa.Value, tagType *wasm.FunctionType) []ssa.Value {
	if len(tagType.Params) == 0 {
		return nil
	}
	builder := c.ssaBuilder

	var values []ssa.Value
	for i, vt := range tagType.Params {
		offset := uint32(i) * 8
		ssaType := WasmTypeToSSAType(vt)
		switch ssaType {
		case ssa.TypeF32:
			// Stored as i32 at throw site; bitcast back to f32.
			raw := builder.AllocateInstruction().
				AsLoad(paramsPtr, offset, ssa.TypeI32).
				Insert(builder).Return()
			val := builder.AllocateInstruction().AsBitcast(raw, ssa.TypeF32).Insert(builder).Return()
			values = append(values, val)
		case ssa.TypeF64:
			// Stored as i64 at throw site; bitcast back to f64.
			raw := builder.AllocateInstruction().
				AsLoad(paramsPtr, offset, ssa.TypeI64).
				Insert(builder).Return()
			val := builder.AllocateInstruction().AsBitcast(raw, ssa.TypeF64).Insert(builder).Return()
			values = append(values, val)
		default:
			val := builder.AllocateInstruction().
				AsLoad(paramsPtr, offset, ssaType).
				Insert(builder).Return()
			values = append(values, val)
		}
	}
	return values
}

// skipTryTableCatchClauses advances the bytecode PC past the catch clauses
// of a try_table instruction. This is used both in reachable and unreachable states.
func (c *Compiler) skipTryTableCatchClauses() {
	c.loweringState.pc++
	catchCount, catchNum, _ := leb128.LoadUint32(c.wasmFunctionBody[c.loweringState.pc:])
	c.loweringState.pc += int(catchNum) - 1
	for i := uint32(0); i < catchCount; i++ {
		c.loweringState.pc++
		kind := c.wasmFunctionBody[c.loweringState.pc]
		switch kind {
		case wasm.CatchKindCatch, wasm.CatchKindCatchRef:
			// Read tag index.
			c.loweringState.pc++
			_, n, _ := leb128.LoadUint32(c.wasmFunctionBody[c.loweringState.pc:])
			c.loweringState.pc += int(n) - 1
			// Read label index.
			c.loweringState.pc++
			_, n, _ = leb128.LoadUint32(c.wasmFunctionBody[c.loweringState.pc:])
			c.loweringState.pc += int(n) - 1
		case wasm.CatchKindCatchAll, wasm.CatchKindCatchAllRef:
			// Read label index.
			c.loweringState.pc++
			_, n, _ := leb128.LoadUint32(c.wasmFunctionBody[c.loweringState.pc:])
			c.loweringState.pc += int(n) - 1
		}
	}
}

func (c *Compiler) readByte() byte {
	v := c.wasmFunctionBody[c.loweringState.pc+1]
	c.loweringState.pc++
	return v
}

func (c *Compiler) readI32u() uint32 {
	v, n, err := leb128.LoadUint32(c.wasmFunctionBody[c.loweringState.pc+1:])
	if err != nil {
		panic(err) // shouldn't be reached since compilation comes after validation.
	}
	c.loweringState.pc += int(n)
	return v
}

func (c *Compiler) readI32s() int32 {
	v, n, err := leb128.LoadInt32(c.wasmFunctionBody[c.loweringState.pc+1:])
	if err != nil {
		panic(err) // shouldn't be reached since compilation comes after validation.
	}
	c.loweringState.pc += int(n)
	return v
}

func (c *Compiler) readI64s() int64 {
	v, n, err := leb128.LoadInt64(c.wasmFunctionBody[c.loweringState.pc+1:])
	if err != nil {
		panic(err) // shouldn't be reached since compilation comes after validation.
	}
	c.loweringState.pc += int(n)
	return v
}

func (c *Compiler) readF32() float32 {
	v := math.Float32frombits(binary.LittleEndian.Uint32(c.wasmFunctionBody[c.loweringState.pc+1:]))
	c.loweringState.pc += 4
	return v
}

func (c *Compiler) readF64() float64 {
	v := math.Float64frombits(binary.LittleEndian.Uint64(c.wasmFunctionBody[c.loweringState.pc+1:]))
	c.loweringState.pc += 8
	return v
}

// readBlockType reads the block type from the current position of the bytecode reader.
func (c *Compiler) readBlockType() *wasm.FunctionType {
	state := c.state()

	c.br.Reset(c.wasmFunctionBody[state.pc+1:])
	bt, num, err := wasm.DecodeBlockType(c.m.TypeSection, c.br, api.CoreFeaturesV2)
	if err != nil {
		panic(err) // shouldn't be reached since compilation comes after validation.
	}
	state.pc += int(num)

	return bt
}

func (c *Compiler) readMemArg() (align, offset uint32) {
	state := c.state()

	align, num, err := leb128.LoadUint32(c.wasmFunctionBody[state.pc+1:])
	if err != nil {
		panic(fmt.Errorf("read memory align: %v", err))
	}

	state.pc += int(num)
	offset, num, err = leb128.LoadUint32(c.wasmFunctionBody[state.pc+1:])
	if err != nil {
		panic(fmt.Errorf("read memory offset: %v", err))
	}

	state.pc += int(num)
	return align, offset
}

// insertJumpToBlock inserts a jump instruction to the given block in the current block.
func (c *Compiler) insertJumpToBlock(args ssa.Values, targetBlk ssa.BasicBlock) {
	if targetBlk.ReturnBlock() {
		if c.needListener {
			c.callListenerAfter()
		}
		// The frame is leaving, so its references go. Doing it here rather than at each
		// return-shaped instruction is what covers the implicit return at the function's End,
		// which reaches the return block by an ordinary jump like any branch to it does.
		from, to := c.frameExitRange()
		c.releaseExnrefs(from, to, true)
	}

	builder := c.ssaBuilder
	jmp := builder.AllocateInstruction()
	jmp.AsJump(args, targetBlk)
	builder.InsertInstruction(jmp)
}

// lowerModuleClosed fills in the block a loop's module-closed check branches to when it finds
// the flag set. It calls back into Go, which fails the call with the module's exit code, and
// jumps back to the check for the case where the module turns out not to be closed after all
// and the call returns. Going back to the check rather than into the body is what leaves the
// body with a single predecessor, and so with no block parameters.
//
// This runs at the loop's End, not where the check is emitted, because block layout follows
// the order blocks were first written to: written last, this one lands after the whole loop,
// and the check falls through into the body instead of branching to it.
func (c *Compiler) lowerModuleClosed(ctrl *controlFrame) {
	builder := c.ssaBuilder
	builder.SetCurrentBlock(ctrl.moduleClosedBlk)

	checkModuleExitCodePtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetCheckModuleExitCodeTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	builder.AllocateInstruction().
		AsCallIndirect(checkModuleExitCodePtr, &c.checkModuleExitCodeSig,
			c.allocateVarLengthValues(1, c.execCtxPtrValue)).
		Insert(builder)

	// The loop header is still unsealed, so its parameters are still only the loop's own:
	// the ones any local read inside the body needs are added when it is sealed, just
	// after this, and this branch gets its arguments for them then, like every other
	// predecessor does.
	loopHeader := ctrl.blk
	backArgs := c.allocateVarLengthValues(loopHeader.Params())
	for i := 0; i < loopHeader.Params(); i++ {
		backArgs = backArgs.Append(builder.VarLengthPool(), loopHeader.Param(i))
	}
	c.insertJumpToBlock(backArgs, loopHeader)
	builder.Seal(ctrl.moduleClosedBlk)
}

// insertIntegerExtend widens the operand from a from-bit value to a to-typed one. to is the
// Wasm type the opcode extends to, which the width to extend to follows from -- that direction
// is the sound one, the way back is not.
func (c *Compiler) insertIntegerExtend(signed bool, from byte, to wasm.ValueType) {
	state := c.state()
	builder := c.ssaBuilder
	v := state.pop()
	extend := builder.AllocateInstruction()
	if toBits := WasmTypeToSSAType(to).Bits(); signed {
		extend.AsSExtend(v, from, toBits)
	} else {
		extend.AsUExtend(v, from, toBits)
	}
	builder.InsertInstruction(extend)
	state.push(extend.Return(), to)
}

// switchTo adjusts the operand stack to originalStackLen and starts translating targetBlk,
// pushing its parameters back. paramTypes are their Wasm types, which the block's SSA
// parameters do not carry.
func (c *Compiler) switchTo(originalStackLen int, targetBlk ssa.BasicBlock, paramTypes []wasm.ValueType) {
	if targetBlk.Preds() == 0 {
		c.loweringState.unreachable = true
	}

	// Now we should adjust the stack and start translating the continuation block.
	c.loweringState.truncate(originalStackLen)

	c.ssaBuilder.SetCurrentBlock(targetBlk)

	// At this point, blocks params consist only of the Wasm-level parameters,
	// (since it's added only when we are trying to resolve variable *inside* this block).
	for i := 0; i < targetBlk.Params(); i++ {
		c.loweringState.push(targetBlk.Param(i), paramTypes[i])
	}
}

// results returns the number of results of the current function.
func (c *Compiler) results() int {
	return len(c.wasmFunctionTyp.Results)
}

func (c *Compiler) lowerBrTable(labels []uint32, index ssa.Value) {
	state := c.state()
	builder := c.ssaBuilder

	f := state.ctrlPeekAt(int(labels[0]))
	var numArgs int
	if f.isLoop() {
		numArgs = len(f.blockType.Params)
	} else {
		numArgs = len(f.blockType.Results)
	}

	varPool := builder.VarLengthPool()
	trampolineBlockIDs := varPool.Allocate(len(labels))

	// We need trampoline blocks since depending on the target block structure, we might end up inserting moves before jumps,
	// which cannot be done with br_table. Instead, we can do such per-block moves in the trampoline blocks.
	// At the linking phase (very end of the backend), we can remove the unnecessary jumps, and therefore no runtime overhead.
	currentBlk := builder.CurrentBlock()
	for _, l := range labels {
		// Args are always on the top of the stack. Note that we should not share the args slice
		// among the jump instructions since the args are modified during passes (e.g. redundant phi elimination).
		args := c.nPeekDup(numArgs)
		targetBlk, _ := state.brTargetArgNumFor(l)
		trampoline := builder.AllocateBasicBlock()
		builder.SetCurrentBlock(trampoline)
		// Each target unwinds to its own label's height, so what it discards is its own; the
		// trampoline is where that can be said per target. A target that is the return block
		// is handled by insertJumpToBlock.
		if !targetBlk.ReturnBlock() {
			from, to := c.branchRange(l, numArgs)
			c.releaseExnrefs(from, to, false)
		}
		c.insertJumpToBlock(args, targetBlk)
		trampolineBlockIDs = trampolineBlockIDs.Append(builder.VarLengthPool(), ssa.Value(trampoline.ID()))
	}
	builder.SetCurrentBlock(currentBlk)

	// If the target block has no arguments, we can just jump to the target block.
	brTable := builder.AllocateInstruction()
	brTable.AsBrTable(index, trampolineBlockIDs)
	builder.InsertInstruction(brTable)

	for _, trampolineID := range trampolineBlockIDs.View() {
		builder.Seal(builder.BasicBlock(ssa.BasicBlockID(trampolineID)))
	}
}

func (l *loweringState) brTargetArgNumFor(labelIndex uint32) (targetBlk ssa.BasicBlock, argNum int) {
	targetFrame := l.ctrlPeekAt(int(labelIndex))
	if targetFrame.isLoop() {
		targetBlk, argNum = targetFrame.blk, len(targetFrame.blockType.Params)
	} else {
		targetBlk, argNum = targetFrame.followingBlock, len(targetFrame.blockType.Results)
	}
	return
}

func (c *Compiler) callListenerBefore() {
	c.storeCallerModuleContext()

	builder := c.ssaBuilder
	beforeListeners1stElement := builder.AllocateInstruction().
		AsLoad(c.moduleCtxPtrValue,
			c.offset.BeforeListenerTrampolines1stElement.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()

	beforeListenerPtr := builder.AllocateInstruction().
		AsLoad(beforeListeners1stElement, uint32(c.wasmFunctionTypeIndex)*8 /* 8 bytes per index */, ssa.TypeI64).Insert(builder).Return()

	entry := builder.EntryBlock()
	ps := entry.Params()

	args := c.allocateVarLengthValues(ps, c.execCtxPtrValue,
		builder.AllocateInstruction().AsIconst32(c.wasmLocalFunctionIndex).Insert(builder).Return())
	for i := 2; i < ps; i++ {
		args = args.Append(builder.VarLengthPool(), entry.Param(i))
	}

	beforeSig := c.listenerSignatures[c.wasmFunctionTyp][0]
	builder.AllocateInstruction().
		AsCallIndirect(beforeListenerPtr, beforeSig, args).
		Insert(builder)
}

// callListenerAfter calls the after-listener with the function's results, which on an
// ordinary return are the top of the operand stack.
func (c *Compiler) callListenerAfter() {
	c.callListenerAfterWith(c.nPeekDup(c.results()))
}

// callListenerAfterWith is callListenerAfter for a return whose results are not the top of
// the operand stack: a catch clause branching to the function's own label returns what the
// clause handed over, and the stack it left behind is discarded rather than returned.
func (c *Compiler) callListenerAfterWith(results ssa.Values) {
	c.storeCallerModuleContext()

	builder := c.ssaBuilder
	afterListeners1stElement := builder.AllocateInstruction().
		AsLoad(c.moduleCtxPtrValue,
			c.offset.AfterListenerTrampolines1stElement.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()

	afterListenerPtr := builder.AllocateInstruction().
		AsLoad(afterListeners1stElement,
			uint32(c.wasmFunctionTypeIndex)*8 /* 8 bytes per index */, ssa.TypeI64).
		Insert(builder).
		Return()

	afterSig := c.listenerSignatures[c.wasmFunctionTyp][1]
	args := c.allocateVarLengthValues(
		c.results()+2,
		c.execCtxPtrValue,
		builder.AllocateInstruction().AsIconst32(c.wasmLocalFunctionIndex).Insert(builder).Return(),
	)

	pool := builder.VarLengthPool()
	for _, v := range results.View() {
		args = args.Append(pool, v)
	}
	builder.AllocateInstruction().
		AsCallIndirect(afterListenerPtr, afterSig, args).
		Insert(builder)
}

const (
	elementOrDataInstanceLenOffset = 8
	elementOrDataInstanceSize      = 24
)

// dropInstance inserts instructions to drop the element/data instance specified by the given index.
func (c *Compiler) dropDataOrElementInstance(index uint32, firstItemOffset wazevoapi.Offset) {
	builder := c.ssaBuilder
	instPtr := c.dataOrElementInstanceAddr(index, firstItemOffset)

	zero := builder.AllocateInstruction().AsIconst64(0).Insert(builder).Return()

	// Clear the instance.
	builder.AllocateInstruction().AsStore(ssa.OpcodeStore, zero, instPtr, 0).Insert(builder)
	builder.AllocateInstruction().AsStore(ssa.OpcodeStore, zero, instPtr, elementOrDataInstanceLenOffset).Insert(builder)
	builder.AllocateInstruction().AsStore(ssa.OpcodeStore, zero, instPtr, elementOrDataInstanceLenOffset+8).Insert(builder)
}

func (c *Compiler) dataOrElementInstanceAddr(index uint32, firstItemOffset wazevoapi.Offset) ssa.Value {
	builder := c.ssaBuilder

	_1stItemPtr := builder.
		AllocateInstruction().
		AsLoad(c.moduleCtxPtrValue, firstItemOffset.U32(), ssa.TypeI64).
		Insert(builder).Return()

	// Each data/element instance is a slice, so we need to multiply index by 16 to get the offset of the target instance.
	index = index * elementOrDataInstanceSize
	indexExt := builder.AllocateInstruction().AsIconst64(uint64(index)).Insert(builder).Return()
	// Then, add the offset to the address of the instance.
	instPtr := builder.AllocateInstruction().AsIadd(_1stItemPtr, indexExt).Insert(builder).Return()
	return instPtr
}

func (c *Compiler) boundsCheckInDataOrElementInstance(instPtr, offsetInInstance, copySize ssa.Value, exitCode wazevoapi.ExitCode) {
	builder := c.ssaBuilder
	dataInstLen := builder.AllocateInstruction().
		AsLoad(instPtr, elementOrDataInstanceLenOffset, ssa.TypeI64).
		Insert(builder).Return()
	ceil := builder.AllocateInstruction().AsIadd(offsetInInstance, copySize).Insert(builder).Return()
	cmp := builder.AllocateInstruction().
		AsIcmp(dataInstLen, ceil, ssa.IntegerCmpCondUnsignedLessThan).
		Insert(builder).
		Return()
	builder.AllocateInstruction().
		AsExitIfTrueWithCode(c.execCtxPtrValue, cmp, exitCode).
		Insert(builder)
}

func (c *Compiler) boundsCheckInTable(tableIndex uint32, offset, size ssa.Value) (tableInstancePtr ssa.Value) {
	builder := c.ssaBuilder
	dstCeil := builder.AllocateInstruction().AsIadd(offset, size).Insert(builder).Return()

	// Load the table.
	tableInstancePtr = builder.AllocateInstruction().
		AsLoad(c.moduleCtxPtrValue, c.offset.TableOffset(int(tableIndex)).U32(), ssa.TypeI64).
		Insert(builder).Return()

	// Load the table's length.
	tableLen := builder.AllocateInstruction().
		AsLoad(tableInstancePtr, tableInstanceLenOffset, ssa.TypeI32).Insert(builder).Return()
	tableLenExt := builder.AllocateInstruction().AsUExtend(tableLen, 32, 64).Insert(builder).Return()

	// Compare the length and the target, and trap if out of bounds.
	checkOOB := builder.AllocateInstruction()
	checkOOB.AsIcmp(tableLenExt, dstCeil, ssa.IntegerCmpCondUnsignedLessThan)
	builder.InsertInstruction(checkOOB)
	exitIfOOB := builder.AllocateInstruction()
	exitIfOOB.AsExitIfTrueWithCode(c.execCtxPtrValue, checkOOB.Return(), wazevoapi.ExitCodeTableOutOfBounds)
	builder.InsertInstruction(exitIfOOB)
	return
}

func (c *Compiler) loadTableBaseAddr(tableInstancePtr ssa.Value) ssa.Value {
	builder := c.ssaBuilder
	loadTableBaseAddress := builder.
		AllocateInstruction().
		AsLoad(tableInstancePtr, tableInstanceBaseAddressOffset, ssa.TypeI64).
		Insert(builder)
	return loadTableBaseAddress.Return()
}

func (c *Compiler) boundsCheckInMemory(memLen, offset, size ssa.Value) {
	builder := c.ssaBuilder
	ceil := builder.AllocateInstruction().AsIadd(offset, size).Insert(builder).Return()
	cmp := builder.AllocateInstruction().
		AsIcmp(memLen, ceil, ssa.IntegerCmpCondUnsignedLessThan).
		Insert(builder).
		Return()
	builder.AllocateInstruction().
		AsExitIfTrueWithCode(c.execCtxPtrValue, cmp, wazevoapi.ExitCodeMemoryOutOfBounds).
		Insert(builder)
}
