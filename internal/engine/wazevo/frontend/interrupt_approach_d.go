//go:build efficient_interrupt_approach_d && !efficient_interrupt_approach_b

package frontend

import (
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// lowerLoopTerminationCheck emits the termination check at a loop header
// (approach D: runtime coordination).
//
// Cheap inline check: load moduleClosedPtr from execCtx, then atomically load
// the uint64 it points to (ModuleInstance.Closed). If zero, fall through to
// the loop body. If non-zero (set by the cancellation watchdog OR by an
// explicit module.Close from another goroutine), branch to the slow path,
// which makes the trampoline call that re-enters Go and reports the error via
// FailIfClosed.
//
// Never exiting to Go on the fast path is only safe because the native-code
// segment runs inside runtime.entersyscall/exitsyscall (see
// wazevo/runtime_syscall.go), which lets the watchdog run regardless.
//
// Both loads are plain, including the cross-thread read of Closed. On the
// architectures wazevo compiles for that is enough: the word is naturally
// aligned so an 8-byte load cannot tear against the writer's
// atomic.Uint64.CompareAndSwap, and both are cache-coherent, so a store from
// the closing goroutine becomes visible to this one in bounded time. Acquire
// ordering is not needed either, because nothing here consumes data published
// alongside the flag -- a non-zero read only routes to the trampoline, and the
// FailIfClosed on the far side of it does its own atomic load.
//
// On return the current block is loopBody, not the loop header, so the rest of
// the loop is lowered there.
func (c *Compiler) lowerLoopTerminationCheck(bt *wasm.FunctionType, originalLen int) {
	builder := c.ssaBuilder
	state := c.state()

	closedPtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetModuleClosedPtr.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	flag := builder.AllocateInstruction().
		AsLoad(closedPtr, 0, ssa.TypeI64).Insert(builder).Return()

	slowPath := builder.AllocateBasicBlock()
	fastPath := builder.AllocateBasicBlock()
	loopBody := builder.AllocateBasicBlock()
	c.addBlockParamsFromWasmTypes(bt.Params, slowPath)
	c.addBlockParamsFromWasmTypes(bt.Params, fastPath)
	c.addBlockParamsFromWasmTypes(bt.Params, loopBody)

	// Forward the loop's params (loopHeader's block params, currently on
	// the value stack at state.values[originalLen:]) through both branches.
	fwdArgs := c.allocateVarLengthValues(len(bt.Params), state.values[originalLen:]...)

	builder.AllocateInstruction().
		AsBrnz(flag, fwdArgs, slowPath).
		Insert(builder)
	c.insertJumpToBlock(fwdArgs, fastPath)

	// Fill the fast path before the slow one. sortBlocks orders a block's successors by the id of
	// their first instruction, that order drives the DFS that builds reverse post-order, and
	// maybeInvertBranches makes whichever successor comes next in RPO the fallthrough. Emitting
	// into the hot block first is therefore what puts the cold trampoline call out of line.
	builder.SetCurrentBlock(fastPath)
	fastParams := make([]ssa.Value, fastPath.Params())
	for i := range fastParams {
		fastParams[i] = fastPath.Param(i)
	}
	c.insertJumpToBlock(c.allocateVarLengthValues(len(fastParams), fastParams...), loopBody)
	builder.Seal(fastPath)

	// Slow path: the approach-A trampoline call, then jump to the loop body.
	builder.SetCurrentBlock(slowPath)
	checkModuleExitCodePtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetCheckModuleExitCodeTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	callArgs := c.allocateVarLengthValues(1, c.execCtxPtrValue)
	builder.AllocateInstruction().
		AsCallIndirect(checkModuleExitCodePtr, &c.checkModuleExitCodeSig, callArgs).
		Insert(builder)
	slowPathParams := make([]ssa.Value, slowPath.Params())
	for i := range slowPathParams {
		slowPathParams[i] = slowPath.Param(i)
	}
	c.insertJumpToBlock(c.allocateVarLengthValues(len(slowPathParams), slowPathParams...), loopBody)

	builder.Seal(slowPath)
	c.switchTo(originalLen, loopBody)
	builder.Seal(loopBody)
}
