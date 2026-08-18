//go:build efficient_interrupt_approach_b && !efficient_interrupt_approach_d

package frontend

import (
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// defaultInterruptCheckInterval is the number of loop back-edges between two unconditional
// exits to Go code, used when the embedder does not set one via
// experimental.WithInterruptCheckInterval.
//
// The exit is there to be a safepoint, not to check anything: the Closed test on every
// back-edge already handles interruption promptly. So the interval trades throughput
// against how long the rest of the process waits on a spinning module -- a stop-the-world
// GC in particular, which has to meet every wasm goroutine several times before it can
// finish, and so waits for rather more than one interval.
//
// 256 is what https://github.com/wazero/wazero/pull/2525 measured as the largest value that
// leaves GC pauses and scheduler latency no worse than exiting on every back-edge, which is
// what this replaces.
//
// Must be a power of two: the lowering tests interval-1 as a bit mask.
const defaultInterruptCheckInterval uint64 = 1 << 8

// lowerLoopTerminationCheck emits the termination check at a loop header
// (approach B: inline flag test plus a 1-of-N exit to Go).
//
// Two tests, in this order:
//
//   - Test the module's closed state inline, and exit to the host only when it is set.
//     What the checkModuleExitCode trampoline goes to Go to fetch is a single word
//     (wasm.ModuleInstance.Closed, whose address the call engine puts in the execution
//     context), so read it here and keep the trampoline call on the cold path. This is
//     what makes interruption prompt without paying the barrier crossing.
//
//   - Increment a counter and exit unconditionally every Nth back-edge. The Closed test
//     above cannot be the only exit from native code, because the Go runtime cannot
//     asynchronously preempt a goroutine executing wazevo-generated machine code. A
//     spinning loop would never reach a safepoint, and a stop-the-world GC would livelock
//     on it, freezing the very goroutine that would deliver the close. When Closed is
//     clear the trampoline returns immediately, and the round trip through Go is itself
//     the safepoint.
//
// Compiled code reads Closed with a plain 64-bit load rather than an atomic one. That is
// tear-free on the architectures wazevo supports, since the word is naturally aligned (see
// Test_moduleClosedPtrLayout), and only eventual visibility is needed: the counter-driven
// exit bounds how long a stale read can delay the check.
//
// The counter lives in its own block so that each test stays a single fused
// compare-and-branch: LowerConditionalBranch only folds a comparison into the branch when
// it is the branch's direct operand, so combining the two tests into one condition would
// instead materialize both through cset/setcc.
//
// On return the current block is afterBlk, not the loop header, so the rest of the loop is
// lowered there.
func (c *Compiler) lowerLoopTerminationCheck(_ *wasm.FunctionType, _ int) {
	builder := c.ssaBuilder

	interval := c.interruptCheckInterval
	if interval == 0 {
		interval = defaultInterruptCheckInterval
	}

	closedPtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetModuleClosedPtr.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	closed := builder.AllocateInstruction().
		AsLoad(closedPtr, 0, ssa.TypeI64).Insert(builder).Return()

	checkBlk, counterBlk, fastBlk, afterBlk :=
		builder.AllocateBasicBlock(), builder.AllocateBasicBlock(),
		builder.AllocateBasicBlock(), builder.AllocateBasicBlock()

	builder.AllocateInstruction().AsBrnz(closed, ssa.ValuesNil, checkBlk).Insert(builder)
	builder.AllocateInstruction().AsJump(ssa.ValuesNil, counterBlk).Insert(builder)

	builder.SetCurrentBlock(counterBlk)
	counter := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetInterruptCounter.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	one := builder.AllocateInstruction().AsIconst64(1).Insert(builder).Return()
	next := builder.AllocateInstruction().AsIadd(counter, one).Insert(builder).Return()
	builder.AllocateInstruction().
		AsStore(ssa.OpcodeStore, next, c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetInterruptCounter.U32()).
		Insert(builder)
	maskVal := builder.AllocateInstruction().AsIconst64(interval - 1).Insert(builder).Return()
	masked := builder.AllocateInstruction().AsBand(next, maskVal).Insert(builder).Return()
	brz := builder.AllocateInstruction()
	brz.AsBrz(masked, ssa.ValuesNil, checkBlk)
	brz.Insert(builder)
	builder.AllocateInstruction().AsJump(ssa.ValuesNil, fastBlk).Insert(builder)
	builder.Seal(counterBlk)

	// Fill the fast path before the slow one. sortBlocks orders a block's successors by the id of
	// their first instruction, that order drives the DFS building reverse post-order, and
	// maybeInvertBranches makes whichever successor comes next in RPO the fallthrough. Emitting
	// into the hot block first is what keeps the cold trampoline call out of the loop's fallthrough
	// path; without it the taken branch is on the common path and the call sits inline.
	builder.SetCurrentBlock(fastBlk)
	builder.AllocateInstruction().AsJump(ssa.ValuesNil, afterBlk).Insert(builder)
	builder.Seal(fastBlk)

	builder.SetCurrentBlock(checkBlk)
	checkModuleExitCodePtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetCheckModuleExitCodeTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	args := c.allocateVarLengthValues(1, c.execCtxPtrValue)
	builder.AllocateInstruction().
		AsCallIndirect(checkModuleExitCodePtr, &c.checkModuleExitCodeSig, args).
		Insert(builder)
	builder.AllocateInstruction().AsJump(ssa.ValuesNil, afterBlk).Insert(builder)

	builder.Seal(checkBlk)
	builder.SetCurrentBlock(afterBlk)
	builder.Seal(afterBlk)
}
