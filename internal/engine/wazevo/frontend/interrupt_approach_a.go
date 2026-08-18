//go:build !efficient_interrupt_approach_b && !efficient_interrupt_approach_d

package frontend

import (
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// lowerLoopTerminationCheck emits the termination check at a loop header
// (approach A: the current upstream behavior).
//
// Every iteration calls the checkModuleExitCode trampoline, which exits to Go
// and reports the error via FailIfClosed. Exiting to Go each iteration is what
// lets other goroutines -- in particular the cancellation watchdog -- run, at
// the cost of a Go barrier crossing per back-edge.
//
// The check emits no control flow, so the current block is still the loop
// header on return and the loop body is lowered straight after it.
func (c *Compiler) lowerLoopTerminationCheck(_ *wasm.FunctionType, _ int) {
	builder := c.ssaBuilder

	checkModuleExitCodePtr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetCheckModuleExitCodeTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()

	args := c.allocateVarLengthValues(1, c.execCtxPtrValue)
	builder.AllocateInstruction().
		AsCallIndirect(checkModuleExitCodePtr, &c.checkModuleExitCodeSig, args).
		Insert(builder)
}
