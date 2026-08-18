//go:build efficient_interrupt_approach_d && !efficient_interrupt_approach_b

package frontend

// Expected SSA for the "loop - br / ensure termination" case in
// TestCompiler_LowerToSSA, under approach D: an inline atomic load of
// ModuleInstance.Closed guarding a slow path that keeps the trampoline call.
// 0x4e0 is ExecutionContextOffsetModuleClosedPtr, 0x58 is
// ExecutionContextOffsetCheckModuleExitCodeTrampolineAddress.

const loopBrEnsureTerminationExp = `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk1

blk1: () <-- (blk0,blk5)
	v2:i64 = Load exec_ctx, 0x4e0
	v3:i64 = Load v2, 0x0
	Brnz v3, blk3
	Jump blk4

blk2: ()

blk3: () <-- (blk1)
	v4:i64 = Load exec_ctx, 0x58
	CallIndirect v4:sig2, exec_ctx
	Jump blk5

blk4: () <-- (blk1)
	Jump blk5

blk5: () <-- (blk4,blk3)
	Jump blk1
`

const loopBrEnsureTerminationExpAfterPasses = `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump fallthrough

blk1: () <-- (blk0,blk5)
	v2:i64 = Load exec_ctx, 0x4e0
	v3:i64 = Load v2, 0x0
	Brnz v3, blk3
	Jump fallthrough

blk4: () <-- (blk1)
	Jump blk5

blk3: () <-- (blk1)
	v4:i64 = Load exec_ctx, 0x58
	CallIndirect v4:sig2, exec_ctx
	Jump fallthrough

blk5: () <-- (blk4,blk3)
	Jump blk1
`
