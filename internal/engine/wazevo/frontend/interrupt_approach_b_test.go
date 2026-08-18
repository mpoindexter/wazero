//go:build efficient_interrupt_approach_b && !efficient_interrupt_approach_d

package frontend

// Expected SSA for the "loop - br / ensure termination" case in
// TestCompiler_LowerToSSA, under approach B: a plain load of
// ModuleInstance.Closed, then a counter block that reaches the trampoline call
// once every defaultInterruptCheckInterval back-edges.
// 0x4e0 is ExecutionContextOffsetModuleClosedPtr, 0x4e8 is
// ExecutionContextOffsetInterruptCounter, 0x58 is
// ExecutionContextOffsetCheckModuleExitCodeTrampolineAddress, and 0xff is
// defaultInterruptCheckInterval-1.

const loopBrEnsureTerminationExp = `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk1

blk1: () <-- (blk0,blk6)
	v2:i64 = Load exec_ctx, 0x4e0
	v3:i64 = Load v2, 0x0
	Brnz v3, blk3
	Jump blk4

blk2: ()

blk3: () <-- (blk1,blk4)
	v9:i64 = Load exec_ctx, 0x58
	CallIndirect v9:sig2, exec_ctx
	Jump blk6

blk4: () <-- (blk1)
	v4:i64 = Load exec_ctx, 0x4e8
	v5:i64 = Iconst_64 0x1
	v6:i64 = Iadd v4, v5
	Store v6, exec_ctx, 0x4e8
	v7:i64 = Iconst_64 0xff
	v8:i64 = Band v6, v7
	Brz v8, blk3
	Jump blk5

blk5: () <-- (blk4)
	Jump blk6

blk6: () <-- (blk5,blk3)
	Jump blk1
`

const loopBrEnsureTerminationExpAfterPasses = `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump fallthrough

blk1: () <-- (blk0,blk6)
	v2:i64 = Load exec_ctx, 0x4e0
	v3:i64 = Load v2, 0x0
	Brnz v3, blk7
	Jump fallthrough

blk4: () <-- (blk1)
	v4:i64 = Load exec_ctx, 0x4e8
	v5:i64 = Iconst_64 0x1
	v6:i64 = Iadd v4, v5
	Store v6, exec_ctx, 0x4e8
	v7:i64 = Iconst_64 0xff
	v8:i64 = Band v6, v7
	Brz v8, blk8
	Jump fallthrough

blk5: () <-- (blk4)
	Jump blk6

blk7: () <-- (blk1)
	Jump blk3

blk8: () <-- (blk4)
	Jump fallthrough

blk3: () <-- (blk7,blk8)
	v9:i64 = Load exec_ctx, 0x58
	CallIndirect v9:sig2, exec_ctx
	Jump fallthrough

blk6: () <-- (blk5,blk3)
	Jump blk1
`
