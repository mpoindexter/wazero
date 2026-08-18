//go:build !efficient_interrupt_approach_b && !efficient_interrupt_approach_d

package frontend

// Expected SSA for the "loop - br / ensure termination" case in
// TestCompiler_LowerToSSA, under approach A: an unconditional trampoline call
// in the loop header, emitting no extra control flow.

const loopBrEnsureTerminationExp = `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk1

blk1: () <-- (blk0,blk1)
	v2:i64 = Load exec_ctx, 0x58
	CallIndirect v2:sig2, exec_ctx
	Jump blk1

blk2: ()
`

const loopBrEnsureTerminationExpAfterPasses = `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump fallthrough

blk1: () <-- (blk0,blk1)
	v2:i64 = Load exec_ctx, 0x58
	CallIndirect v2:sig2, exec_ctx
	Jump blk1
`
