package amd64

import (
	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend/regalloc"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
)

// PostRegAlloc implements backend.Machine.
func (m *machine) PostRegAlloc() {
	m.setupPrologue()
	m.postRegAlloc()
	m.compensateLandingPadRSP()
}

// compensateLandingPadRSP undoes, at each table-driven-EH landing pad, the stack pointer
// adjustment its call site is bracketed by.
//
// postRegAlloc brackets a call whose arguments and results do not all fit in registers
// with `sub $size, %rsp` / `add $size, %rsp`. A landing pad is entered by overwriting the
// callee's saved return address, so control resumes there rather than at the trailing
// `add`, and %rsp stays lowered by the argument area for the rest of the frame -- which
// corrupts every %rsp-relative spill slot access and the epilogue's pops. Re-applying the
// `add` at the very top of the pad, ahead of any reconciliation moves register allocation
// placed there for the dispatch block, restores the frame's canonical %rsp.
//
// arm64 needs no equivalent: it reserves the argument area within the frame
// (maxRequiredStackSizeForCalls), so its stack pointer does not move across a call.
func (m *machine) compensateLandingPadRSP() {
	for _, pos := range m.orderedSSABlockLabelPos {
		size := m.landingPadCallStackSize(pos.sb)
		if size == 0 {
			continue
		}
		// pos.begin is the block's head nop, so splicing here lands ahead of everything.
		add := m.allocateInstr().asAluRmiR(aluRmiROpcodeAdd, newOperandImm32(size), rspVReg, true)
		next := pos.begin.next
		linkInstr(pos.begin, add)
		linkInstr(add, next)
	}
}

// landingPadCallStackSize returns the argument/result area size of the call whose landing
// pad blk is: zero unless blk is entered by an ssa.OpcodeExceptionEdge, and zero when that
// call passes everything in registers.
func (m *machine) landingPadCallStackSize(blk ssa.BasicBlock) uint32 {
	// A landing pad is entered only by the runtime redirecting a return, so its sole
	// predecessor is the block holding the call it belongs to.
	if blk == nil || blk.Preds() != 1 {
		return 0
	}
	callBlk := blk.Pred(0)
	var isLandingPad bool
	// Branching instructions all sit at the tail of a block, and an exception edge is one
	// of them -- it just emits no code. See backend.compiler.lowerBranches.
	for cur := callBlk.Tail(); cur != nil && cur.IsBranching(); cur = cur.Prev() {
		if cur.Opcode() != ssa.OpcodeExceptionEdge {
			continue
		}
		if _, _, target := cur.BranchData(); target == blk.ID() {
			isLandingPad = true
			break
		}
	}
	if !isLandingPad {
		return 0
	}

	pos := m.labelPositionPool.Get(int(callBlk.ID()))
	if pos == nil {
		return 0
	}
	// The call is the last one in its block: the exception edge terminates the block right
	// after it, and any earlier call is a Go trampoline, which resumes through
	// afterGoFunctionCallEntrypoint rather than through a landing pad.
	var size uint32
	for cur := pos.begin; cur != nil; cur = cur.next {
		if cur.kind == call || cur.kind == callIndirect {
			_, _, _, _, size = backend.ABIInfoFromUint64(cur.u2)
		}
		if cur == pos.end {
			break
		}
	}
	return size
}

func (m *machine) setupPrologue() {
	cur := m.rootInstr
	prevInitInst := cur.next

	// At this point, we have the stack layout as follows:
	//
	//                   (high address)
	//                 +-----------------+ <----- RBP (somewhere in the middle of the stack)
	//                 |     .......     |
	//                 |      ret Y      |
	//                 |     .......     |
	//                 |      ret 0      |
	//                 |      arg X      |
	//                 |     .......     |
	//                 |      arg 1      |
	//                 |      arg 0      |
	//                 |   Return Addr   |
	//       RSP ----> +-----------------+
	//                    (low address)

	// First, we push the RBP, and update the RBP to the current RSP.
	//
	//                   (high address)                     (high address)
	//       RBP ----> +-----------------+                +-----------------+
	//                 |     .......     |                |     .......     |
	//                 |      ret Y      |                |      ret Y      |
	//                 |     .......     |                |     .......     |
	//                 |      ret 0      |                |      ret 0      |
	//                 |      arg X      |                |      arg X      |
	//                 |     .......     |     ====>      |     .......     |
	//                 |      arg 1      |                |      arg 1      |
	//                 |      arg 0      |                |      arg 0      |
	//                 |   Return Addr   |                |   Return Addr   |
	//       RSP ----> +-----------------+                |    Caller_RBP   |
	//                    (low address)                   +-----------------+ <----- RSP, RBP
	//
	cur = m.setupRBPRSP(cur)

	if !m.stackBoundsCheckDisabled {
		cur = m.insertStackBoundsCheck(m.requiredStackSize(), cur)
	}

	//
	//            (high address)
	//          +-----------------+                  +-----------------+
	//          |     .......     |                  |     .......     |
	//          |      ret Y      |                  |      ret Y      |
	//          |     .......     |                  |     .......     |
	//          |      ret 0      |                  |      ret 0      |
	//          |      arg X      |                  |      arg X      |
	//          |     .......     |                  |     .......     |
	//          |      arg 1      |                  |      arg 1      |
	//          |      arg 0      |                  |      arg 0      |
	//          |      xxxxx      |                  |      xxxxx      |
	//          |   Return Addr   |                  |   Return Addr   |
	//          |    Caller_RBP   |      ====>       |    Caller_RBP   |
	// RBP,RSP->+-----------------+                  +-----------------+ <----- RBP
	//             (low address)                     |   clobbered M   |
	//                                               |   clobbered 1   |
	//                                               |   ...........   |
	//                                               |   clobbered 0   |
	//                                               +-----------------+ <----- RSP
	//
	if regs := m.clobberedRegs; len(regs) > 0 {
		for i := range regs {
			r := regs[len(regs)-1-i] // Reverse order.
			if r.RegType() == regalloc.RegTypeInt {
				cur = linkInstr(cur, m.allocateInstr().asPush64(newOperandReg(r)))
			} else {
				// Push the XMM register is not supported by the PUSH instruction.
				cur = m.addRSP(-16, cur)
				push := m.allocateInstr().asXmmMovRM(
					sseOpcodeMovdqu, r, newOperandMem(m.newAmodeImmReg(0, rspVReg)),
				)
				cur = linkInstr(cur, push)
			}
		}
	}

	if size := m.spillSlotSize; size > 0 {
		// Simply decrease the RSP to allocate the spill slots.
		// 		sub $size, %rsp
		cur = linkInstr(cur, m.allocateInstr().asAluRmiR(aluRmiROpcodeSub, newOperandImm32(uint32(size)), rspVReg, true))

		// At this point, we have the stack layout as follows:
		//
		//            (high address)
		//          +-----------------+
		//          |     .......     |
		//          |      ret Y      |
		//          |     .......     |
		//          |      ret 0      |
		//          |      arg X      |
		//          |     .......     |
		//          |      arg 1      |
		//          |      arg 0      |
		//          |   ReturnAddress |
		//          |   Caller_RBP    |
		//          +-----------------+ <--- RBP
		//          |    clobbered M  |
		//          |   ............  |
		//          |    clobbered 1  |
		//          |    clobbered 0  |
		//          |   spill slot N  |
		//          |   ............  |
		//          |   spill slot 0  |
		//          +-----------------+ <--- RSP
		//             (low address)
	}

	linkInstr(cur, prevInitInst)
}

// postRegAlloc does multiple things while walking through the instructions:
// 1. Inserts the epilogue code.
// 2. Removes the redundant copy instruction.
// 3. Inserts the dec/inc RSP instruction right before/after the call instruction.
// 4. Lowering that is supposed to be done after regalloc.
func (m *machine) postRegAlloc() {
	for cur := m.rootInstr; cur != nil; cur = cur.next {
		switch k := cur.kind; k {
		case ret:
			m.setupEpilogueAfter(cur.prev)
			continue
		case fcvtToSintSequence, fcvtToUintSequence:
			m.pendingInstructions = m.pendingInstructions[:0]
			if k == fcvtToSintSequence {
				m.lowerFcvtToSintSequenceAfterRegalloc(cur)
			} else {
				m.lowerFcvtToUintSequenceAfterRegalloc(cur)
			}
			prev := cur.prev
			next := cur.next
			cur := prev
			for _, instr := range m.pendingInstructions {
				cur = linkInstr(cur, instr)
			}
			linkInstr(cur, next)
			continue
		case xmmCMov:
			m.pendingInstructions = m.pendingInstructions[:0]
			m.lowerXmmCmovAfterRegAlloc(cur)
			prev := cur.prev
			next := cur.next
			cur := prev
			for _, instr := range m.pendingInstructions {
				cur = linkInstr(cur, instr)
			}
			linkInstr(cur, next)
			continue
		case idivRemSequence:
			m.pendingInstructions = m.pendingInstructions[:0]
			m.lowerIDivRemSequenceAfterRegAlloc(cur)
			prev := cur.prev
			next := cur.next
			cur := prev
			for _, instr := range m.pendingInstructions {
				cur = linkInstr(cur, instr)
			}
			linkInstr(cur, next)
			continue
		case call, callIndirect:
			// At this point, reg alloc is done, therefore we can safely insert dec/inc RPS instruction
			// right before/after the call instruction. If this is done before reg alloc, the stack slot
			// can point to the wrong location and therefore results in a wrong value.
			call := cur
			next := call.next
			_, _, _, _, size := backend.ABIInfoFromUint64(call.u2)
			if size > 0 {
				dec := m.allocateInstr().asAluRmiR(aluRmiROpcodeSub, newOperandImm32(size), rspVReg, true)
				linkInstr(call.prev, dec)
				linkInstr(dec, call)
				inc := m.allocateInstr().asAluRmiR(aluRmiROpcodeAdd, newOperandImm32(size), rspVReg, true)
				linkInstr(call, inc)
				linkInstr(inc, next)
			}
			continue
		case tailCall, tailCallIndirect:
			// At this point, reg alloc is done, therefore we can safely insert dec RPS instruction
			// right before the tail call (jump) instruction. If this is done before reg alloc, the stack slot
			// can point to the wrong location and therefore results in a wrong value.
			tailCall := cur
			_, _, _, _, size := backend.ABIInfoFromUint64(tailCall.u2)
			if size > 0 {
				dec := m.allocateInstr().asAluRmiR(aluRmiROpcodeSub, newOperandImm32(size), rspVReg, true)
				linkInstr(tailCall.prev, dec)
				linkInstr(dec, tailCall)
			}
			// In a tail call, we insert the epilogue before the jump instruction.
			m.setupEpilogueAfter(tailCall.prev)
			// If this has been encoded as a proper tail call, we can remove the trailing instructions
			// For details, see internal/engine/RATIONALE.md
			m.removeUntilRet(cur.next)
			continue
		}

		// Removes the redundant copy instruction.
		if cur.IsCopy() && cur.op1.reg().RealReg() == cur.op2.reg().RealReg() {
			prev, next := cur.prev, cur.next
			// Remove the copy instruction.
			prev.next = next
			if next != nil {
				next.prev = prev
			}
		}
	}
}

func (m *machine) setupEpilogueAfter(cur *instruction) {
	prevNext := cur.next

	// At this point, we have the stack layout as follows:
	//
	//            (high address)
	//          +-----------------+
	//          |     .......     |
	//          |      ret Y      |
	//          |     .......     |
	//          |      ret 0      |
	//          |      arg X      |
	//          |     .......     |
	//          |      arg 1      |
	//          |      arg 0      |
	//          |   ReturnAddress |
	//          |   Caller_RBP    |
	//          +-----------------+ <--- RBP
	//          |    clobbered M  |
	//          |   ............  |
	//          |    clobbered 1  |
	//          |    clobbered 0  |
	//          |   spill slot N  |
	//          |   ............  |
	//          |   spill slot 0  |
	//          +-----------------+ <--- RSP
	//             (low address)

	if size := m.spillSlotSize; size > 0 {
		// Simply increase the RSP to free the spill slots.
		// 		add $size, %rsp
		cur = linkInstr(cur, m.allocateInstr().asAluRmiR(aluRmiROpcodeAdd, newOperandImm32(uint32(size)), rspVReg, true))
	}

	//
	//             (high address)
	//            +-----------------+                     +-----------------+
	//            |     .......     |                     |     .......     |
	//            |      ret Y      |                     |      ret Y      |
	//            |     .......     |                     |     .......     |
	//            |      ret 0      |                     |      ret 0      |
	//            |      arg X      |                     |      arg X      |
	//            |     .......     |                     |     .......     |
	//            |      arg 1      |                     |      arg 1      |
	//            |      arg 0      |                     |      arg 0      |
	//            |   ReturnAddress |                     |   ReturnAddress |
	//            |    Caller_RBP   |                     |    Caller_RBP   |
	//   RBP ---> +-----------------+      ========>      +-----------------+ <---- RSP, RBP
	//            |    clobbered M  |
	//            |   ............  |
	//            |    clobbered 1  |
	//            |    clobbered 0  |
	//   RSP ---> +-----------------+
	//               (low address)
	//
	if regs := m.clobberedRegs; len(regs) > 0 {
		for _, r := range regs {
			if r.RegType() == regalloc.RegTypeInt {
				cur = linkInstr(cur, m.allocateInstr().asPop64(r))
			} else {
				// Pop the XMM register is not supported by the POP instruction.
				pop := m.allocateInstr().asXmmUnaryRmR(
					sseOpcodeMovdqu, newOperandMem(m.newAmodeImmReg(0, rspVReg)), r,
				)
				cur = linkInstr(cur, pop)
				cur = m.addRSP(16, cur)
			}
		}
	}

	// Now roll back the RSP to RBP, and pop the caller's RBP.
	cur = m.revertRBPRSP(cur)

	linkInstr(cur, prevNext)
}

// removeUntilRet removes the instructions starting from `cur` until the first `ret` instruction.
func (m *machine) removeUntilRet(cur *instruction) {
	// Stop at a nop0, which every block both begins and ends with. Removal is only a size
	// optimization -- the epilogue is emitted before the tail jump, so whatever follows it
	// is already unreachable -- so bounding it to the tail call's own block is safe. It
	// also keeps us from cutting a live return sequence out of a later block when the
	// return we are looking for is not adjacent, which is the case under exception
	// handling: there the return sits in a continuation block after the landing-pad edge.
	for ; cur != nil && cur.kind != nop0; cur = cur.next {
		prev, next := cur.prev, cur.next
		prev.next = next
		if next != nil {
			next.prev = prev
		}
		if cur.kind == ret {
			return
		}
	}
}

func (m *machine) addRSP(offset int32, cur *instruction) *instruction {
	if offset == 0 {
		return cur
	}
	opcode := aluRmiROpcodeAdd
	if offset < 0 {
		opcode = aluRmiROpcodeSub
		offset = -offset
	}
	return linkInstr(cur, m.allocateInstr().asAluRmiR(opcode, newOperandImm32(uint32(offset)), rspVReg, true))
}

func (m *machine) setupRBPRSP(cur *instruction) *instruction {
	cur = linkInstr(cur, m.allocateInstr().asPush64(newOperandReg(rbpVReg)))
	cur = linkInstr(cur, m.allocateInstr().asMovRR(rspVReg, rbpVReg, true))
	return cur
}

func (m *machine) revertRBPRSP(cur *instruction) *instruction {
	cur = linkInstr(cur, m.allocateInstr().asMovRR(rbpVReg, rspVReg, true))
	cur = linkInstr(cur, m.allocateInstr().asPop64(rbpVReg))
	return cur
}
