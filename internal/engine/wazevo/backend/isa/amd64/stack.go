package amd64

import (
	"encoding/binary"
	"reflect"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/wasmdebug"
)

func stackView(rbp, top uintptr) []byte {
	l := int(top - rbp)
	var stackBuf []byte
	{
		//nolint:staticcheck
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&stackBuf))
		hdr.Data = rbp
		hdr.Len = l
		hdr.Cap = l
	}
	return stackBuf
}

// UnwindStack implements wazevo.unwindStack.
func UnwindStack(_, rbp, top uintptr, returnAddresses []uintptr) []uintptr {
	stackBuf := stackView(rbp, top)

	for i := uint64(0); i < uint64(len(stackBuf)); {
		//       (high address)
		//    +-----------------+
		//    |     .......     |
		//    |      ret Y      |
		//    |     .......     |
		//    |      ret 0      |
		//    |      arg X      |
		//    |     .......     |
		//    |      arg 1      |
		//    |      arg 0      |
		//    |  ReturnAddress  |
		//    |   Caller_RBP    |
		//    +-----------------+ <---- Caller_RBP
		//    |   ...........   |
		//    |   clobbered  M  |
		//    |   ............  |
		//    |   clobbered  0  |
		//    |   spill slot N  |
		//    |   ............  |
		//    |   spill slot 0  |
		//    |  ReturnAddress  |
		//    |   Caller_RBP    |
		//    +-----------------+ <---- RBP
		//       (low address)

		callerRBP := binary.LittleEndian.Uint64(stackBuf[i:])
		retAddr := binary.LittleEndian.Uint64(stackBuf[i+8:])
		returnAddresses = append(returnAddresses, uintptr(retAddr))
		i = callerRBP - uint64(rbp)
		if len(returnAddresses) == wasmdebug.MaxFrames {
			break
		}
	}
	return returnAddresses
}

// GoCallStackView implements wazevo.goCallStackView.
func GoCallStackView(stackPointerBeforeGoCall *uint64) []uint64 {
	//                  (high address)
	//              +-----------------+ <----+
	//              |   xxxxxxxxxxx   |      | ;; optional unused space to make it 16-byte aligned.
	//           ^  |  arg[N]/ret[M]  |      |
	// sliceSize |  |  ............   |      | SizeInBytes/8
	//           |  |  arg[1]/ret[1]  |      |
	//           v  |  arg[0]/ret[0]  | <----+
	//              |   SizeInBytes   |
	//              +-----------------+ <---- stackPointerBeforeGoCall
	//                 (low address)
	data := unsafe.Add(unsafe.Pointer(stackPointerBeforeGoCall), 8)
	size := *stackPointerBeforeGoCall / 8
	return unsafe.Slice((*uint64)(data), size)
}

// retSlot returns a 1-element view over the saved-return-address slot of the frame whose
// frame pointer (RBP) is `rbp`. In the standard amd64 frame the return address sits at
// RBP+8 — the slot its `ret` pops.
func retSlot(rbp uintptr) []uintptr {
	var slot []uintptr
	{
		//nolint:staticcheck
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&slot))
		hdr.Data = rbp + 8
		hdr.Len = 1
		hdr.Cap = 1
	}
	return slot
}

// ReturnAddrAt returns the saved return address of the frame whose frame pointer is `rbp`.
func ReturnAddrAt(rbp uintptr) uintptr { return retSlot(rbp)[0] }

// SetReturnAddrAt overwrites the saved return address of the frame whose frame pointer is `rbp`.
func SetReturnAddrAt(rbp uintptr, addr uintptr) { retSlot(rbp)[0] = addr }

// CallerRBP returns the caller's frame pointer (Caller_RBP, saved at [rbp]) of the frame
// whose frame pointer is `rbp`.
func CallerRBP(rbp uintptr) uintptr {
	var caller []uintptr
	{
		//nolint:staticcheck
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&caller))
		hdr.Data = rbp
		hdr.Len = 1
		hdr.Cap = 1
	}
	return caller[0]
}

func AdjustClonedStack(oldRsp, oldTop, rsp, rbp, top uintptr) {
	diff := uint64(rsp - oldRsp)

	newBuf := stackView(rbp, top)
	for i := uint64(0); i < uint64(len(newBuf)); {
		//       (high address)
		//    +-----------------+
		//    |     .......     |
		//    |      ret Y      |
		//    |     .......     |
		//    |      ret 0      |
		//    |      arg X      |
		//    |     .......     |
		//    |      arg 1      |
		//    |      arg 0      |
		//    |  ReturnAddress  |
		//    |   Caller_RBP    |
		//    +-----------------+ <---- Caller_RBP
		//    |   ...........   |
		//    |   clobbered  M  |
		//    |   ............  |
		//    |   clobbered  0  |
		//    |   spill slot N  |
		//    |   ............  |
		//    |   spill slot 0  |
		//    |  ReturnAddress  |
		//    |   Caller_RBP    |
		//    +-----------------+ <---- RBP
		//       (low address)

		callerRBP := binary.LittleEndian.Uint64(newBuf[i:])
		if callerRBP == 0 {
			// End of stack.
			break
		}
		if i64 := int64(callerRBP); i64 < int64(oldRsp) || i64 >= int64(oldTop) {
			panic("BUG: callerRBP is out of range")
		}
		if int(callerRBP) < 0 {
			panic("BUG: callerRBP is negative")
		}
		adjustedCallerRBP := callerRBP + diff
		if int(adjustedCallerRBP) < 0 {
			panic("BUG: adjustedCallerRBP is negative")
		}
		binary.LittleEndian.PutUint64(newBuf[i:], adjustedCallerRBP)
		i = adjustedCallerRBP - uint64(rbp)
	}
}
