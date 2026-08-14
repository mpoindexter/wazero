package arm64

import (
	"encoding/binary"
	"reflect"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/wasmdebug"
)

// UnwindStack implements wazevo.unwindStack.
func UnwindStack(sp, _, top uintptr, returnAddresses []uintptr) []uintptr {
	l := int(top - sp)

	var stackBuf []byte
	{
		//nolint:staticcheck
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&stackBuf))
		hdr.Data = sp
		hdr.Len = l
		hdr.Cap = l
	}

	for i := uint64(0); i < uint64(l); {
		//       (high address)
		//    +-----------------+
		//    |     .......     |
		//    |      ret Y      |  <----+
		//    |     .......     |       |
		//    |      ret 0      |       |
		//    |      arg X      |       |  size_of_arg_ret
		//    |     .......     |       |
		//    |      arg 1      |       |
		//    |      arg 0      |  <----+
		//    | size_of_arg_ret |
		//    |  ReturnAddress  |
		//    +-----------------+ <----+
		//    |   ...........   |      |
		//    |   spill slot M  |      |
		//    |   ............  |      |
		//    |   spill slot 2  |      |
		//    |   spill slot 1  |      | frame size
		//    |   spill slot 1  |      |
		//    |   clobbered N   |      |
		//    |   ............  |      |
		//    |   clobbered 0   | <----+
		//    |     xxxxxx      |  ;; unused space to make it 16-byte aligned.
		//    |   frame_size    |
		//    +-----------------+ <---- SP
		//       (low address)

		frameSize := binary.LittleEndian.Uint64(stackBuf[i:])
		i += frameSize +
			16 // frame size + aligned space.
		retAddr := binary.LittleEndian.Uint64(stackBuf[i:])
		i += 8 // ret addr.
		sizeOfArgRet := binary.LittleEndian.Uint64(stackBuf[i:])
		i += 8 + sizeOfArgRet
		returnAddresses = append(returnAddresses, uintptr(retAddr))
		if len(returnAddresses) == wasmdebug.MaxFrames {
			break
		}
	}
	return returnAddresses
}

// FrameTop returns the top (high address) of the frame whose stack pointer is
// `sp`, i.e. the stack pointer of its caller. It is one iteration of the
// UnwindStack frame walk, deriving the boundary from the per-frame frame_size /
// arg-ret metadata.
func FrameTop(sp uintptr) uintptr {
	// View the frame to read frame_size and size_of_arg_ret without a
	// uintptr->Pointer conversion (matches UnwindStack's stackView approach).
	var buf []byte
	{
		//nolint:staticcheck
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
		hdr.Data = sp
		hdr.Len = 32
		hdr.Cap = 32
	}
	frameSize := binary.LittleEndian.Uint64(buf)
	i := frameSize + 16 // frame size + aligned space.
	i += 8              // ret addr.
	// Re-view at the size_of_arg_ret slot, then advance past the arg/ret area.
	{
		//nolint:staticcheck
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
		hdr.Data = sp + uintptr(i)
		hdr.Len = 8
		hdr.Cap = 8
	}
	sizeOfArgRet := binary.LittleEndian.Uint64(buf)
	i += 8 + sizeOfArgRet
	return sp + uintptr(i)
}

// returnAddrSlot returns a 1-element []uintptr view over the saved-return-address slot
// of the frame whose stack pointer is `sp`. The slot lives at sp + frame_size + 16 (see
// the UnwindStack frame diagram), so reads/writes through the returned slice load/store
// exactly the value the function's epilogue restores into LR before `ret`.
func returnAddrSlot(sp uintptr) []uintptr {
	var buf []byte
	{
		//nolint:staticcheck
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
		hdr.Data = sp
		hdr.Len = 8
		hdr.Cap = 8
	}
	slotAddr := sp + uintptr(binary.LittleEndian.Uint64(buf)) + 16
	var slot []uintptr
	{
		//nolint:staticcheck
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&slot))
		hdr.Data = slotAddr
		hdr.Len = 1
		hdr.Cap = 1
	}
	return slot
}

// ReturnAddrAt returns the saved return address of the frame whose stack pointer is `sp`.
func ReturnAddrAt(sp uintptr) uintptr { return returnAddrSlot(sp)[0] }

// SetReturnAddrAt overwrites the saved return address of the frame whose stack pointer is `sp`.
func SetReturnAddrAt(sp uintptr, addr uintptr) { returnAddrSlot(sp)[0] = addr }

// GoCallStackView implements wazevo.goCallStackView.
func GoCallStackView(stackPointerBeforeGoCall *uint64) []uint64 {
	//                  (high address)
	//              +-----------------+ <----+
	//              |   xxxxxxxxxxx   |      | ;; optional unused space to make it 16-byte aligned.
	//           ^  |  arg[N]/ret[M]  |      |
	// sliceSize |  |  ............   |      | sliceSize
	//           |  |  arg[1]/ret[1]  |      |
	//           v  |  arg[0]/ret[0]  | <----+
	//              |    sliceSize    |
	//              |   frame_size    |
	//              +-----------------+ <---- stackPointerBeforeGoCall
	//                 (low address)
	ptr := unsafe.Pointer(stackPointerBeforeGoCall)
	data := (*uint64)(unsafe.Add(ptr, 16)) // skips the (frame_size, sliceSize).
	size := *(*uint64)(unsafe.Add(ptr, 8))
	return unsafe.Slice(data, size)
}
