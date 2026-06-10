//go:build amd64

package wazevo

import (
	"encoding/binary"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend/isa/amd64"
)

func newMachine() backend.Machine {
	return amd64.NewBackend()
}

// unwindStack is a function to unwind the stack, and appends return addresses to `returnAddresses` slice.
// The implementation must be aligned with the ABI/Calling convention.
func unwindStack(sp, fp, top uintptr, returnAddresses []uintptr) []uintptr {
	return amd64.UnwindStack(sp, fp, top, returnAddresses)
}

// goCallStackView is a function to get a view of the stack before a Go call, which
// is the view of the stack allocated in CompileGoFunctionTrampoline.
func goCallStackView(stackPointerBeforeGoCall *uint64) []uint64 {
	return amd64.GoCallStackView(stackPointerBeforeGoCall)
}

// adjustClonedStack is a function to adjust the stack after it is grown.
// More precisely, absolute addresses (frame pointers) in the stack must be adjusted.
func adjustClonedStack(oldsp, oldTop, sp, fp, top uintptr) {
	amd64.AdjustClonedStack(oldsp, oldTop, sp, fp, top)
}

// tryTableFrameTop returns the top of the frame of the function that made the
// try_table enter Go call: the boundary above which the try body mutates nothing.
// The frame extends up to the caller's frame base, which is the saved Caller_RBP
// stored at [fp].
func tryTableFrameTop(sp, fp, top uintptr) uintptr {
	// Read [fp] through a byte view to avoid a uintptr->Pointer conversion.
	return uintptr(binary.LittleEndian.Uint64(stackBytesView(fp, fp+8)))
}

// restoreFrameSnapshot copies the saved frame bytes back over [sp, hi). The
// region's one absolute pointer, the saved Caller_RBP at [fp], is preserved from
// the live stack so it stays valid if the stack was grown (relocated) meanwhile;
// without a grow the live and saved words are identical.
func restoreFrameSnapshot(sp, fp, hi uintptr, snapshot []byte) {
	live := stackBytesView(sp, hi)
	off := int(fp - sp)
	saved := binary.LittleEndian.Uint64(live[off:])
	copy(live, snapshot)
	binary.LittleEndian.PutUint64(live[off:], saved)
}
