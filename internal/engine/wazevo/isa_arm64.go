//go:build arm64

package wazevo

import (
	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend/isa/arm64"
)

func newMachine() backend.Machine {
	return arm64.NewBackend()
}

// unwindStack is a function to unwind the stack, and appends return addresses to `returnAddresses` slice.
// The implementation must be aligned with the ABI/Calling convention.
func unwindStack(sp, fp, top uintptr, returnAddresses []uintptr) []uintptr {
	return arm64.UnwindStack(sp, fp, top, returnAddresses)
}

// goCallStackView is a function to get a view of the stack before a Go call, which
// is the view of the stack allocated in CompileGoFunctionTrampoline.
func goCallStackView(stackPointerBeforeGoCall *uint64) []uint64 {
	return arm64.GoCallStackView(stackPointerBeforeGoCall)
}

// adjustClonedStack is a function to adjust the stack after it is grown.
// More precisely, absolute addresses (frame pointers) in the stack must be adjusted.
func adjustClonedStack(oldsp, oldTop, sp, fp, top uintptr) {
	// TODO: currently, the frame pointers are not used, and saved old sps are relative to the current stack pointer,
	//  so no need to adjustment on arm64. However, when we make it absolute, which in my opinion is better perf-wise
	//  at the expense of slightly costly stack growth, we need to adjust the pushed frame pointers.
}

// tryTableFrameTop returns the top (high address) of the frame of the function
// that made the try_table enter Go call. arm64 has no frame-pointer chain, so we
// derive the boundary by walking one frame record up from sp. fp is unused.
func tryTableFrameTop(sp, fp, top uintptr) uintptr {
	return arm64.FrameTop(sp)
}

// restoreFrameSnapshot copies the saved frame bytes back over the live stack
// region [sp, hi). arm64 frames contain no absolute stack pointers (saved SPs are
// frame-size-relative; see adjustClonedStack), so a plain copy is correct even
// after a stack grow. fp is unused.
func restoreFrameSnapshot(sp, fp, hi uintptr, snapshot []byte) {
	copy(stackBytesView(sp, hi), snapshot)
}
