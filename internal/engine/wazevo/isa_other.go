//go:build !(amd64 || arm64)

package wazevo

import (
	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend"
)

func newMachine() backend.Machine {
	panic("unsupported architecture")
}

// unwindStack is a function to unwind the stack, and appends return addresses to `returnAddresses` slice.
// The implementation must be aligned with the ABI/Calling convention.
func unwindStack(sp, fp, top uintptr, returnAddresses []uintptr) []uintptr {
	panic("unsupported architecture")
}

// goCallStackView is a function to get a view of the stack before a Go call, which
// is the view of the stack allocated in CompileGoFunctionTrampoline.
func goCallStackView(stackPointerBeforeGoCall *uint64) []uint64 {
	panic("unsupported architecture")
}

// adjustClonedStack is a function to adjust the stack after it is grown.
// More precisely, absolute addresses (frame pointers) in the stack must be adjusted.
func adjustClonedStack(oldsp, oldTop, sp, fp, top uintptr) {
	panic("unsupported architecture")
}

// tryTableFrameTop returns the top of the frame of the function that made the
// try_table enter Go call. See the amd64/arm64 implementations.
func tryTableFrameTop(sp, fp, top uintptr) uintptr {
	panic("unsupported architecture")
}

// restoreFrameSnapshot copies a try_table frame snapshot back over the live
// stack. See the amd64/arm64 implementations.
func restoreFrameSnapshot(sp, fp, hi uintptr, snapshot []byte) {
	panic("unsupported architecture")
}
