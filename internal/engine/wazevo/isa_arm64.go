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

// goCallerReturnAddr reads the saved return address of the go-call's own frame: an
// address inside the function that made the call, which is how a trampoline identifies
// the frame it ran for. returnAddrAt steps up to that function's caller instead.
func goCallerReturnAddr(sp, fp uintptr) uintptr { return arm64.ReturnAddrAt(sp) }

// goCallStackView is a function to get a view of the stack before a Go call, which
// is the view of the stack allocated in CompileGoFunctionTrampoline.
func goCallStackView(stackPointerBeforeGoCall *uint64) []uint64 {
	return arm64.GoCallStackView(stackPointerBeforeGoCall)
}

// returnAddrAt and setReturnAddrAt read and overwrite the saved return address of the
// caller of the go-call whose saved sp/fp are given. arm64 finds that frame from sp (the
// go-call's frame is one below it, so FrameTop steps up); fp is unused.
func returnAddrAt(sp, fp uintptr) uintptr { return arm64.ReturnAddrAt(arm64.FrameTop(sp)) }
func setReturnAddrAt(sp, fp, a uintptr)   { arm64.SetReturnAddrAt(arm64.FrameTop(sp), a) }

// adjustClonedStack is a function to adjust the stack after it is grown.
// More precisely, absolute addresses (frame pointers) in the stack must be adjusted.
func adjustClonedStack(oldsp, oldTop, sp, fp, top uintptr) {
	// TODO: currently, the frame pointers are not used, and saved old sps are relative to the current stack pointer,
	//  so no need to adjustment on arm64. However, when we make it absolute, which in my opinion is better perf-wise
	//  at the expense of slightly costly stack growth, we need to adjust the pushed frame pointers.
}
