//go:build amd64

package wazevo

import (
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

// goCallerReturnAddr reads the saved return address of the go-call's own frame: an
// address inside the function that made the call, which is how a trampoline identifies
// the frame it ran for. returnAddrAt steps up to that function's caller instead.
func goCallerReturnAddr(sp, fp uintptr) uintptr { return amd64.ReturnAddrAt(fp) }

// goCallStackView is a function to get a view of the stack before a Go call, which
// is the view of the stack allocated in CompileGoFunctionTrampoline.
func goCallStackView(stackPointerBeforeGoCall *uint64) []uint64 {
	return amd64.GoCallStackView(stackPointerBeforeGoCall)
}

// returnAddrAt and setReturnAddrAt read and overwrite the saved return address of the
// caller of the go-call whose saved sp/fp are given. amd64 uses fp (the go-call's RBP):
// CallerRBP steps up to the calling frame and ReturnAddrAt reads its own return address;
// sp is unused.
func returnAddrAt(sp, fp uintptr) uintptr { return amd64.ReturnAddrAt(amd64.CallerRBP(fp)) }
func setReturnAddrAt(sp, fp, a uintptr)   { amd64.SetReturnAddrAt(amd64.CallerRBP(fp), a) }

// adjustClonedStack is a function to adjust the stack after it is grown.
// More precisely, absolute addresses (frame pointers) in the stack must be adjusted.
func adjustClonedStack(oldsp, oldTop, sp, fp, top uintptr) {
	amd64.AdjustClonedStack(oldsp, oldTop, sp, fp, top)
}
