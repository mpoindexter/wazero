//go:build efficient_interrupt_approach_d && (arm64 || amd64)

package wazevo

import (
	_ "unsafe" // for go:linkname
)

// runtime_entersyscall and runtime_exitsyscall mark the goroutine as being
// in a syscall, which detaches its P. This lets the Go runtime's sysmon
// retake the P after ~10ms and run other goroutines on it, even if the
// wasm goroutine is in a long-running native loop.
//
// Same trick used by gvisor (see runtime/proc.go: "hall of shame" comment
// on entersyscallblock -- the runtime team has committed to not changing
// the type signatures of these entry points).

//go:linkname runtime_entersyscall runtime.entersyscall
func runtime_entersyscall()

//go:linkname runtime_exitsyscall runtime.exitsyscall
func runtime_exitsyscall()

// guestEntrypoints returns the pair of functions used to enter generated code, bracketed with
// entersyscall/exitsyscall only when the module was compiled with ensureTermination.
//
// The two settings correspond to the two ways a guest gets called. A module compiled with
// WithCloseOnContextDone is one whose calls may run long enough to need interrupting, and it wants
// the scheduler to know it is off running native code so that everything else -- the cancellation
// watchdog, the collector, other requests -- keeps moving. A module compiled without it is being
// used for short calls where the only thing that matters is that the call is cheap, and there the
// pair is pure overhead: it costs ~8ns per Call, which is 23% of a 34ns one.
//
// The choice is made once per callEngine rather than tested per entry, so the fast path is a call
// straight to the assembly with no Go frame in between.
func guestEntrypoints(ensureTermination bool) (guestEntryFunc, afterGoCallFunc) {
	if !ensureTermination {
		return entrypointAsm, afterGoFunctionCallEntrypointAsm
	}
	return entrypointSyscall, afterGoFunctionCallEntrypointSyscall
}

// entrypointSyscall wraps the native-execution entry point with entersyscall /
// exitsyscall so the Go runtime can retake this goroutine's P while wasm
// is running. Marked nosplit because entersyscall sets throwsplit and we
// must not grow the stack between entersyscall and exitsyscall.
//
//go:nosplit
func entrypointSyscall(preambleExecutable, functionExecutable *byte, executionContextPtr uintptr, moduleContextPtr *byte, paramResultStackPtr *uint64, goAllocatedStackSlicePtr uintptr) {
	runtime_entersyscall()
	entrypointAsm(preambleExecutable, functionExecutable, executionContextPtr, moduleContextPtr, paramResultStackPtr, goAllocatedStackSlicePtr)
	runtime_exitsyscall()
}

// afterGoFunctionCallEntrypointSyscall re-enters native code after a Go-side
// dispatcher iteration (host call, FailIfClosed, stack grow, etc.). Same
// syscall bracketing as entrypointSyscall, same nosplit constraint.
//
//go:nosplit
func afterGoFunctionCallEntrypointSyscall(executable *byte, executionContextPtr uintptr, stackPointer, framePointer uintptr) {
	runtime_entersyscall()
	afterGoFunctionCallEntrypointAsm(executable, executionContextPtr, stackPointer, framePointer)
	runtime_exitsyscall()
}
