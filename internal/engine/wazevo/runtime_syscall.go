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
// on entersyscallblock — the runtime team has committed to not changing
// the type signatures of these entry points).

//go:linkname runtime_entersyscall runtime.entersyscall
func runtime_entersyscall()

//go:linkname runtime_exitsyscall runtime.exitsyscall
func runtime_exitsyscall()

// entrypoint wraps the native-execution entry point with entersyscall /
// exitsyscall so the Go runtime can retake this goroutine's P while wasm
// is running.
func entrypoint(preambleExecutable, functionExecutable *byte, executionContextPtr uintptr, moduleContextPtr *byte, paramResultStackPtr *uint64, goAllocatedStackSlicePtr uintptr, ensureTermination bool) {
	if ensureTermination {
		entrypointEnsureTermination(preambleExecutable, functionExecutable, executionContextPtr, moduleContextPtr, paramResultStackPtr, goAllocatedStackSlicePtr)
	} else {
		entrypointAsm(preambleExecutable, functionExecutable, executionContextPtr, moduleContextPtr, paramResultStackPtr, goAllocatedStackSlicePtr)
	}
}

// Marked nosplit because entersyscall sets throwsplit and we
// must not grow the stack between entersyscall and exitsyscall.
//
//go:nosplit
func entrypointEnsureTermination(preambleExecutable, functionExecutable *byte, executionContextPtr uintptr, moduleContextPtr *byte, paramResultStackPtr *uint64, goAllocatedStackSlicePtr uintptr) {
	runtime_entersyscall()
	entrypointAsm(preambleExecutable, functionExecutable, executionContextPtr, moduleContextPtr, paramResultStackPtr, goAllocatedStackSlicePtr)
	runtime_exitsyscall()
}

// afterGoFunctionCallEntrypoint re-enters native code after a Go-side
// dispatcher iteration (host call, FailIfClosed, stack grow, etc.).
func afterGoFunctionCallEntrypoint(executable *byte, executionContextPtr uintptr, stackPointer, framePointer uintptr, ensureTermination bool) {
	if ensureTermination {
		afterGoFunctionCallEntrypointEnsureTermination(executable, executionContextPtr, stackPointer, framePointer)
	} else {
		afterGoFunctionCallEntrypointAsm(executable, executionContextPtr, stackPointer, framePointer)
	}
}

//go:nosplit
func afterGoFunctionCallEntrypointEnsureTermination(executable *byte, executionContextPtr uintptr, stackPointer, framePointer uintptr) {
	runtime_entersyscall()
	afterGoFunctionCallEntrypointAsm(executable, executionContextPtr, stackPointer, framePointer)
	runtime_exitsyscall()
}
