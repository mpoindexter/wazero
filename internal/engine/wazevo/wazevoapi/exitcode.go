package wazevoapi

// ExitCode is an exit code of an execution of a function.
type ExitCode uint32

const (
	ExitCodeOK ExitCode = iota
	ExitCodeGrowStack
	ExitCodeGrowMemory
	ExitCodeUnreachable
	ExitCodeMemoryOutOfBounds
	// ExitCodeCallGoModuleFunction is an exit code for a call to an api.GoModuleFunction.
	ExitCodeCallGoModuleFunction
	// ExitCodeCallGoFunction is an exit code for a call to an api.GoFunction.
	ExitCodeCallGoFunction
	ExitCodeTableOutOfBounds
	ExitCodeIndirectCallNullPointer
	ExitCodeIndirectCallTypeMismatch
	ExitCodeIntegerDivisionByZero
	ExitCodeIntegerOverflow
	ExitCodeInvalidConversionToInteger
	ExitCodeCheckModuleExitCode
	ExitCodeCallListenerBefore
	ExitCodeCallListenerAfter
	ExitCodeCallGoModuleFunctionWithListener
	ExitCodeCallGoFunctionWithListener
	ExitCodeTableGrow
	ExitCodeRefFunc
	ExitCodeMemoryWait32
	ExitCodeMemoryWait64
	ExitCodeMemoryNotify
	ExitCodeUnalignedAtomic
	// ExitCodeThrowAlloc is an exit code for allocating the heap Exception object on throw.
	ExitCodeThrowAlloc
	// ExitCodeMatchException is an exit code for matching the in-flight exception against a try_table's catch clauses.
	ExitCodeMatchException
	// ExitCodeNullReference is an exit code for a null reference trap (throw_ref with null exnref).
	ExitCodeNullReference
	// ExitCodeThrow is an exit code for propagating an exception out of the current function.
	ExitCodeThrow
	// ExitCodeRaiseRef is an exit code for throw_ref: it resolves the exnref guest code is
	// raising and records it as the exception in flight, which every raise does before
	// transferring control.
	ExitCodeRaiseRef
	// ExitCodeExnrefSlotFill is an exit code for the write barrier over a run of
	// exnref-typed table slots, which table.fill writes.
	ExitCodeExnrefSlotFill
	// ExitCodeExnrefSlotCopy is an exit code for the write barrier over a run of
	// exnref-typed table slots copied from elsewhere, which table.copy and table.init write.
	ExitCodeExnrefSlotCopy
	// ExitCodeExnrefSlotLoad is an exit code for the read barrier on an exnref-typed global
	// or table slot: what the slot names becomes reachable from this call, so the runtime
	// has to pin it before compiled code can hold the handle.
	ExitCodeExnrefSlotLoad
	// ExitCodeExnrefSlotStore is an exit code for the write barrier on an exnref-typed
	// global or table slot: the slot becomes a durable holder of what it now names, and
	// stops being one for what it held.
	ExitCodeExnrefSlotStore
	// ExitCodeAdjustExnrefs is an exit code for adjusting the call's exnref reference counts:
	// one handle gains a reference, another loses one. Either may be zero, meaning nothing.
	// One exit covers all of it because the instructions that move an exnref between a local
	// and the operand stack do both at once.
	ExitCodeAdjustExnrefs
	exitCodeMax
)

const ExitCodeMask = 0xff

// String implements fmt.Stringer.
func (e ExitCode) String() string {
	switch e {
	case ExitCodeOK:
		return "ok"
	case ExitCodeGrowStack:
		return "grow_stack"
	case ExitCodeCallGoModuleFunction:
		return "call_go_module_function"
	case ExitCodeCallGoFunction:
		return "call_go_function"
	case ExitCodeUnreachable:
		return "unreachable"
	case ExitCodeMemoryOutOfBounds:
		return "memory_out_of_bounds"
	case ExitCodeUnalignedAtomic:
		return "unaligned_atomic"
	case ExitCodeTableOutOfBounds:
		return "table_out_of_bounds"
	case ExitCodeIndirectCallNullPointer:
		return "indirect_call_null_pointer"
	case ExitCodeIndirectCallTypeMismatch:
		return "indirect_call_type_mismatch"
	case ExitCodeIntegerDivisionByZero:
		return "integer_division_by_zero"
	case ExitCodeIntegerOverflow:
		return "integer_overflow"
	case ExitCodeInvalidConversionToInteger:
		return "invalid_conversion_to_integer"
	case ExitCodeCheckModuleExitCode:
		return "check_module_exit_code"
	case ExitCodeCallListenerBefore:
		return "call_listener_before"
	case ExitCodeCallListenerAfter:
		return "call_listener_after"
	case ExitCodeCallGoModuleFunctionWithListener:
		return "call_go_module_function_with_listener"
	case ExitCodeCallGoFunctionWithListener:
		return "call_go_function_with_listener"
	case ExitCodeGrowMemory:
		return "grow_memory"
	case ExitCodeTableGrow:
		return "table_grow"
	case ExitCodeRefFunc:
		return "ref_func"
	case ExitCodeMemoryWait32:
		return "memory_wait32"
	case ExitCodeMemoryWait64:
		return "memory_wait64"
	case ExitCodeRaiseRef:
		return "raise_ref"
	case ExitCodeExnrefSlotFill:
		return "exnref_slot_fill"
	case ExitCodeExnrefSlotCopy:
		return "exnref_slot_copy"
	case ExitCodeExnrefSlotLoad:
		return "exnref_slot_load"
	case ExitCodeExnrefSlotStore:
		return "exnref_slot_store"
	case ExitCodeAdjustExnrefs:
		return "adjust_exnrefs"
	case ExitCodeMemoryNotify:
		return "memory_notify"
	case ExitCodeThrowAlloc:
		return "throw_alloc"
	case ExitCodeMatchException:
		return "match_exception"
	case ExitCodeNullReference:
		return "null_reference"
	case ExitCodeThrow:
		return "throw"
	}
	panic("TODO")
}

func ExitCodeCallGoModuleFunctionWithIndex(index int, withListener bool) ExitCode {
	if withListener {
		return ExitCodeCallGoModuleFunctionWithListener | ExitCode(index<<8)
	}
	return ExitCodeCallGoModuleFunction | ExitCode(index<<8)
}

func ExitCodeCallGoFunctionWithIndex(index int, withListener bool) ExitCode {
	if withListener {
		return ExitCodeCallGoFunctionWithListener | ExitCode(index<<8)
	}
	return ExitCodeCallGoFunction | ExitCode(index<<8)
}

func GoFunctionIndexFromExitCode(exitCode ExitCode) int {
	return int(exitCode >> 8)
}
