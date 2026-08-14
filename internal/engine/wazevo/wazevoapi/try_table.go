package wazevoapi

// CatchClauseInstance is a runtime catch clause with resolved tag index.
type CatchClauseInstance struct {
	Kind     byte   // wasm.CatchKindCatch, etc.
	TagIndex uint32 // module-local tag index
}

// TryTableInfo holds try_table metadata assigned during compilation and looked up at
// runtime by try_table ID. matchException uses CatchClauses to match the in-flight
// exception against this try_table's catch clauses.
type TryTableInfo struct {
	CatchClauses []CatchClauseInstance
}

// TryTableID packs a try_table's identity -- the index of the local function holding it,
// and its ordinal among that function's try_tables -- into the constant compiled code
// hands to matchException.
//
// Both halves are properties of the function alone, so the code emitted for a function
// does not depend on how many try_tables other functions happened to compile first. That
// is what keeps compilation deterministic when functions are compiled in parallel, and
// therefore in an arbitrary order.
func TryTableID(localFnIdx, ordinal uint32) uint64 {
	return uint64(localFnIdx)<<32 | uint64(ordinal)
}

// TryTableIDParts is the inverse of TryTableID. The parts index
// wazevo.compiledModule.tryTableInfo, which is nested the same way.
func TryTableIDParts(id uint64) (localFnIdx, ordinal uint32) {
	return uint32(id >> 32), uint32(id)
}

// ExceptionTableEntry maps a call site to its table-driven-EH landing pad, as
// function-relative executable offsets. On throw the runtime finds the entry whose
// CallBlockStart is the greatest <= (returnAddr - funcBase - 1) and redirects the IP
// to funcBase + LandingPad. See OpcodeExceptionEdge.
type ExceptionTableEntry struct {
	CallBlockStart uint32
	LandingPad     uint32
}
