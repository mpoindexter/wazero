//go:build !efficient_interrupt_approach_d || !(arm64 || amd64)

package wazevo

// guestEntrypoints returns the pair of functions used to enter generated code. Outside approach
// D there is nothing to choose: generated code always runs holding a P, so both point straight at
// the backend's assembly and ensureTermination makes no difference to how it is entered.
func guestEntrypoints(bool) (guestEntryFunc, afterGoCallFunc) {
	return entrypointAsm, afterGoFunctionCallEntrypointAsm
}
