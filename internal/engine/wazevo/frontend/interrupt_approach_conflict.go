//go:build efficient_interrupt_approach_b && efficient_interrupt_approach_d

package frontend

// The interrupt approaches replace each other's loop lowering, so at most one may be
// selected. Building with both is a mistake in the benchmark invocation, not a
// configuration, and would otherwise fail with an unrelated "undefined method" error.
var _ = efficient_interrupt_approach_b_and_efficient_interrupt_approach_d_are_mutually_exclusive
