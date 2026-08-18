//go:build !efficient_interrupt_approach_b || efficient_interrupt_approach_d

package bench

import "context"

// benchmarkCtx is the identity outside approach B: approaches A and D have no interrupt
// check interval to configure.
func benchmarkCtx(ctx context.Context) context.Context { return ctx }
