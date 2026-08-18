package expctxkeys

import "context"

// InterruptCheckIntervalKey is a context.Context Value key.
// Its associated value should be a uint64 representing the interrupt check interval
// for the compiler engine when WithCloseOnContextDone is enabled.
type InterruptCheckIntervalKey struct{}

// InterruptCheckInterval returns the interval set on ctx, or 0 when none is set.
func InterruptCheckInterval(ctx context.Context) uint64 {
	interval, _ := ctx.Value(InterruptCheckIntervalKey{}).(uint64)
	return interval
}
