//go:build !efficient_interrupt_approach_b || efficient_interrupt_approach_d

package wazero

import "context"

// interruptCheckInterval is always zero outside approach B: approaches A and D do not
// have an interval to tune, so nothing varies the generated code or the cache key.
func interruptCheckInterval(context.Context, bool) uint64 { return 0 }
