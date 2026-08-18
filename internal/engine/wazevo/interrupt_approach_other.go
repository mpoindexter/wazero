//go:build !efficient_interrupt_approach_b || efficient_interrupt_approach_d

package wazevo

import "context"

// interruptCheckIntervalOf is always zero outside approach B, whose loop lowering is the
// only one with an interval to tune.
func interruptCheckIntervalOf(context.Context) uint64 { return 0 }
