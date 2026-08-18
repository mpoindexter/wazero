//go:build efficient_interrupt_approach_b && !efficient_interrupt_approach_d

package wazevo

import (
	"context"

	"github.com/tetratelabs/wazero/internal/expctxkeys"
)

// interruptCheckIntervalOf returns the loop interrupt check interval to compile into this
// module, taken from the context the caller compiled with. Zero means the frontend picks
// its default. The value is part of the module ID (see wasm.Module.AssignModuleID), so a
// cache hit is always for code compiled at the same interval.
func interruptCheckIntervalOf(ctx context.Context) uint64 {
	return expctxkeys.InterruptCheckInterval(ctx)
}
