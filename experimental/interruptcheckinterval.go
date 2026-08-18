//go:build efficient_interrupt_approach_b

package experimental

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero/internal/expctxkeys"
)

// WithInterruptCheckInterval configures the interrupt check interval for the compiler engine
// when WithCloseOnContextDone is enabled. Instead of exiting to Go code on every loop
// iteration, the exit is performed every N iterations; a closed module is still noticed on
// every iteration, by testing the module's Closed word inline.
//
// The interval must be a power of 2 (e.g. 1, 2, 4, ... 256, 1024). A value of 0 selects the
// default. Internally the value is used as a bitmask (interval - 1) so that the test is a
// single and-and-branch.
//
// The interval must be set on the context passed to CompileModule or Instantiate, since it
// is baked into the generated code. It is also part of the compilation cache key, so the
// same binary compiled at two intervals does not collide.
//
// This setting only affects the compiler engine (wazevo). The interpreter engine ignores it.
func WithInterruptCheckInterval(ctx context.Context, interval uint64) context.Context {
	if interval != 0 && (interval&(interval-1)) != 0 {
		panic(fmt.Errorf("interruptCheckInterval invalid: %d is not zero or a power of two", interval))
	}

	return context.WithValue(ctx, expctxkeys.InterruptCheckIntervalKey{}, interval)
}

// GetInterruptCheckInterval returns the interrupt check interval from context.
// Returns 0 if not set, meaning the default is used.
func GetInterruptCheckInterval(ctx context.Context) uint64 {
	return expctxkeys.InterruptCheckInterval(ctx)
}
