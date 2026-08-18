//go:build efficient_interrupt_approach_b && !efficient_interrupt_approach_d

package wazero

import (
	"context"

	"github.com/tetratelabs/wazero/internal/expctxkeys"
)

// interruptCheckInterval resolves the loop interrupt check interval that CompileModule
// should bake into the generated code, and that the compilation cache should key on.
// See experimental.WithInterruptCheckInterval. Zero selects the engine's default.
func interruptCheckInterval(ctx context.Context, ensureTermination bool) uint64 {
	if !ensureTermination {
		return 0
	}
	return expctxkeys.InterruptCheckInterval(ctx)
}
