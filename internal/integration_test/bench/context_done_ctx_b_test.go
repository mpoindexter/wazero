//go:build efficient_interrupt_approach_b && !efficient_interrupt_approach_d

package bench

import (
	"context"
	"os"
	"strconv"

	"github.com/tetratelabs/wazero/experimental"
)

// benchmarkCtx applies the interrupt check interval named by
// WAZERO_INTERRUPT_CHECK_INTERVAL, so that BenchmarkContextDoneOverhead can be swept
// across N from the command line without its sub-benchmark names changing -- benchstat
// matches runs by name, so the A, D and every-N-of-B runs have to produce the same ones.
//
// Unset leaves the frontend's default (see defaultInterruptCheckInterval).
func benchmarkCtx(ctx context.Context) context.Context {
	v := os.Getenv("WAZERO_INTERRUPT_CHECK_INTERVAL")
	if v == "" {
		return ctx
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		panic("WAZERO_INTERRUPT_CHECK_INTERVAL: " + err.Error())
	}
	return experimental.WithInterruptCheckInterval(ctx, n)
}
