//go:build efficient_interrupt_approach_b && !efficient_interrupt_approach_d

package bench

import (
	"context"
	"strconv"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

// BenchmarkContextDoneInterval sweeps approach B's interrupt check interval, to answer the
// open question in INTERRUPT_DESIGN.md of whether an N exists that needs no tuning.
//
// It runs the same module as BenchmarkContextDoneOverhead with ensureTermination on, so
// the "with_close_on_ctx_done" rows of that benchmark are the same measurement at the
// default interval, and its "without_close_on_ctx_done" rows are the floor being
// approached.
func BenchmarkContextDoneInterval(b *testing.B) {
	if !platform.CompilerSupported() {
		b.Skip()
	}

	bin := buildContextDoneModule(b)

	for _, interval := range []uint64{1, 16, 64, 256, 1024, 16384, 262144} {
		b.Run("interval_"+strconv.FormatUint(interval, 10), func(b *testing.B) {
			ctx := experimental.WithInterruptCheckInterval(context.Background(), interval)
			r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(true))
			defer r.Close(ctx)

			mod, err := r.Instantiate(ctx, bin)
			require.NoError(b, err)

			tightLoop := mod.ExportedFunction("tight_loop")
			memLoop := mod.ExportedFunction("mem_loop")

			for _, sz := range []struct {
				name  string
				iters uint64
			}{{"short_1k", 1_000}, {"long_10M", 10_000_000}} {
				b.Run("tight/"+sz.name, func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						if _, err := tightLoop.Call(ctx, sz.iters); err != nil {
							b.Fatal(err)
						}
					}
				})
				b.Run("mem/"+sz.name, func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						if _, err := memLoop.Call(ctx, sz.iters); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
