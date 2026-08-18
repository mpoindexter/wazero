package bench

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

// TestInterruptLargeLoopBody is the safety property behind BenchmarkInterruptLatency: a
// guest that goes a long way between loop back-edges must still be stoppable, and must
// still be stoppable when there is no spare P for the goroutine that delivers the close.
//
// It asserts termination, not promptness -- how long it takes is what the benchmark is
// for, and it varies by approach and (for approach B) by interrupt check interval. The
// bound here is only loose enough to distinguish "slow" from "hung".
func TestInterruptLargeLoopBody(t *testing.T) {
	if !platform.CompilerSupported() {
		t.Skip()
	}

	// buildSpinModule takes *testing.B only to call b.Helper; nothing else needs it.
	bin := buildSpinModule(&testing.B{}, 100_000)

	for _, procs := range []int{0, 1} {
		name := "default_gomaxprocs"
		if procs == 1 {
			name = "gomaxprocs_1"
		}
		t.Run(name, func(t *testing.T) {
			if procs == 1 {
				prev := runtime.GOMAXPROCS(1)
				t.Cleanup(func() { runtime.GOMAXPROCS(prev) })
			}

			ctx := context.Background()
			r := wazero.NewRuntimeWithConfig(ctx,
				wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(true))
			defer r.Close(ctx)

			mod, err := r.Instantiate(ctx, bin)
			require.NoError(t, err)

			callCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			defer cancel()

			start := time.Now()
			_, err = mod.ExportedFunction("spin").Call(callCtx)
			elapsed := time.Since(start)

			require.Error(t, err)
			require.Contains(t, err.Error(), "context deadline exceeded")
			if elapsed > 10*time.Second {
				t.Fatalf("interruption took %s, which is a hang rather than a slow check", elapsed)
			}
			t.Logf("interrupted %s after the deadline", elapsed-20*time.Millisecond)
		})
	}
}
