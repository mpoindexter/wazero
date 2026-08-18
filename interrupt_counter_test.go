//go:build efficient_interrupt_approach_b && !efficient_interrupt_approach_d

package wazero_test

import (
	"context"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

// TestInterruptCheckInterval_ContextTimeout verifies that an infinite loop is
// terminated by context timeout at every supported interval, including the ones large
// enough that the unconditional exit is rare and the inline Closed test is what notices.
func TestInterruptCheckInterval_ContextTimeout(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval uint64
	}{
		{name: "interval=0 (default)", interval: 0},
		{name: "interval=1", interval: 1},
		{name: "interval=16", interval: 16},
		{name: "interval=256", interval: 256},
		{name: "interval=65536", interval: 65536},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := experimental.WithInterruptCheckInterval(context.Background(), tc.interval)

			r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
			defer r.Close(ctx)

			moduleInstance, err := r.InstantiateWithConfig(ctx, infiniteLoopWasm,
				wazero.NewModuleConfig().WithName("test_module"))
			require.NoError(t, err)

			timeoutCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()

			_, err = moduleInstance.ExportedFunction("infinite_loop").Call(timeoutCtx)
			require.Error(t, err)
			require.Contains(t, err.Error(), "context deadline exceeded")
		})
	}
}

// TestInterruptCheckInterval_ContextCancel verifies that an infinite loop is
// terminated by context cancellation when the interrupt check interval is configured.
func TestInterruptCheckInterval_ContextCancel(t *testing.T) {
	ctx := experimental.WithInterruptCheckInterval(context.Background(), 65536)

	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer r.Close(ctx)

	moduleInstance, err := r.InstantiateWithConfig(ctx, infiniteLoopWasm,
		wazero.NewModuleConfig().WithName("test_module"))
	require.NoError(t, err)

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	_, err = moduleInstance.ExportedFunction("infinite_loop").Call(cancelCtx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "context canceled")
}

// TestInterruptCheckInterval_ModuleClose verifies that an infinite loop is
// terminated by explicit module close when the interrupt check interval is configured.
func TestInterruptCheckInterval_ModuleClose(t *testing.T) {
	ctx := experimental.WithInterruptCheckInterval(context.Background(), 65536)

	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer r.Close(ctx)

	moduleInstance, err := r.InstantiateWithConfig(ctx, infiniteLoopWasm,
		wazero.NewModuleConfig().WithName("test_module"))
	require.NoError(t, err)

	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = moduleInstance.CloseWithExitCode(ctx, 1)
	}()

	_, err = moduleInstance.ExportedFunction("infinite_loop").Call(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exit_code(1)")
}

// TestInterruptCheckInterval_NonPowerOfTwoPanics verifies that a non-power-of-two
// interval panics: the lowering tests interval-1 as a bit mask.
func TestInterruptCheckInterval_NonPowerOfTwoPanics(t *testing.T) {
	err := require.CapturePanic(func() {
		experimental.WithInterruptCheckInterval(context.Background(), 3)
	})
	require.EqualError(t, err, "interruptCheckInterval invalid: 3 is not zero or a power of two")
}

// TestInterruptCheckInterval_CacheKey verifies that two intervals do not share a compiled
// module: the interval is baked into the generated code, so a cache hit across intervals
// would run the wrong code.
func TestInterruptCheckInterval_CacheKey(t *testing.T) {
	base := context.Background()
	cache := wazero.NewCompilationCache()
	defer cache.Close(base)

	cfg := wazero.NewRuntimeConfig().WithCloseOnContextDone(true).WithCompilationCache(cache)

	for _, interval := range []uint64{16, 65536} {
		ctx := experimental.WithInterruptCheckInterval(base, interval)
		r := wazero.NewRuntimeWithConfig(ctx, cfg)

		moduleInstance, err := r.InstantiateWithConfig(ctx, infiniteLoopWasm,
			wazero.NewModuleConfig().WithName("test_module"))
		require.NoError(t, err)

		timeoutCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, err = moduleInstance.ExportedFunction("infinite_loop").Call(timeoutCtx)
		cancel()
		require.Error(t, err)
		require.Contains(t, err.Error(), "context deadline exceeded")
		require.NoError(t, r.Close(ctx))
	}
}
