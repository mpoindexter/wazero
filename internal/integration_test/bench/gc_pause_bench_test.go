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

// A stop-the-world GC has a harder problem than a cancellation does. Cancellation needs one
// goroutine to notice one flag; the GC has to suspend *every* goroutine to scan its stack,
// so it waits on the slowest one, and it does that on every cycle rather than once. A
// goroutine executing wazevo-generated code cannot be preempted asynchronously -- the signal
// handler cannot find a Go frame for a PC in JIT memory -- so the runtime has to wait for it
// to reach a synchronous preemption point, which is a Go function call. The interrupt check
// trampoline is the only Go call a wasm loop makes, which makes GC exposure a function of
// how often that trampoline runs.
//
// BenchmarkGCPauseWithSpinningGuests measures the cost of a full GC cycle while every P is
// occupied by a guest, against loop body size. The heap under test is a fixed live structure
// built before measuring, so mark work is real and identical across approaches and the
// difference between them is waiting.
//
// Interpretation notes:
//   - compare each spinning/* row against no_guests, which is the same GC with nothing in
//     the way.
//   - max-ns/gc is the number that matters. A mean hides the cycles that waited.
func BenchmarkGCPauseWithSpinningGuests(b *testing.B) {
	if !platform.CompilerSupported() {
		b.Skip()
	}

	b.Run("no_guests", func(b *testing.B) { benchGCPause(b, 0, 0) })
	for _, units := range []int{1, 1_000, 100_000} {
		b.Run("spinning/body_"+unitLabel(units), func(b *testing.B) {
			benchGCPause(b, units, runtime.GOMAXPROCS(0))
		})
	}
}

func benchGCPause(b *testing.B, units, spinners int) {
	if spinners > 0 {
		bin := buildSpinModule(b, units)
		ctx := benchmarkCtx(context.Background())
		r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(true))
		defer r.Close(ctx)

		compiled, err := r.CompileModule(ctx, bin)
		require.NoError(b, err)
		defer startSpinners(b, ctx, r, compiled, spinners)()

		// Give them time to be in generated code rather than still starting up.
		time.Sleep(50 * time.Millisecond)
	}

	live := buildLiveHeap(200_000)
	defer func() { liveHeapSink = nil }()

	var worst time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		runtime.GC()
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	b.StopTimer()

	runtime.KeepAlive(live)
	b.ReportMetric(float64(worst), "max-ns/gc")
}

// liveHeapNode is a pointer-bearing object, so that retaining a lot of them gives the mark
// phase real work rather than letting it skip a pointerless span.
type liveHeapNode struct {
	next *liveHeapNode
	pad  [3]uintptr
}

// liveHeapSink keeps the structure reachable for the duration of a measurement.
var liveHeapSink *liveHeapNode

func buildLiveHeap(n int) *liveHeapNode {
	var head *liveHeapNode
	for i := 0; i < n; i++ {
		head = &liveHeapNode{next: head}
	}
	liveHeapSink = head
	return head
}

// BenchmarkHostProgressWhileSpinning is the other half of the question: not how long the GC
// waits, but whether ordinary Go code gets to run at all while guests are executing. That is
// the second of the two points this whole investigation rests on -- native code that does not
// coordinate with the scheduler can keep Go code off the CPU -- and it is the one an
// embedder feels as unrelated request latency rather than as a wasm problem.
//
// The host work here is allocation, both because it is what a Go service spends its time on
// and because it produces the real, ongoing GC pressure that the forced-GC benchmark above
// deliberately leaves out. Compare each spinning/* row against no_guests.
func BenchmarkHostProgressWhileSpinning(b *testing.B) {
	if !platform.CompilerSupported() {
		b.Skip()
	}

	b.Run("no_guests", func(b *testing.B) { benchHostProgress(b, 0, 0) })
	for _, units := range []int{1, 1_000, 100_000} {
		b.Run("spinning/body_"+unitLabel(units), func(b *testing.B) {
			benchHostProgress(b, units, runtime.GOMAXPROCS(0))
		})
	}
}

func benchHostProgress(b *testing.B, units, spinners int) {
	if spinners > 0 {
		bin := buildSpinModule(b, units)
		ctx := benchmarkCtx(context.Background())
		r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(true))
		defer r.Close(ctx)

		compiled, err := r.CompileModule(ctx, bin)
		require.NoError(b, err)
		defer startSpinners(b, ctx, r, compiled, spinners)()

		time.Sleep(50 * time.Millisecond)
	}

	// Retained in a ring so that most of what is allocated dies, but enough survives to keep
	// the collector working rather than sweeping an empty heap.
	ring := make([][]byte, 256)

	var worst time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		ring[i%len(ring)] = make([]byte, 4096)
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	b.StopTimer()

	runtime.KeepAlive(ring)
	// The worst single allocation is the interesting one: a mean of a million fast
	// allocations hides the one that waited behind a GC that was waiting on a guest.
	b.ReportMetric(float64(worst), "max-ns/alloc")
}
