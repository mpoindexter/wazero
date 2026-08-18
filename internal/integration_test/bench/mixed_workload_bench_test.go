package bench

import (
	"context"
	"errors"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/sys"
)

// Every other benchmark here is a worst case: a guest that never stops, a machine with nothing
// to spare, a deadline that always fires. BenchmarkMixedWorkload is the opposite question --
// what does turning `WithCloseOnContextDone` on cost a service that is behaving normally?
//
// A request is a mix of what a real handler does, in order:
//
//	Go CPU + allocation  ->  guest call (compute)  ->  IO wait  ->  guest call (memory)  ->  Go allocation
//
// so the process is simultaneously running Go code, running generated code, allocating enough to
// keep the collector busy, and parking on IO. Requests run on more goroutines than there are Ps,
// which is what makes the scheduler interesting, but the *offered load* is deliberately below
// capacity: mixedWorkers goroutines each spend most of a request asleep, so the service keeps up
// with its own offered load. A saturated machine is the case the other benchmarks already cover,
// and it is not where most systems live.
//
// Read p50 against the serial cost of one request (~3.5ms as configured). If they are close,
// requests are not queueing and the run really was under capacity; if p50 is several times that,
// the sizing has drifted and the numbers are measuring saturation instead.
//
// The worker count scales with GOMAXPROCS, so the offered load stays the same fraction of capacity
// whatever the benchmark is run on.
func BenchmarkMixedWorkload(b *testing.B) {
	if !platform.CompilerSupported() {
		b.Skip()
	}

	for _, ensure := range []bool{false, true} {
		label := "without_close_on_ctx_done"
		if ensure {
			label = "with_close_on_ctx_done"
		}
		b.Run(label, func(b *testing.B) { benchMixedWorkload(b, ensure) })
	}
}

// mixedWorkers is the number of requests in flight, deliberately several times GOMAXPROCS so
// goroutines queue for Ps the way they do in a real server. Scaling with GOMAXPROCS rather than
// fixing it keeps offered load at the same fraction of capacity on any machine.
func mixedWorkers() int { return 4 * runtime.GOMAXPROCS(0) }

const (
	// Sized so that a request is mostly IO, which is what keeps offered load under capacity.
	mixedTightIters = 300_000 // ~135us of guest compute
	mixedMemIters   = 200_000 // ~145us of guest work against linear memory
	mixedIOWait     = 3 * time.Millisecond
	// A real handler sets a deadline, so the timer and the watchdog goroutine it implies are
	// part of what is being measured. 200ms against a ~3.7ms request is 54x headroom, which
	// ought to be unreachable -- the `timeouts` metric reports when an approach reaches it
	// anyway, which is a different and worse failure than being slow.
	mixedDeadline = 200 * time.Millisecond
)

type mixedWorker struct {
	r          wazero.Runtime
	compiled   wazero.CompiledModule
	ctx        context.Context
	mod        api.Module
	tight, mem api.Function
	sink       uint64
	keep       [][]byte
}

// reinstantiate replaces this worker's module. A module that hit its deadline is closed for
// good, so a server would have to discard the instance and build another; doing the same here
// keeps a timeout from silently ending the worker.
func (w *mixedWorker) reinstantiate() error {
	if w.mod != nil {
		_ = w.mod.Close(w.ctx)
	}
	mod, err := w.r.InstantiateModule(w.ctx, w.compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return err
	}
	w.mod = mod
	w.tight = mod.ExportedFunction("tight_loop")
	w.mem = mod.ExportedFunction("mem_loop")
	return nil
}

func benchMixedWorkload(b *testing.B, ensureTermination bool) {
	bin := buildContextDoneModule(b)

	ctx := benchmarkCtx(context.Background())
	r := wazero.NewRuntimeWithConfig(ctx,
		wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(ensureTermination))
	defer r.Close(ctx)

	compiled, err := r.CompileModule(ctx, bin)
	require.NoError(b, err)

	// One module per worker, which is the pooled-instance pattern a server uses. Sharing one
	// instance across goroutines would serialize on the guest's linear memory instead.
	workers := make([]*mixedWorker, mixedWorkers())
	for i := range workers {
		workers[i] = &mixedWorker{r: r, compiled: compiled, ctx: ctx}
		require.NoError(b, workers[i].reinstantiate())
	}

	latencies := make([][]time.Duration, len(workers))
	var issued, timeouts int64
	var wg sync.WaitGroup

	b.ResetTimer()
	for i := range workers {
		wg.Add(1)
		go func(w *mixedWorker, slot int) {
			defer wg.Done()
			for {
				if atomic.AddInt64(&issued, 1) > int64(b.N) {
					return
				}
				start := time.Now()
				err := mixedRequest(w)
				latencies[slot] = append(latencies[slot], time.Since(start))
				if err == nil {
					continue
				}
				var exitErr *sys.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != sys.ExitCodeDeadlineExceeded {
					b.Error(err)
					return
				}
				atomic.AddInt64(&timeouts, 1)
				if err := w.reinstantiate(); err != nil {
					b.Error(err)
					return
				}
			}
		}(workers[i], i)
	}
	wg.Wait()
	b.StopTimer()

	var all []time.Duration
	for _, l := range latencies {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	if len(all) == 0 {
		return
	}
	b.ReportMetric(float64(all[len(all)/2]), "p50-ns/req")
	b.ReportMetric(float64(all[len(all)*99/100]), "p99-ns/req")
	b.ReportMetric(float64(all[len(all)-1]), "max-ns/req")
	b.ReportMetric(float64(timeouts), "timeouts")
}

// mixedRequest is one request: Go work, guest work, an IO wait, more guest work, more Go work.
// The per-request context carries a deadline because real handlers do, and because that is what
// makes the runtime spawn the cancellation watchdog when ensureTermination is on.
func mixedRequest(w *mixedWorker) error {
	reqCtx, cancel := context.WithTimeout(w.ctx, mixedDeadline)
	defer cancel()

	// Go, CPU and allocation: stand-in for decoding a request body.
	buf := make([]byte, 8<<10)
	var sum uint64
	for i := range buf {
		buf[i] = byte(i)
		sum = sum*31 + uint64(buf[i])
	}
	w.sink = sum

	// Guest, CPU bound.
	if _, err := w.tight.Call(reqCtx, mixedTightIters); err != nil {
		return err
	}

	// Waiting on something external.
	time.Sleep(mixedIOWait)

	// Guest, touching linear memory.
	if _, err := w.mem.Call(reqCtx, mixedMemIters); err != nil {
		return err
	}

	// Go, allocation: stand-in for building a response. Retained until the next request so it
	// survives long enough to be worth collecting.
	out := make([][]byte, 16)
	for i := range out {
		out[i] = make([]byte, 512)
	}
	w.keep = out
	return nil
}

// BenchmarkGuestCallFrequency isolates per-call cost from per-iteration cost. Every variant does
// the same total amount of guest work; only the number of Call boundaries it is split across
// changes. An approach whose overhead is per-iteration is flat across the sweep; one whose
// overhead is per-call rises with it.
//
// Two per-call costs are worth separating from per-iteration cost here. Every approach spawns a
// watchdog goroutine per Call when ensureTermination is on, and approach D additionally wraps each
// entry into generated code with entersyscall/exitsyscall -- on an idle machine exitsyscall
// reacquires the same P for nothing, but with more goroutines than Ps it can fail and put the
// goroutine on a run queue, turning each guest call into a scheduling round trip. The sweep shows
// whether the second is distinguishable from the first.
//
// Uses the same oversubscribed worker pool as BenchmarkMixedWorkload. The per-request context is
// deliberately absent: calls use the worker's context, so the watchdog is spawned but never has a
// deadline to fire on, which isolates the cost of the mechanism from the cost of a live timer.
func BenchmarkGuestCallFrequency(b *testing.B) {
	if !platform.CompilerSupported() {
		b.Skip()
	}

	const totalIters = 512_000
	for _, calls := range []int{1, 2, 8, 32, 128} {
		for _, ensure := range []bool{false, true} {
			label := "off"
			if ensure {
				label = "on"
			}
			b.Run("calls_"+strconv.Itoa(calls)+"/"+label, func(b *testing.B) {
				benchGuestCallFrequency(b, ensure, calls, uint64(totalIters/calls))
			})
		}
	}
}

func benchGuestCallFrequency(b *testing.B, ensureTermination bool, calls int, itersPerCall uint64) {
	bin := buildContextDoneModule(b)

	ctx := benchmarkCtx(context.Background())
	r := wazero.NewRuntimeWithConfig(ctx,
		wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(ensureTermination))
	defer r.Close(ctx)

	compiled, err := r.CompileModule(ctx, bin)
	require.NoError(b, err)

	workers := make([]*mixedWorker, mixedWorkers())
	for i := range workers {
		workers[i] = &mixedWorker{r: r, compiled: compiled, ctx: ctx}
		require.NoError(b, workers[i].reinstantiate())
	}

	var issued int64
	var wg sync.WaitGroup
	b.ResetTimer()
	for i := range workers {
		wg.Add(1)
		go func(w *mixedWorker) {
			defer wg.Done()
			for {
				if atomic.AddInt64(&issued, 1) > int64(b.N) {
					return
				}
				for c := 0; c < calls; c++ {
					if _, err := w.tight.Call(ctx, itersPerCall); err != nil {
						b.Error(err)
						return
					}
				}
			}
		}(workers[i])
	}
	wg.Wait()
	b.StopTimer()
}
