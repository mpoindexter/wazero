package bench

import (
	"context"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/binaryencoding"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// The interrupt check lives at loop back-edges, so how promptly a guest can be stopped is
// set by how much work it does between them -- not by how much work it does in total. A
// guest with a very long loop body reaches its next check rarely, whether by accident
// (an unrolled inner loop, an inlined callee) or on purpose.
//
// BenchmarkInterruptLatency measures the delay a guest like that can impose, exactly as an
// embedder would experience it: give the calls a context with a deadline, wait for them to
// return, and report how long after that deadline they actually did.
//
// Everything between the deadline instant and the call returning is inside the measurement,
// including the part that is easy to lose: the goroutine that delivers the cancellation needs
// a P of its own, and the guests are holding them. Under an approach that yields a P only
// every N back-edges, that is where most of the delay lives -- the guest cannot even be *told*
// to stop until it reaches a Go call. Starting the clock when cancellation was delivered
// rather than when it was due would drop that term and, at GOMAXPROCS=1, drop essentially the
// whole effect.
//
// The cost of measuring against the deadline is Go's timer error, a median of 1.04ms on
// darwin (see _interrupt_bench/timer_probe). That is a floor on every row here, so a result
// at ~1ms means "no slower than a context deadline can be observed at all".
//
// Three variants, differing in which calls share the deadline:
//
//   - alone: one guest.
//   - one_of_N: GOMAXPROCS+1 guests, one on the deadline context and the rest left running.
//     A per-request timeout expiring on a loaded server, and the hard case: nothing else in
//     the process has any reason to give up a P.
//   - all_of_N: GOMAXPROCS+1 guests, all on the deadline context. A shutdown. Once the first
//     guest stops it frees a P, which lets the next cancellation be delivered, so the tail is
//     cheap -- but the first one still has to be reached, so unlike a cancel-relative
//     measurement this does not hide the wait.
//
// The variants collapse at GOMAXPROCS=1, where only alone is run.
//
// Interpretation notes:
//   - sec/op is meaningless here; it is dominated by the fixed run-up to the deadline. Read
//     ns/interrupt (mean) and max-ns/interrupt (worst case seen in the run).
//   - worst case is the number that matters, since the premise is a guest chosen by
//     someone who wants the process to stall.
func BenchmarkInterruptLatency(b *testing.B) {
	if !platform.CompilerSupported() {
		b.Skip()
	}

	type variant struct {
		name             string
		total, cancelled int
	}
	// One more in-flight call than there are Ps, which is what a loaded server looks like.
	p := runtime.GOMAXPROCS(0)
	loaded := p + 1
	variants := []variant{{"alone", 1, 1}}
	if p > 1 {
		variants = append(variants,
			variant{"one_of_" + strconv.Itoa(loaded), loaded, 1},
			variant{"all_of_" + strconv.Itoa(loaded), loaded, loaded},
		)
	}

	for _, v := range variants {
		for _, units := range []int{1, 1_000, 10_000, 100_000} {
			b.Run(v.name+"/body_"+unitLabel(units), func(b *testing.B) {
				benchInterruptLatency(b, units, v.total, v.cancelled)
			})
		}
	}
}

// budget is how long the calls are given before their deadline expires: long enough that all
// of them are certainly executing generated code by then, short enough that b.N rounds stay
// quick.
const budget = 20 * time.Millisecond

func benchInterruptLatency(b *testing.B, units, total, cancelled int) {
	bin := buildSpinModule(b, units)

	ctx := benchmarkCtx(context.Background())
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(true))
	defer r.Close(ctx)

	compiled, err := r.CompileModule(ctx, bin)
	require.NoError(b, err)

	var sum, worst time.Duration
	for i := 0; i < b.N; i++ {
		// A closed module stays closed, so each round needs fresh instances. Instantiate
		// before setting the deadline so that only the calls themselves are inside it.
		mods := make([]api.Module, total)
		errs := make([]error, total)
		for j := range mods {
			mod, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(""))
			require.NoError(b, err)
			mods[j] = mod
		}

		deadline := time.Now().Add(budget)
		callCtx, cancel := context.WithDeadline(ctx, deadline)

		var timedCalls, backgroundCalls sync.WaitGroup
		for j := 0; j < total; j++ {
			// The first `cancelled` calls carry the deadline and are the ones being
			// timed. The rest are load: they run on a context with no deadline and are
			// stopped afterwards, so nothing gives up a P on their account.
			c, wg := ctx, &backgroundCalls
			if j < cancelled {
				c, wg = callCtx, &timedCalls
			}
			wg.Add(1)
			go func(j int, c context.Context, wg *sync.WaitGroup) {
				defer wg.Done()
				_, errs[j] = mods[j].ExportedFunction("spin").Call(c)
			}(j, c, wg)
		}

		timedCalls.Wait()
		overshoot := time.Since(deadline)
		cancel()

		for j := cancelled; j < total; j++ {
			_ = mods[j].Close(ctx)
		}
		backgroundCalls.Wait()

		for j := 0; j < cancelled; j++ {
			if errs[j] == nil {
				b.Fatal("spin returned on its own; the loop was supposed to be unbounded")
			}
			_ = mods[j].Close(ctx)
		}
		if overshoot < 0 {
			b.Fatal("call returned before its deadline; it cannot have been running")
		}

		sum += overshoot
		if overshoot > worst {
			worst = overshoot
		}
	}

	b.ReportMetric(float64(sum)/float64(b.N), "ns/interrupt")
	b.ReportMetric(float64(worst), "max-ns/interrupt")
}

// startSpinners runs n guest calls that never return on their own, to occupy the Ps. They
// are stopped by closing their modules, which the same interrupt check they are being used
// to measure is what notices -- so the returned stop func can take as long as the latency
// under study, which is itself informative when it does.
func startSpinners(b *testing.B, ctx context.Context, r wazero.Runtime, compiled wazero.CompiledModule, n int) func() {
	b.Helper()
	mods := make([]api.Module, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		mod, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(""))
		require.NoError(b, err)
		mods[i] = mod
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mod.ExportedFunction("spin").Call(ctx)
		}()
	}
	return func() {
		for _, m := range mods {
			_ = m.Close(ctx)
		}
		wg.Wait()
	}
}

func unitLabel(units int) string {
	switch {
	case units >= 1_000_000 && units%1_000_000 == 0:
		return strconv.Itoa(units/1_000_000) + "M"
	case units >= 1_000 && units%1_000 == 0:
		return strconv.Itoa(units/1_000) + "k"
	default:
		return strconv.Itoa(units)
	}
}

// buildSpinModule produces a module exporting:
//
//	(func (export "spin") (result i64) (local $acc i64)
//	  (loop
//	    <units copies of: (local.set $acc (i64.add (local.get $acc) (i64.const 1)))>
//	    (br_if 0 (i64.ne (local.get $acc) (i64.const -1))))
//	  (local.get $acc))
//
// $acc reaches -1 only after 2^64 iterations, so the loop is unbounded in practice and the
// only way out is interruption.
//
// The body is a *dependent* add chain on purpose. Each add consumes the previous one's
// result, so dead code elimination cannot drop it (the chain feeds the loop condition) and
// the CPU cannot overlap the adds. That makes `units` translate into time between
// back-edges, which is the variable under study; independent work would be absorbed by
// instruction-level parallelism and understate the gap.
func buildSpinModule(b *testing.B, units int) []byte {
	b.Helper()
	const i64 = wasm.ValueTypeI64

	body := make([]byte, 0, units*7+16)
	body = append(body, opLoop, bt0x40)
	for i := 0; i < units; i++ {
		body = append(body, opLocalGet, 0, opI64Const, 0x01, opI64Add, opLocalSet, 0)
	}
	// i64.const -1 is 0x7f in signed leb128.
	body = append(body, opLocalGet, 0, opI64Const, 0x7f, opI64Ne, opBrIf, 0)
	body = append(body, opEnd, opLocalGet, 0, opEnd)

	return binaryencoding.EncodeModule(&wasm.Module{
		TypeSection: []wasm.FunctionType{{
			Results: []wasm.ValueType{i64}, ResultNumInUint64: 1,
		}},
		FunctionSection: []wasm.Index{0},
		ExportSection:   []wasm.Export{{Name: "spin", Type: wasm.ExternTypeFunc, Index: 0}},
		CodeSection:     []wasm.Code{{LocalTypes: []wasm.ValueType{i64}, Body: body}},
	})
}

const opI64Ne = 0x52
