# Interruption approach investigation

## Background

There are two key points to improving close on context done:
- Crossing the Go barrier from native code is relatively expensive
- Without coordinating with the Go runtime, executing native code can prevent Go from executing concurrently

Point 1 means that we should minimize the number of times we cross from native to Go if we want to perform well.
Point 2 means that we MUST coordinate with Go in some way to ensure that the code that would close the module (another goroutine) executes.

## Approaches

### Current approach (Approach A)

In the current approach, every loop iteration calls into a Go function to check if the module is terminated (https://github.com/wazero/wazero/blob/main/internal/engine/wazevo/frontend/lower.go#L1368)
If the module has been closed, a panic is raised, aborting execution of the Go function. This fulfills point 2 by returning to the Go runtime at each loop iteration, allowing concurrent Go code a chance to execute.

Pros:
- Simple
- Obviously correct

Cons:
- Expensive, because it pays the Go barrier crossing cost every loop iteration, reported as slowing code down by 10-20x

### Interrupt check on an interval (Approach B)

The approach proposed by https://github.com/wazero/wazero/pull/2482

Basically, add a config knob to check for interruption only every N loop iterations

A variant was proposed in https://github.com/wazero/wazero/pull/2525 where the check is changed to a hybrid:
A flag is exposed to native code that it can check each loop iteration, and if true abort. This is not sufficient
in and of itself as the Go code responsible for setting the flag is not guaranteed to run without coordination with
the Go runtime, so a 1-every-N-loops exit is still needed.

I implemented a version to test this approach that was a synthesis of the two PRs: keep the configuration knob to see
if N needs to be configurable, but implement the flag test from 2525 for quicker interruption.

Open questions:
- is there a setting that can be picked that removes the need to tune N for the 1-of-N exit to Go? (#2482 proposed making this configurable, #2525 hardcoded N)
- what factors would influence N? Off the top of my head, number of instructions in the loop, GOMAXPROCS, goroutine usage pattern, number of CPUs all seem like they would influence N
- is there an N that is resilient to poorly behaving guest code? (i.e. extremely long loop bodies, either intentionally or by accident)

Pros:
- Reduces the overhead proportional to N

Cons:
- Need to determine a correct value for N, either in the embedder, or in wazero itself
- If embedder is responsible for setting N, needs new API
- If N is configurable, adds a new dimension to the compile cache

### Fuel API (Approach C)

Proposed by https://github.com/wazero/wazero/pull/2500

Interruption would be controlled by Fuel, with a trap raised whenever fuel was exhausted

I did not benchmark or test this approach because no compiler implementation exists.

Pros:
- Aligns with how other engines expose this concept
- Flexible
- Resilient to guest code shape: fuel is proportional to instructions executed, so loop structure in guest code does not matter

Cons:
- Only implemented in the interpreter. It is unclear how to implement it in the compiler.
- Needs new API

### Runtime coordination (Approach D)

Proposed by https://github.com/mpoindexter/wazero/pull/1/changes

Instead of trying to determine when we should exit to Go, instead coordinate with the scheduler to tell it we're executing native code using runtime.entersyscall/runtime.exitsyscall around each switch to native code.
The Go scheduler is then responsible for ensuring that other Go code is allowed to run concurrently when the current thread is executing native code.
This matches what CGO does under the covers when calling out to C code, and what the Go runtime does when entering a syscall. Once the runtime is ensuring that other Go code can run while we're executing the the generated code, we can then just check the module closed flag every loop iteration, and exit to Go only for a final check and cleanup if the module is closed.

The version tested on this branch makes two significant changes from the code proposed in the PR above:
- Removes the atomic load of the closed check - on amd64 and arm64 the flag is guaranteed to be eventually written to memory, and the full exit triggered by it does a full atomic load to enforce ordering.
- Eliminates calling runtime.entersyscall/runtime.exitsyscall around transitions when WithCloseOnContextDone is false. This removes virtually all overhead from this approach when WithCloseOnContextDone is false. 

Pros:
- No new API
- Resilient to guest code shape
- Ensures that Go runtime has clear visibility into what's happening on this thread to make globally good decisions

Cons:
- As proposed, it relies on accessing Go scheduler internals via the go:linkname directive. A thin CGO shim could probably move this to an approach that does not rely on internals, but that would break `CGO_ENABLED=0` builds.
- Increases the overhead of all Go->native transitions by a small amount (although this is reduced significantly as of Go 1.26 due to https://go.dev/doc/go1.26#faster-cgo-calls)

## Benchmarks

Several concerns are relevant to assessing the performance of any of these changes:
- Benchmark of existing code performance (i.e. how much does the change impact performance with ensure termination disabled)
- Benchmark of performance change when ensure termination is enabled
- Assess how long a request to interrupt takes to actually take effect, particularly in the face of poorly behaved guest code (e.g. guest code with long stretches between loop back-edges).
- Test how termination behavior influences other code executing in the system

To assess this the following benchmarks are useful:
- BenchmarkContextDoneOverhead (new). Measures the impact to a set of synthetic code with and without ensure termination
- BenchmarkInvocation (existing). Measures impact on invocations, with ensure termination both
  disabled and enabled. Run it with `-skip-interpreter`: none of the approaches touch the
  interpreter, so running the interpreter tests just introduces noise.
- BenchmarkInterruptLatency (new). Measures interruption latency against loop body size and system
  load. Measures the "resilient to guest code shape" dimension.
- BenchmarkGCPauseWithSpinningGuests and BenchmarkHostProgressWhileSpinning (new). Measure what a
  spinning guest costs the rest of the Go process: how long a GC cycle takes, and whether ordinary
  Go code makes progress.
- BenchmarkMixedWorkload and BenchmarkGuestCallFrequency (new). A service-shaped workload -- Go CPU,
  Go allocation, guest calls, IO waits, more goroutines than Ps -- run *below* capacity, which is
  where most systems actually live and which none of the above covers. The companion sweep varies
  guest call frequency at constant total work, to separate per-call from per-iteration cost.

Methodology:
Run each of the benchmarks above with the changes from each approach multiple times, and use https://pkg.go.dev/golang.org/x/perf/cmd/benchstat to measure change in behavior.

Each approach is selected by a build tag, so all of them live in the tree at once:

| Approach | Build tag |
| --- | --- |
| A | (none) |
| B | `efficient_interrupt_approach_b` |
| D | `efficient_interrupt_approach_d` |

e.g. `go test -tags efficient_interrupt_approach_d -run XXX -bench BenchmarkContextDoneOverhead ./internal/integration_test/bench/`.
The tags are mutually exclusive; selecting both fails to build.

Approach B's N is set with `experimental.WithInterruptCheckInterval(ctx, n)` on the context passed to
`Instantiate`/`CompileModule`, and the benchmarks test at several N's.

### Results

#### BenchmarkContextDoneOverhead

Apple M4 Pro (14 logical CPUs), go1.26.5, darwin/arm64. Seven configurations -- A, D, and B at
N = 16, 64, 256, 1024, 4096 -- each at GOMAXPROCS=1 and at the default, `-benchtime=500ms -count=6`,
medians via benchstat. All fourteen were run interleaved, one sample each per round.

Raw output is in `_interrupt_bench/contextdone/{p1,pdefault}/<config>.txt` and regenerable with
`_interrupt_bench/run_contextdone.sh`.

"tight" is a pure integer loop; "mem" the same loop with an i64 load from linear memory per
iteration. "short_1k" is 1000 iterations per `Call`, "long_10M" is ten million.

##### With ensureTermination off, nothing costs anything

| GOMAXPROCS=14, feature off | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| tight, 1k iters | 472.3 ns | 471.9 ns | 476.8 ns | 474.8 ns | 474.9 ns | 472.4 ns | 474.3 ns |
| mem, 1k iters | 752.8 ns | 753.6 ns | 756.3 ns | 754.0 ns | 755.0 ns | 754.9 ns | 754.5 ns |
| tight, 10M iters | 4.474 ms | 4.460 ms | 4.464 ms | 4.455 ms | 4.463 ms | 4.454 ms | 4.472 ms |
| mem, 10M iters | 7.301 ms | 7.301 ms | 7.296 ms | 7.315 ms | 7.307 ms | 7.287 ms | 7.321 ms |

##### With it on

| GOMAXPROCS=14, feature on | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| tight, 1k iters | 18.63 µs | 0.835 µs | 2.336 µs | 1.477 µs | 1.225 µs | 1.145 µs | 1.102 µs |
| mem, 1k iters | 18.80 µs | 1.545 µs | 2.629 µs | 1.815 µs | 1.496 µs | 1.422 µs | 1.355 µs |
| tight, 10M iters | 128.99 ms | 4.889 ms | 15.19 ms | 9.732 ms | 7.966 ms | 7.491 ms | 7.358 ms |
| mem, 10M iters | 129.04 ms | 9.723 ms | 17.95 ms | 12.36 ms | 10.49 ms | 10.03 ms | 9.872 ms |

| GOMAXPROCS=1, feature on | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| tight, 1k iters | 14.33 µs | 0.920 µs | 2.039 µs | 1.397 µs | 1.208 µs | 1.167 µs | 1.138 µs |
| mem, 1k iters | 14.53 µs | 1.348 µs | 2.299 µs | 1.667 µs | 1.466 µs | 1.397 µs | 1.377 µs |
| tight, 10M iters | 129.95 ms | 4.870 ms | 15.45 ms | 9.782 ms | 7.984 ms | 7.489 ms | 7.331 ms |
| mem, 10M iters | 131.06 ms | 9.720 ms | 17.98 ms | 12.37 ms | 10.48 ms | 10.03 ms | 9.898 ms |

Every non-A "on" figure differs from A at p=0.002, the floor for six samples.

##### Per-iteration cost

`(on - off) / 10M`, the cost of one interrupt check:

| ns per loop back-edge | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| tight, GOMAXPROCS=14 | 12.45 | **0.043** | 1.073 | 0.528 | 0.350 | 0.304 | 0.289 |
| tight, GOMAXPROCS=1 | 12.55 | **0.042** | 1.098 | 0.533 | 0.352 | 0.303 | 0.287 |
| mem, GOMAXPROCS=14 | 12.17 | **0.242** | 1.065 | 0.504 | 0.318 | 0.275 | 0.255 |
| mem, GOMAXPROCS=1 | 12.37 | **0.243** | 1.067 | 0.505 | 0.318 | 0.272 | 0.258 |

#### BenchmarkInvocation

Same machine and methodology as above: seven configurations -- A, D, and B at N = 16, 64, 256,
1024, 4096 -- each at GOMAXPROCS=1 and at the default, `-benchtime=500ms -count=6`, medians, all
fourteen interleaved one sample per round.

The guest is TinyGo-compiled code with real loops, so with the feature on the interrupt check is
compiled into them; this is the question BenchmarkContextDoneOverhead asks, on something less
synthetic. The interpreter variants are skipped with `-skip-interpreter`, since no approach touches
the interpreter.

Raw output is in `_interrupt_bench/invocation/{p1,pdefault}/<config>.txt`, regenerable with
`_interrupt_bench/run_invocation.sh`; the tables below come from `_interrupt_bench/fmt_invocation.py`.

##### With ensureTermination off

With the feature off we'd expect no measurable difference in approaches, and the results confirm it.

**GOMAXPROCS=14, feature off**

| | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| base64_5_per_exec | 7.92 µs | 7.81 µs | 7.75 µs | 7.79 µs | 7.65 µs | 7.76 µs | 7.81 µs |
| base64_100_per_exec | 156.87 µs | 155.17 µs | 156.92 µs | 154.92 µs | 153.48 µs | 156.13 µs | 156.49 µs |
| base64_10000_per_exec | 15.572 ms | 15.488 ms | 15.461 ms | 15.597 ms | 15.492 ms | 15.436 ms | 15.420 ms |
| fib_for_5 | 34.4 ns | 34.2 ns | 34.6 ns | 34.8 ns | 34.8 ns | 34.5 ns | 34.9 ns |
| fib_for_10 | 160.0 ns | 159.2 ns | 162.8 ns | 160.4 ns | 162.3 ns | 162.1 ns | 160.6 ns |
| fib_for_20 | 17.84 µs | 18.05 µs | 17.95 µs | 18.25 µs | 18.27 µs | 18.57 µs | 18.01 µs |
| fib_for_30 | 2.209 ms | 2.220 ms | 2.273 ms | 2.225 ms | 2.272 ms | 2.247 ms | 2.289 ms |
| string_manipulation_size_50 | 9.42 µs | 9.29 µs | 9.36 µs | 9.29 µs | 9.39 µs | 9.38 µs | 9.39 µs |
| string_manipulation_size_100 | 28.74 µs | 28.64 µs | 28.74 µs | 28.77 µs | 28.88 µs | 28.95 µs | 28.84 µs |
| string_manipulation_size_1000 | 2.073 ms | 2.090 ms | 2.085 ms | 2.091 ms | 2.087 ms | 2.102 ms | 2.098 ms |
| reverse_array_size_500 | 2.02 µs | 2.01 µs | 2.01 µs | 2.02 µs | 2.02 µs | 2.01 µs | 2.02 µs |
| reverse_array_size_1000 | 4.41 µs | 4.35 µs | 4.53 µs | 4.54 µs | 4.31 µs | 4.54 µs | 4.26 µs |
| reverse_array_size_10000 | 75.16 µs | 82.59 µs | 75.89 µs | 82.77 µs | 83.66 µs | 75.53 µs | 91.33 µs |
| random_mat_mul_size_5 | 8.27 µs | 7.55 µs | 6.98 µs | 6.54 µs | 6.48 µs | 7.19 µs | 7.08 µs |
| random_mat_mul_size_10 | 12.59 µs | 12.56 µs | 12.89 µs | 12.51 µs | 12.64 µs | 12.81 µs | 13.73 µs |
| random_mat_mul_size_20 | 55.12 µs | 54.20 µs | 54.16 µs | 54.76 µs | 55.08 µs | 54.26 µs | 55.60 µs |

Two benchmarks are too noisy to read at this sample count, and stay that way in every table below:
`random_mat_mul_size_5` and `reverse_array_size_10000` carry +/-20% to +/-46% confidence intervals
on their own medians. They produce benchstat's only "significant" feature-off rows (-17% and +73%),
which given the above cannot be real.

##### With it on

**GOMAXPROCS=14, feature on**

| | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| base64_5_per_exec | 13.86 µs | 12.26 µs | 12.35 µs | 12.45 µs | 12.18 µs | 12.42 µs | 12.12 µs |
| base64_100_per_exec | 271.10 µs | 240.04 µs | 240.55 µs | 239.99 µs | 239.46 µs | 238.29 µs | 239.04 µs |
| base64_10000_per_exec | 27.059 ms | 23.865 ms | 24.140 ms | 24.292 ms | 23.994 ms | 23.690 ms | 23.847 ms |
| fib_for_5 | 555.8 ns | 282.6 ns | 305.7 ns | 281.9 ns | 273.3 ns | 273.8 ns | 266.8 ns |
| fib_for_10 | 4.53 µs | 449.8 ns | 780.3 ns | 534.2 ns | 462.8 ns | 440.1 ns | 439.2 ns |
| fib_for_20 | 398.39 µs | 27.53 µs | 64.07 µs | 38.66 µs | 31.50 µs | 30.76 µs | 29.38 µs |
| fib_for_30 | 46.648 ms | 2.733 ms | 6.396 ms | 4.012 ms | 3.197 ms | 3.191 ms | 3.097 ms |
| string_manipulation_size_50 | 53.28 µs | 12.21 µs | 15.53 µs | 12.39 µs | 11.53 µs | 11.44 µs | 11.26 µs |
| string_manipulation_size_100 | 159.28 µs | 36.24 µs | 48.07 µs | 39.76 µs | 36.75 µs | 36.05 µs | 35.85 µs |
| string_manipulation_size_1000 | 13.829 ms | 2.303 ms | 3.258 ms | 2.607 ms | 2.404 ms | 2.345 ms | 2.325 ms |
| reverse_array_size_500 | 18.54 µs | 2.94 µs | 4.27 µs | 3.28 µs | 2.98 µs | 2.90 µs | 2.86 µs |
| reverse_array_size_1000 | 39.15 µs | 6.35 µs | 8.97 µs | 7.09 µs | 6.43 µs | 6.28 µs | 6.06 µs |
| reverse_array_size_10000 | 692.71 µs | 108.26 µs | 137.00 µs | 118.08 µs | 105.43 µs | 94.87 µs | 93.22 µs |
| random_mat_mul_size_5 | 39.66 µs | 6.75 µs | 12.33 µs | 8.57 µs | 7.73 µs | 8.50 µs | 7.84 µs |
| random_mat_mul_size_10 | 70.97 µs | 16.75 µs | 22.28 µs | 17.97 µs | 17.44 µs | 16.84 µs | 16.84 µs |
| random_mat_mul_size_20 | 266.82 µs | 61.65 µs | 80.86 µs | 67.88 µs | 65.09 µs | 63.41 µs | 63.00 µs |

**GOMAXPROCS=1, feature on**

| | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| base64_5_per_exec | 16.58 µs | 15.02 µs | 15.03 µs | 14.98 µs | 14.94 µs | 14.85 µs | 14.78 µs |
| base64_100_per_exec | 320.19 µs | 286.62 µs | 285.51 µs | 284.80 µs | 282.49 µs | 284.49 µs | 284.36 µs |
| base64_10000_per_exec | 31.987 ms | 28.709 ms | 28.898 ms | 28.503 ms | 28.552 ms | 28.532 ms | 28.401 ms |
| fib_for_5 | 727.1 ns | 495.9 ns | 525.1 ns | 482.3 ns | 472.9 ns | 474.4 ns | 475.1 ns |
| fib_for_10 | 3.67 µs | 631.3 ns | 897.7 ns | 721.0 ns | 651.9 ns | 625.9 ns | 616.5 ns |
| fib_for_20 | 400.17 µs | 22.38 µs | 55.90 µs | 35.62 µs | 27.35 µs | 25.21 µs | 25.14 µs |
| fib_for_30 | 47.485 ms | 2.788 ms | 6.483 ms | 4.310 ms | 3.378 ms | 3.173 ms | 3.060 ms |
| string_manipulation_size_50 | 47.63 µs | 9.94 µs | 13.63 µs | 11.01 µs | 10.25 µs | 10.12 µs | 10.05 µs |
| string_manipulation_size_100 | 152.87 µs | 32.06 µs | 42.32 µs | 33.95 µs | 31.81 µs | 31.24 µs | 30.83 µs |
| string_manipulation_size_1000 | 13.945 ms | 2.291 ms | 3.266 ms | 2.595 ms | 2.396 ms | 2.336 ms | 2.318 ms |
| reverse_array_size_500 | 16.56 µs | 2.68 µs | 3.86 µs | 3.07 µs | 2.83 µs | 2.76 µs | 2.72 µs |
| reverse_array_size_1000 | 36.05 µs | 5.36 µs | 8.06 µs | 6.37 µs | 5.47 µs | 5.51 µs | 5.61 µs |
| reverse_array_size_10000 | 708.24 µs | 88.32 µs | 143.89 µs | 113.46 µs | 110.20 µs | 89.86 µs | 96.59 µs |
| random_mat_mul_size_5 | 46.89 µs | 7.13 µs | 9.08 µs | 8.88 µs | 7.66 µs | 8.20 µs | 9.10 µs |
| random_mat_mul_size_10 | 69.88 µs | 13.46 µs | 17.45 µs | 14.96 µs | 13.80 µs | 15.07 µs | 13.54 µs |
| random_mat_mul_size_20 | 287.15 µs | 62.05 µs | 74.61 µs | 62.81 µs | 59.85 µs | 59.61 µs | 58.17 µs |

##### Cost of enabling the feature

Each configuration's own on/off ratio, so the comparison is against that build rather than across
builds:

**GOMAXPROCS=14**

| | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| base64_5_per_exec | 1.75x | 1.57x | 1.59x | 1.60x | 1.59x | 1.60x | 1.55x |
| base64_100_per_exec | 1.73x | 1.55x | 1.53x | 1.55x | 1.56x | 1.53x | 1.53x |
| base64_10000_per_exec | 1.74x | 1.54x | 1.56x | 1.56x | 1.55x | 1.53x | 1.55x |
| fib_for_5 | 16.16x | 8.26x | 8.83x | 8.09x | 7.85x | 7.92x | 7.64x |
| fib_for_10 | 28.28x | 2.83x | 4.79x | 3.33x | 2.85x | 2.72x | 2.74x |
| fib_for_20 | 22.33x | 1.53x | 3.57x | 2.12x | 1.72x | 1.66x | 1.63x |
| fib_for_30 | 21.12x | 1.23x | 2.81x | 1.80x | 1.41x | 1.42x | 1.35x |
| string_manipulation_size_50 | 5.66x | 1.31x | 1.66x | 1.33x | 1.23x | 1.22x | 1.20x |
| string_manipulation_size_100 | 5.54x | 1.27x | 1.67x | 1.38x | 1.27x | 1.25x | 1.24x |
| string_manipulation_size_1000 | 6.67x | 1.10x | 1.56x | 1.25x | 1.15x | 1.12x | 1.11x |
| reverse_array_size_500 | 9.20x | 1.46x | 2.13x | 1.62x | 1.48x | 1.44x | 1.42x |
| reverse_array_size_1000 | 8.87x | 1.46x | 1.98x | 1.56x | 1.49x | 1.38x | 1.42x |
| reverse_array_size_10000 | 9.22x | 1.31x | 1.81x | 1.43x | 1.26x | 1.26x | 1.02x |
| random_mat_mul_size_5 | 4.80x | 0.89x | 1.77x | 1.31x | 1.19x | 1.18x | 1.11x |
| random_mat_mul_size_10 | 5.64x | 1.33x | 1.73x | 1.44x | 1.38x | 1.32x | 1.23x |
| random_mat_mul_size_20 | 4.84x | 1.14x | 1.49x | 1.24x | 1.18x | 1.17x | 1.13x |

**GOMAXPROCS=1**

| | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| base64_5_per_exec | 2.13x | 1.93x | 1.93x | 1.91x | 1.89x | 1.90x | 1.89x |
| base64_100_per_exec | 2.08x | 1.86x | 1.85x | 1.83x | 1.82x | 1.86x | 1.84x |
| base64_10000_per_exec | 2.06x | 1.85x | 1.86x | 1.84x | 1.85x | 1.85x | 1.86x |
| fib_for_5 | 19.99x | 13.68x | 14.51x | 13.27x | 12.95x | 13.05x | 13.03x |
| fib_for_10 | 22.24x | 3.86x | 5.41x | 4.35x | 3.90x | 3.74x | 3.77x |
| fib_for_20 | 21.77x | 1.25x | 3.12x | 1.98x | 1.52x | 1.39x | 1.40x |
| fib_for_30 | 21.12x | 1.25x | 2.86x | 1.93x | 1.54x | 1.41x | 1.39x |
| string_manipulation_size_50 | 5.07x | 1.06x | 1.44x | 1.18x | 1.09x | 1.08x | 1.07x |
| string_manipulation_size_100 | 5.32x | 1.12x | 1.46x | 1.17x | 1.10x | 1.08x | 1.07x |
| string_manipulation_size_1000 | 6.66x | 1.10x | 1.56x | 1.24x | 1.15x | 1.12x | 1.11x |
| reverse_array_size_500 | 8.20x | 1.32x | 1.91x | 1.52x | 1.41x | 1.37x | 1.35x |
| reverse_array_size_1000 | 8.19x | 1.18x | 1.84x | 1.45x | 1.25x | 1.24x | 1.24x |
| reverse_array_size_10000 | 7.72x | 1.17x | 1.89x | 1.51x | 1.21x | 1.08x | 1.06x |
| random_mat_mul_size_5 | 8.43x | 0.74x | 1.24x | 1.26x | 1.26x | 1.20x | 1.52x |
| random_mat_mul_size_10 | 5.59x | 1.05x | 1.31x | 1.03x | 1.07x | 1.08x | 1.03x |
| random_mat_mul_size_20 | 5.28x | 1.12x | 1.35x | 1.14x | 1.09x | 1.10x | 1.07x |

The spread across sub-benchmarks is wider than the spread across approaches, and it tracks how much
work the guest does between back-edges. `base64` calls a host function once per loop iteration, so
the check is amortized against that and costs everyone 1.5-1.7x; `fib` recurses with almost nothing
between back-edges and costs A 16-28x. That is the same relationship BenchmarkContextDoneOverhead
shows between its tight and mem loops, on code nobody wrote to demonstrate it.

`fib_for_5` is the one row where every approach is expensive -- 7.6-8.3x for D and B, 16x for A. At
34ns per call, per-`Call` cost due to launching the the watchdog goroutine `CloseModuleOnCanceledOrTimeout`
spawns dominates the cost.

B reaches D at N >= 256 here and the two are within noise at N = 4096, unlike
BenchmarkContextDoneOverhead where D's check was 7x cheaper per back-edge. Loop bodies in this guest
are large enough to amortize that difference away.

#### BenchmarkInterruptLatency

Same machine and methodology: seven configurations -- A, D, and B at N = 16, 64, 256, 1024, 4096 --
each at GOMAXPROCS=1 and at the default, `-benchtime=30x -count=6`, medians, all fourteen
interleaved one sample per round.

Raw output is in `_interrupt_bench/latency/{p1,pdefault}/<config>.txt`, regenerable with
`_interrupt_bench/run_latency.sh`; tables from `_interrupt_bench/fmt_latency.py`.

There is no with/without split: this benchmark always enables `WithCloseOnContextDone`, since
this test measures interruption latency. Its loaded variants need more than one P, so GOMAXPROCS=1 runs only `alone`.

Give the calls a context with a deadline, wait for them to return, report how long after the
deadline they actually did. `alone` is one guest; `one_of_15` is fifteen guests with one on the
deadline context and the rest left running; `all_of_15` is fifteen all on it. The loop body is a
dependent add chain of the stated length. There is a floor around 1ms from Go's timer resolution on
darwin, so ~1ms means "no slower than a context deadline can be observed at all".

**GOMAXPROCS=14** -- mean / worst, per interruption

| variant, loop body | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| alone/body_1 | 930.4 µs / 1.05 ms | 982.3 µs / 1.09 ms | 953.2 µs / 1.03 ms | 961.7 µs / 1.04 ms | 995.4 µs / 1.54 ms | 935.6 µs / 1.07 ms | 955.2 µs / 1.27 ms |
| alone/body_1k | 999.3 µs / 1.05 ms | 1.01 ms / 1.06 ms | 977.4 µs / 1.06 ms | 935.7 µs / 1.03 ms | 1.02 ms / 1.55 ms | 945.0 µs / 1.06 ms | 926.0 µs / 1.06 ms |
| alone/body_10k | 961.3 µs / 1.04 ms | 997.0 µs / 1.05 ms | 954.2 µs / 1.06 ms | 977.2 µs / 1.03 ms | 969.6 µs / 1.05 ms | 949.8 µs / 1.07 ms | 977.1 µs / 1.02 ms |
| alone/body_100k | 965.0 µs / 1.05 ms | 1.00 ms / 1.07 ms | 968.5 µs / 1.05 ms | 972.0 µs / 1.07 ms | 985.2 µs / 1.05 ms | 1.03 ms / 1.24 ms | 1.01 ms / 1.07 ms |
| one_of_15/body_1 | 17.28 ms / 72.54 ms | 1.46 ms / 8.36 ms | 17.07 ms / 55.93 ms | 19.00 ms / 69.90 ms | 17.86 ms / 59.78 ms | 20.33 ms / 74.54 ms | 20.39 ms / 62.48 ms |
| one_of_15/body_1k | 18.76 ms / 64.95 ms | 1.66 ms / 11.37 ms | 19.31 ms / 75.80 ms | 16.72 ms / 63.49 ms | 20.68 ms / 76.00 ms | 16.97 ms / 69.57 ms | 20.12 ms / 70.74 ms |
| one_of_15/body_10k | 19.89 ms / 69.91 ms | 1.24 ms / 8.18 ms | 16.65 ms / 56.03 ms | 15.01 ms / 57.86 ms | 17.05 ms / 81.00 ms | 18.92 ms / 59.58 ms | 26.85 ms / 85.67 ms |
| one_of_15/body_100k | 18.73 ms / 60.21 ms | 1.65 ms / 9.56 ms | 18.77 ms / 63.08 ms | 16.69 ms / 48.48 ms | 26.54 ms / 80.52 ms | 28.68 ms / 91.29 ms | 116.09 ms / 223.70 ms |
| all_of_15/body_1 | 16.06 ms / 49.49 ms | 1.36 ms / 6.95 ms | 16.25 ms / 40.23 ms | 13.02 ms / 37.34 ms | 15.15 ms / 45.50 ms | 14.41 ms / 35.69 ms | 15.71 ms / 41.73 ms |
| all_of_15/body_1k | 18.20 ms / 49.89 ms | 1.45 ms / 5.83 ms | 13.50 ms / 43.02 ms | 12.51 ms / 49.91 ms | 15.90 ms / 48.07 ms | 15.20 ms / 42.16 ms | 12.30 ms / 38.81 ms |
| all_of_15/body_10k | 14.19 ms / 45.54 ms | 1.42 ms / 6.45 ms | 13.18 ms / 43.61 ms | 17.26 ms / 41.64 ms | 13.99 ms / 41.95 ms | 13.73 ms / 46.10 ms | 17.75 ms / 60.56 ms |
| all_of_15/body_100k | 16.09 ms / 42.67 ms | 1.46 ms / 7.33 ms | 15.50 ms / 44.47 ms | 18.74 ms / 48.05 ms | 19.78 ms / 46.30 ms | 19.99 ms / 58.60 ms | 102.40 ms / 175.60 ms |

**GOMAXPROCS=1** -- mean / worst, per interruption

| variant, loop body | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| alone/body_1 | 5.26 ms / 16.51 ms | 1.01 ms / 1.04 ms | 4.97 ms / 5.46 ms | 4.94 ms / 5.07 ms | 4.99 ms / 5.05 ms | 4.95 ms / 5.10 ms | 4.97 ms / 5.08 ms |
| alone/body_1k | 5.83 ms / 30.08 ms | 1.02 ms / 1.06 ms | 5.83 ms / 30.07 ms | 5.51 ms / 30.06 ms | 5.78 ms / 30.08 ms | 5.80 ms / 30.22 ms | 5.76 ms / 30.61 ms |
| alone/body_10k | 5.64 ms / 17.61 ms | 959.6 µs / 1.07 ms | 6.52 ms / 30.10 ms | 6.61 ms / 30.84 ms | 6.53 ms / 30.09 ms | 6.58 ms / 31.27 ms | 17.14 ms / 38.58 ms |
| alone/body_100k | 5.78 ms / 24.66 ms | 1.00 ms / 1.05 ms | 6.45 ms / 26.09 ms | 5.96 ms / 24.32 ms | 8.59 ms / 29.24 ms | 7.31 ms / 40.20 ms | 75.57 ms / 122.72 ms |

##### With a spare P, nothing separates the approaches

Every `alone` row at GOMAXPROCS=14 is 0.93-1.03ms mean, which is the timer floor, for every
approach and every N. With a spare P the cancellation is delivered at once, the watchdog sets the
flag at once, and the guest's inline check catches it on the next back-edge whenever that is.

Contention between guests is not the variable; a spare P is. The `alone` rows at GOMAXPROCS=1 are
just as uncontended -- one guest, nothing competing with it -- and they separate the approaches
fivefold, as the next section shows.

##### Without a spare P, only D stays at the floor

In `one_of_15`, excluding N=4096 at the 100k body below, A and B are 15-29ms mean with worst cases
of 48-91ms, and neither N nor loop body size moves them much -- the limit is sysmon, which marks a
wasm goroutine preemptible only after it has run ~10ms. D is 1.24-1.66ms mean, worst 8.2-11.4ms.

The same holds at GOMAXPROCS=1 with a single guest and no competition at all, which is what shows
that the variable is a spare P rather than contention: A and B are 4.9-8.6ms mean (again excluding
N=4096 at the two largest bodies), D is 0.96-1.02ms mean with a worst case of 1.07ms, tighter than
the timer can resolve.

##### B at N=4096 adds `N x body` on top

At a 100k-instruction body, B at N=4096 is 116ms mean / 224ms worst in `one_of_15`, against
17-27ms for every other N; 102ms / 176ms in `all_of_15`; and 75.6ms / 123ms even alone on one P.
The 10k body shows the same effect an order of magnitude down (17.1ms alone at GOMAXPROCS=1 against
6.5ms at every smaller N). Nothing else in the sweep depends on body size this way.

#### BenchmarkGCPauseWithSpinningGuests / BenchmarkHostProgressWhileSpinning

Same machine and methodology: seven configurations -- A, D, and B at N = 16, 64, 256, 1024, 4096 --
each at GOMAXPROCS=1 and at the default, `-count=6`, medians, all fourteen interleaved one sample
per round. `-benchtime=10x` for the GC pause and `200000x` for host allocation, since one is
milliseconds and the other nanoseconds.

Raw output is in `_interrupt_bench/{gcpause,hostprogress}/{p1,pdefault}/<config>.txt`, regenerable
with `_interrupt_bench/run_gc.sh`; tables from `_interrupt_bench/fmt_gc.py`.

Both always enable `WithCloseOnContextDone` -- what a spinning guest costs the rest of the process
is only a question when the guest is interruptible at all -- so there is no with/without split.
Both measure the *host*, not the guest: `GCPause` times a forced `runtime.GC()` against a fixed live
heap of 200k pointer-bearing objects, `HostProgress` times an allocation loop on an ordinary Go
goroutine. Both size their spinner pool from GOMAXPROCS, so the GOMAXPROCS=1 tables have one
spinning guest against the default's fourteen; they are different scenarios, not the same one
scaled.

##### Forced GC cycle

**GOMAXPROCS=14 -- forced GC cycle, mean / worst**

| guests | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| no_guests | 2.56 ms / 2.82 ms | 2.95 ms / 3.31 ms | 2.78 ms / 3.19 ms | 2.78 ms / 3.07 ms | 2.74 ms / 2.95 ms | 2.75 ms / 3.02 ms | 2.72 ms / 2.97 ms |
| spinning/body_1 | 340.89 ms / 494.46 ms | 7.59 ms / 9.18 ms | 329.37 ms / 400.74 ms | 342.08 ms / 440.76 ms | 312.12 ms / 400.70 ms | 355.75 ms / 516.70 ms | 337.66 ms / 433.83 ms |
| spinning/body_1k | 347.63 ms / 443.85 ms | 9.25 ms / 18.45 ms | 310.90 ms / 412.51 ms | 348.88 ms / 428.42 ms | 291.83 ms / 382.43 ms | 260.33 ms / 334.73 ms | 249.67 ms / 357.83 ms |
| spinning/body_100k | 327.53 ms / 450.78 ms | 8.59 ms / 11.91 ms | 262.96 ms / 430.13 ms | 255.41 ms / 389.79 ms | 297.10 ms / 413.09 ms | 524.10 ms / 676.07 ms | 1788.82 ms / 2017.20 ms |

**GOMAXPROCS=1 -- forced GC cycle, mean / worst**

| guests | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| no_guests | 2.52 ms / 2.67 ms | 2.54 ms / 2.78 ms | 2.51 ms / 2.64 ms | 2.52 ms / 2.76 ms | 2.48 ms / 2.53 ms | 2.47 ms / 2.53 ms | 2.48 ms / 2.54 ms |
| spinning/body_1 | 1980.75 ms / 2064.80 ms | 2.53 ms / 2.71 ms | 2167.00 ms / 2238.22 ms | 2356.34 ms / 2448.74 ms | 2357.49 ms / 2450.97 ms | 2355.09 ms / 2447.39 ms | 2229.97 ms / 2431.73 ms |
| spinning/body_1k | 1987.99 ms / 2071.74 ms | 2.60 ms / 4.00 ms | 2291.88 ms / 2366.99 ms | 2350.70 ms / 2375.14 ms | 2349.83 ms / 2374.01 ms | 2343.42 ms / 2377.14 ms | 2161.40 ms / 2221.06 ms |
| spinning/body_100k | 2339.90 ms / 4166.77 ms | 2.73 ms / 3.66 ms | 2627.31 ms / 5000.67 ms | 2618.17 ms / 4987.38 ms | 2621.26 ms / 4979.45 ms | 3502.70 ms / 5755.92 ms | 8104.95 ms / 15234.52 ms |

##### Host allocation

**GOMAXPROCS=14 -- host allocation, mean / worst single alloc**

| guests | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| no_guests | 498 ns / 0.10 ms | 502 ns / 95.1 µs | 510 ns / 0.11 ms | 472 ns / 89.8 µs | 472 ns / 91.2 µs | 467 ns / 78.1 µs | 466 ns / 83.9 µs |
| spinning/body_1 | 4995 ns / 50.69 ms | 1020 ns / 6.77 ms | 7028 ns / 51.50 ms | 5004 ns / 46.53 ms | 6148 ns / 60.06 ms | 4700 ns / 55.20 ms | 5808 ns / 50.62 ms |
| spinning/body_1k | 5308 ns / 43.17 ms | 1768 ns / 10.73 ms | 4668 ns / 51.50 ms | 6072 ns / 48.68 ms | 5762 ns / 51.96 ms | 6407 ns / 54.47 ms | 6601 ns / 54.56 ms |
| spinning/body_100k | 5662 ns / 51.20 ms | 1454 ns / 10.29 ms | 6681 ns / 43.38 ms | 9124 ns / 64.90 ms | 12106 ns / 61.24 ms | 22728 ns / 175.58 ms | 58308 ns / 634.43 ms |

**GOMAXPROCS=1 -- host allocation, mean / worst single alloc**

| guests | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| no_guests | 273 ns / 42.1 µs | 278 ns / 54.5 µs | 273 ns / 60.8 µs | 266 ns / 35.1 µs | 268 ns / 38.8 µs | 267 ns / 47.8 µs | 269 ns / 55.5 µs |
| spinning/body_1 | 559 ns / 27.57 ms | 307 ns / 0.23 ms | 565 ns / 30.05 ms | 489 ns / 23.53 ms | 516 ns / 30.07 ms | 482 ns / 23.83 ms | 511 ns / 27.55 ms |
| spinning/body_1k | 540 ns / 27.54 ms | 308 ns / 0.14 ms | 558 ns / 30.05 ms | 575 ns / 30.06 ms | 574 ns / 30.10 ms | 466 ns / 27.65 ms | 476 ns / 26.49 ms |
| spinning/body_100k | 580 ns / 27.57 ms | 351 ns / 1.08 ms | 570 ns / 24.69 ms | 623 ns / 30.96 ms | 667 ns / 34.83 ms | 841 ns / 46.58 ms | 1486 ns / 92.27 ms |

##### What these measure is how long Go work waits for a P

Neither benchmark is really about garbage collection or allocation. Both measure how long a Go-side
operation waits to be *scheduled* while guests are running, and the answer is set by one thing: who
holds the Ps.

A's per-back-edge exit is a Go function call, not a trip through the scheduler, and it does not
release the P. It creates a preemption *point* -- a stack-check prologue that yields only if
`stackguard0` has been set to `stackPreempt` -- and nothing sets that until sysmon retakes the
goroutine after ~10ms. B's 1-of-N exit is the same exit. So under both, a wasm goroutine holds its P
by default and the GC's mark workers and the allocating goroutine wait on sysmon's granularity.
Under D, `entersyscall` hands the P back once at entry and the thread never holds one, so there is
nothing to wait for.

The frequency of the exits is not the mechanism, and the data says so directly: at body_1, exit
frequency spans 4096x from A (every back-edge) to B at N=4096, and the forced GC does not move --
341, 329, 342, 312, 356, 338ms. If frequent exits were generating scheduler pressure, A would be far
the worst; it is indistinguishable.

The numbers that follow from this: at GOMAXPROCS=14 a forced GC goes from 2.6-3.0ms with no guests
to 250-356ms for A and for B at every N, against 7.6-9.3ms for D. Host allocation is 4.7-9.1µs for A
and B against 466-510ns unloaded, 1.0-1.8µs for D, with worst-case single allocations of 43-65ms
against D's 6.8-10.7ms.

At GOMAXPROCS=1 the same comparison is starker, because one spinning guest is enough to own the only
P: A and B take **2.0-2.6 seconds** per forced GC where D takes 2.5-2.7ms against a 2.5ms unloaded
baseline -- D is not measurably affected at all, and everything else is ~1000x its own baseline.

##### B at N=4096 with a long body adds to it

At a 100k-instruction body and N=4096, B's forced GC is 1.79s mean / 2.02s worst at GOMAXPROCS=14,
against 250-300ms at every smaller N; at GOMAXPROCS=1 it is 8.10s / 15.23s. Host allocation at that
setting averages 58.3µs -- 125x its own unloaded 466ns -- with a single `make([]byte, 4096)` stalling
634ms. N=1024 shows the beginning of the same curve (524ms per GC, 22.7µs per alloc).

This is the one place exit frequency matters, and in the opposite direction to the intuition. The
guest reaches a Go call only every `N x body` instructions, so once sysmon does flag it for
preemption it cannot honour the flag until then. The problem is exits being too *rare* to reach a
safepoint, and it stacks on top of the P-holding floor rather than replacing it -- which is why every
N below 1024 sits at the same ~300ms as A, and only 1024 and above pull away.

#### BenchmarkMixedWorkload / BenchmarkGuestCallFrequency

Other benchmarks exist to measure various worst case behavior. This benchmark attempts to measure
a "realistic" scenario under which one might want to enable WithCloseOnContextDone.

Same machine and methodology: seven configurations -- A, D, and B at N = 16, 64, 256, 1024, 4096 --
`-count=6`, medians, all seven interleaved one sample per round. `-benchtime=2000x` for the mixed
workload, `1000x` for the call-frequency sweep. Both benchmarks carry their own with/without
`ensureTermination` split internally, so approach is the only dimension swept here.

Raw output is in `_interrupt_bench/{mixed,callfreq}/<config>.txt`, regenerable with
`_interrupt_bench/run_mixed.sh`; tables from `_interrupt_bench/fmt_mixed.py`.

Unlike the other sweeps there is no GOMAXPROCS=1 leg. Both benchmarks let guests run concurrently,
and a guest inside `entersyscall` under D is not holding a P, so pinning to one P bounds guest
concurrency for A and B but not for D -- it would change what is being compared rather than scale
it. All cores only.

The benchmark keeps 56 requests in flight on 14 Ps. The worker count is 4x GOMAXPROCS, so offered
load stays the same fraction of capacity on any machine. A request is Go CPU and allocation, a guest
call, a 3ms IO wait, a second guest call against linear memory, then more Go allocation -- 500k
guest loop back-edges and ~0.3ms of guest CPU inside a ~3.6ms request. Every request carries a 200ms
deadline, 54x what it nominally takes.

**Mixed workload, 56 concurrent requests on 14 Ps**

| | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| throughput / op (off) | 66.0 µs | 66.0 µs | 66.0 µs | 66.1 µs | 66.0 µs | 66.0 µs | 66.0 µs |
| throughput / op (on) | 615.3 µs | 67.0 µs | 81.1 µs | 67.8 µs | 66.6 µs | 67.6 µs | 67.1 µs |
| p50 / req (off) | 3.60 ms | 3.58 ms | 3.60 ms | 3.60 ms | 3.59 ms | 3.59 ms | 3.59 ms |
| p50 / req (on) | 17.66 ms | 3.66 ms | 4.33 ms | 3.63 ms | 3.55 ms | 3.65 ms | 3.60 ms |
| p99 / req (off) | 4.92 ms | 4.90 ms | 4.94 ms | 4.87 ms | 4.85 ms | 4.93 ms | 4.95 ms |
| p99 / req (on) | 372.71 ms | 4.81 ms | 7.24 ms | 5.48 ms | 5.19 ms | 5.26 ms | 5.24 ms |
| max / req (off) | 5.30 ms | 5.39 ms | 5.38 ms | 5.41 ms | 5.24 ms | 5.60 ms | 5.41 ms |
| max / req (on) | 1055.17 ms | 5.63 ms | 9.38 ms | 6.71 ms | 6.33 ms | 6.17 ms | 6.17 ms |
| timeouts / 2000 (on) | 28 | 0 | 0 | 0 | 0 | 0 | 0 |

##### With the feature off, the run really is under capacity

All seven configurations agree to 0.2% on throughput and 0.6% on p50, which is what identical
generated code should look like.

More importantly, p50 with the feature off is 3.58-3.60ms against a ~3.6ms serial request, so
requests are not queueing and the offered load really is below capacity. That is the precondition
for everything below: this is the only benchmark here that starts under capacity, and the only one
that can show an approach crossing out of it.

##### A crosses into saturation; nothing else does

Throughput 9.3x, p50 4.9x, p99 76x, the worst request 199x -- just over a second -- and **1.4% of
requests blew a deadline with 54x headroom**. That last is a different failure from "everything is
slower": it is an SLO breach on more than one request in a hundred.

Throughput and p50 disagreeing is the tell. If requests had simply got 4.9x slower the two would
move together; the extra factor of two is requests waiting rather than running. The arithmetic is
the per-back-edge cost from `BenchmarkContextDoneOverhead` applied to this request: 300k tight
back-edges at 12.45ns plus 200k mem back-edges at 12.17ns is 6.17ms of added CPU on a request that
otherwise spends ~0.3ms of its 3.6ms doing work. That takes each worker from ~9% busy to ~68% busy,
and 56 workers at 68% is ~38 Ps' worth of demand against 14 -- so a queue forms, and queues are
where tails come from.

An embedder sizing on p50 would see a 4.9x regression. One with an SLO would see the service fall
over.

##### B needs N >= 64 on a workload of this shape

N=16 is the one B setting that shows: 1.23x throughput, 1.20x p50, and p99 up 1.5x, though no
timeouts. The same arithmetic accounts for it -- 500k back-edges at ~1.07ns is 0.54ms added to a
0.3ms request, ~12 Ps of demand against 14, close enough to capacity for a queue to start forming.
From N=64 up it is 1.01-1.03x on throughput and within noise on p50, and N=64 through N=4096 are
indistinguishable from each other.

D is 1.02x on throughput and p50 with no timeouts, which puts it level with B at any N >= 64. On a
workload of this shape there is nothing to choose between them.

##### Per-`Call` cost is the watchdog goroutine, and every approach pays it

`BenchmarkGuestCallFrequency` holds total guest work constant at 512k iterations and varies only
how many `Call` boundaries it is split across. An approach whose overhead is per-iteration is flat
across the sweep; one whose overhead is per-call rises with it.

**Guest call frequency, off / on**

| | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| calls_1 | 22.1 µs / 640.7 µs | 22.8 µs / 23.3 µs | 21.8 µs / 73.7 µs | 22.1 µs / 47.9 µs | 22.0 µs / 39.0 µs | 22.0 µs / 36.3 µs | 22.4 µs / 35.7 µs |
| calls_2 | 21.6 µs / 635.7 µs | 21.8 µs / 23.3 µs | 22.0 µs / 73.5 µs | 21.4 µs / 48.2 µs | 21.5 µs / 38.5 µs | 21.5 µs / 36.2 µs | 21.7 µs / 35.4 µs |
| calls_8 | 21.7 µs / 643.5 µs | 21.7 µs / 24.3 µs | 21.5 µs / 75.4 µs | 21.8 µs / 49.1 µs | 21.7 µs / 40.4 µs | 21.7 µs / 37.6 µs | 21.8 µs / 36.9 µs |
| calls_32 | 22.2 µs / 659.4 µs | 22.0 µs / 30.9 µs | 22.0 µs / 81.5 µs | 21.9 µs / 54.0 µs | 22.4 µs / 45.5 µs | 21.5 µs / 42.9 µs | 21.8 µs / 42.9 µs |
| calls_128 | 23.0 µs / 669.1 µs | 24.1 µs / 55.4 µs | 24.4 µs / 100.5 µs | 22.8 µs / 82.1 µs | 23.1 µs / 71.7 µs | 24.0 µs / 70.5 µs | 23.0 µs / 71.5 µs |

With the feature off, every column is flat across the sweep and every row agrees across approaches,
as it must be -- all seven compile identical code in that configuration.

The `calls_1` row is the per-iteration cost with per-call cost held to one `Call`: against a ~22µs
baseline, D adds 0.5µs, B adds 13.3µs at N=4096 rising to 51.9µs at N=16, and A adds 618.6µs.

**Per extra `Call`, feature on** (calls_128 - calls_1, / 127)

| | A | D | B16 | B64 | B256 | B1024 | B4096 |
|---|---|---|---|---|---|---|---|
| cost per Call | 224 ns | 253 ns | 211 ns | 270 ns | 258 ns | 269 ns | 281 ns |

210-280ns for every approach, with no separation by approach: the six per-round slopes overlap
across the whole table (A 140-279ns, D 233-308ns, B4096 230-335ns), so the spread here is run noise
rather than an approach effect.

That is the watchdog goroutine. `callEngine.call` spawns `CloseModuleOnCanceledOrTimeout`
unconditionally when `ensureTermination` is set (`call_engine.go:357`); it allocates a channel and
starts a goroutine without checking whether `ctx.Done()` is even non-nil, and every approach pays it
identically. It only *looks* like a D or B problem in the ratios -- D goes 23.3 -> 55.4µs across the
sweep, 2.4x, against A's 1.04x -- because A's per-iteration cost is so large that a per-call cost
disappears next to it.

This is also the one cost on the table that no approach here addresses, and the only one that would
still be worth removing after picking any of them: for a `ctx` with no `Done()` channel the
goroutine can never fire and need not be spawned at all.

#### Approach A

Baseline for throughput. For latency it is not a baseline so much as a second data point: see
"Under load, only D stays at the floor" and "What these measure is how long Go work waits for a P"
above. A's per-back-edge Go exit buys a preemption point, not a yield, and the two benchmarks show
that the distinction is most of what matters -- it is 5.3-5.8ms to interrupt even a single guest on
a single P, where D is at the 1ms measurement floor.

#### Approach B

Throughput costs 0.29-0.35ns per back-edge at N>=256, flattening by N=1024; 1024 to 4096 buys
0.015ns. It cannot reach D's 0.04ns at any N, because the counter work it does on every back-edge --
load, increment, store, mask, branch -- does not go away as N grows, only the exit frequency does.
But the latency and GC benchmarks answer the open questions in the negative. Interruption latency is
`N x (guest-chosen loop body time)`. GC cost is two terms rather than one: B pays the same
P-holding floor as A whatever N is -- 310-342ms at N=16 through N=256, against A's 341ms -- and
`N x body` adds on top of that floor once it grows past it, reaching 1.79s per GC at N=4096 with a
100k-instruction body. Lowering N cannot buy back the floor, only remove the second term. No fixed N
is resilient, because resilience would require bounding a factor the guest owns. Using it safely
would mean either capping N low enough to be worthless (N=1 is approach A) or bounding loop body
cost, which wasm does not let you do.

On the realistic mixed workload it needs N >= 64 to disappear: N=16 costs 1.23x throughput and 1.20x
p50 there, and from 64 up it is 1.01-1.03x and indistinguishable from D. So the usable range is
bounded from both ends -- too small and it costs throughput, too large and interruption latency and
GC pauses grow without limit -- and neither bound is a property the embedder controls, since both
scale with the guest's loop body.

N=1 reduces to approach A by construction: a 1-of-1 exit is an unconditional exit. The sweep here
starts at N=16, so this is analytical rather than measured. It is still a useful property -- the
interval subsumes the current behavior rather than replacing it, so B is only ever a question of
what N to pick.

#### Approach C
Skipped. The PR implements changes for the interpreter only, so it is not in a state where the performance-sensitive case can be benchmarked.

#### Approach D

Cheapest per back-edge of any approach and with no N to tune -- 0.04ns on the tight loop against
B's 0.29ns best, and level with B on the mem loop -- and the only one whose behavior does not
depend on guest code shape in any of the benchmarks: interruption latency at or near the 1ms
measurement floor everywhere -- 1.24-1.66ms under load and 0.96-1.02ms on a single P, where A is
14-20ms and 5.3-5.8ms respectively and B reaches 224ms worst case -- GC cycles 3x rather than 90-660x,
host allocation 2-4x rather than 10-125x. It is the only one that never has to be taken off a P by
sysmon before other Go work can run.

On the realistic mixed workload it is 1.02x throughput and p50 with the feature on and takes no
timeouts, which is level with B at any N >= 64 -- and unlike B it gets there without an N to choose.
With the feature off it is free as well.

The entersyscall/exitsyscall pair does not show up as a per-`Call` cost specific to D: on the call
frequency sweep D pays 253ns per extra `Call` against A's 224ns and B's 211-281ns, which is the
watchdog goroutine every approach spawns, with the per-round slopes overlapping across the whole
table.

### Conclusions

#### Recommendation

Either implement approach D if the dependency on runtime internals is acceptable, or implement B
leaving in a tuning parameter for N if not.

D is better on basically every dimension than B, so the only real con is the dependency on runtime internals.

If B is adopted, the results show that there's not a single N that is optimal for all workloads, even measured on a single
machine. Expanding the testing to different architectures/CPU speeds/number of cores would likely show even greater
need to tune N. This is further argument against B - it's going to be a parameter that's very hard for embedders to set
correctly.

#### Future optimizations/questions

- We could skip the watchdog goroutine when ctx.Done() is nil. It costs every approach 210-280ns per Call, and would still allow for enforcing termination by closing the module instance.
- The tested code for Approach D was with using runtime.entersyscall/runtime.exitsyscall only if WithCloseOnContextDone is set. We could also consider doing it unconditionally. Preliminary benchmarks showed a small cost (~3%), but significant improvement in contended behavior when many goroutines were running. If Approach D is adopted it would be worth doing a separate set of benchmarks to further investigate and refine the tradeoffs.