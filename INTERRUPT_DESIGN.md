# Interruption approach investigation

## Background

There are two key points to improving close on context done:
- Crossing the Go barrier from native code is relatively expensive
- Without coordinating with the Go runtime, executing native code can prevent Go from executing concurrently

Point 2 means that we MUST coordinate with Go in some way to ensure that the code that would close the module (another goroutine) executes. 
Point 1 means that we should minimize the number of times we cross from native to Go if we want to perform well.

## Approaches

### Current approach (Approach A)

In the current approach, every loop iteration calls into a Go function to check if the module is terminated (https://github.com/wazero/wazero/blob/main/internal/engine/wazevo/frontend/lower.go#L1368)
If the module has been closed, a panic is raised, aborting execution of the Go function. This fulfills point 2 by returning to the Go runtime at each loop iteration, allowing concurrent Go code a change to execute.

Pros:
- Simple
- Obviously correct

Cons:
- Expensive, because it pays the Go barrier crossing cost every loop iteration, slowing code down by 10-20x

### Interrupt check on an interval (Approach B)

The approach proposed by https://github.com/wazero/wazero/pull/2482

Basically, add a config knob to check for interruption only every N loop iterations

A variant was proposed in https://github.com/wazero/wazero/pull/2525 where the check is changed to a hybrid:
A flag is exposed to native code that it can check each loop iteration, and if true abort. This is not sufficient
in and of itself as the Go code responsible for setting the flag is not guaranteed to run without coordination with
the Go runtime, so a 1-every-N-loops exit is still needed.

Open questions:
- is there a setting that can be picked that removes the need to tune N for the 1-of-N exit to Go? (#2482 proposed making this configurable, #2525 hardcoded N)
- what factors would influence N? Off the top of my head, number of instructions in the loop, GOMAXPROCS, goroutine usage pattern, number of CPUs all seem like they would influence N
- is there an N that is resilient to poorly behaving guest code? (i.e. extremely long loop bodies, either intentionally or by accident)

Pros:
- Reduces the overhead proportional to N

Cons:
- Need to determine a correct value for N, either in the embedder, or in wazero itself
- If embedder is responsible for setting N, needs new API

### Fuel API (Approach C)

Proposed by https://github.com/wazero/wazero/pull/2500

Interruption would be controlled by Fuel, with a trap raised whenever fuel was exhausted

Pros:
- Aligns with how other engines expose this concept
- Flexible
- Resilient to guest code shape: fuel is proportional to instructions executed, so loop structure in guest code does not matter

Cons:
- Only implemented in interpreter, unclear how to implement in compiler
- Needs new API

### Runtime coordination (Approach D)

Proposed by https://github.com/mpoindexter/wazero/pull/1/changes

Instead of trying to determine when we should exit to Go, instead coordinate with the scheduler to tell it we're executing native code using runtime.entersyscall/runtime.exitsyscall.
The Go scheduler is then responsible for ensuring that other Go code is allowed to run concurrently when the current thread is executing native code.

Pros:
- No new API
- Resilient to guest code shape
- Ensures that Go runtime has clear visibility into what's happening on this thread to make globally good decisions

Cons:
- As proposed, relies on accessing Go scheduler internals via go:linkname directive. Could probably utilize a thin CGO shim to move this into an approach that doesn't rely on internals, but would break `CGO_ENABLED=0` builds.
- Increases the overhead of all native->Go transitions (although this is reduced significantly as of Go 1.26 due to https://go.dev/doc/go1.26#faster-cgo-calls)


## Benchmarks

Two concerns are relevant to assessing the performance of any of these changes:
- Benchmark of existing code performance (i.e. how much does the change impact performance with ensure termination disabled)
- Benchmark of performance change when ensure termination is enabled

To assess this three sets of benchmarks are useful:
- BenchmarkContextDoneOverhead (new). Measures the impact to a set of synthetic code with and without ensure termination
- BenchmarkInvocation (existing). Measures impact to invocations with ensure termination disabled.
- Libsodium benchmark (github.com/tetratelabs/wazero/internal/integration_test/libsodium - existing). Measures impact on a real world codebase with ensure termination disabled.

Methodology:
Run each of the three benchmarks above with the changes from each approach multiple times, and use https://pkg.go.dev/golang.org/x/perf/cmd/benchstat to measure change in behavior.

### Results

#### Approach A

#### Approach B

#### Approach C
Skipped - as the PR only implements changes for the interpreter, not in a state where benchmarks can be run for the performance sensitive case.

#### Approach D