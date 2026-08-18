#!/bin/bash
# BenchmarkMixedWorkload and BenchmarkGuestCallFrequency across every approach, on all cores.
#
# Unlike the other sweeps this one does not have a GOMAXPROCS=1 leg. Both benchmarks size their
# worker pool at 4x GOMAXPROCS and both let guests run concurrently, so pinning to a single P
# changes what is being compared rather than scaling it -- under D a guest inside entersyscall is
# not holding a P at all, so GOMAXPROCS=1 does not bound guest concurrency for D the way it does
# for A and B. All cores only.
#
# Both benchmarks carry their own with/without ensureTermination split internally, so approach is
# the only dimension varied here.
#
# Benchtimes differ: a MixedWorkload op is a whole ~3.7ms request, a GuestCallFrequency op is
# 512k guest iterations split across a varying number of Call boundaries.
#
# Interleaved: one sample per configuration per round, so drift over the run spreads across
# configurations instead of tracking the order they ran in.
#
# Raw output lands in mixed/<config>.txt and callfreq/<config>.txt, where <config> is a, d, or
# b_n<N>. Regenerate with:
#
#	./_interrupt_bench/run_mixed.sh
#
set -uo pipefail
cd "$(dirname "$0")"
ROOT=../internal/integration_test/bench
BIN=$(mktemp -d)
trap 'rm -rf "$BIN"' EXIT

echo "building..."
go test -c -o "$BIN/a.test" "$ROOT" || exit 1
go test -c -tags efficient_interrupt_approach_b -o "$BIN/b.test" "$ROOT" || exit 1
go test -c -tags efficient_interrupt_approach_d -o "$BIN/d.test" "$ROOT" || exit 1

rm -rf mixed callfreq
mkdir -p mixed callfreq

MIXED=(-test.run XXX -test.bench BenchmarkMixedWorkload -test.benchtime 2000x -test.count 1)
FREQ=(-test.run XXX -test.bench BenchmarkGuestCallFrequency -test.benchtime 1000x -test.count 1)
INTERVALS=(16 64 256 1024 4096)
ROUNDS=6

sample() { # sample <config> <binary> <env...>
  local cfg=$1 bin=$2; shift 2
  env "$@" "$BIN/$bin" "${MIXED[@]}" >> "mixed/$cfg.txt"
  env "$@" "$BIN/$bin" "${FREQ[@]}"  >> "callfreq/$cfg.txt"
}

for r in $(seq 1 $ROUNDS); do
  echo "round $r/$ROUNDS"
  sample a a.test WAZERO_UNUSED=1
  sample d d.test WAZERO_UNUSED=1
  for n in "${INTERVALS[@]}"; do
    sample "b_n$n" b.test "WAZERO_INTERRUPT_CHECK_INTERVAL=$n"
  done
done
echo ALL_DONE
