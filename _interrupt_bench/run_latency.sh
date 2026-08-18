#!/bin/bash
# BenchmarkInterruptLatency across every approach, at GOMAXPROCS=1 and unset.
#
# This benchmark always enables WithCloseOnContextDone -- interruption latency with the feature off
# is not a quantity, since the call never stops -- so there is no with/without split here.
#
# Its loaded variants need more than one P, so at GOMAXPROCS=1 only the "alone" variant runs.
#
# Interleaved: one sample per configuration per round, so drift over the run spreads across
# configurations instead of tracking the order they ran in.
#
# Raw output lands in latency/<procs>/<config>.txt, where <procs> is "p1" or "pdefault"
# and <config> is a, d, or b_n<N>. Regenerate with:
#
#	./_interrupt_bench/run_latency.sh
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

OUT=latency
rm -rf "$OUT"; mkdir -p "$OUT/p1" "$OUT/pdefault"

FLAGS=(-test.run XXX -test.bench BenchmarkInterruptLatency -test.benchtime 30x -test.count 1)
INTERVALS=(16 64 256 1024 4096)
ROUNDS=6

sample() { # sample <outdir> <config> <binary> <env...>
  local dir=$1 cfg=$2 bin=$3; shift 3
  env "$@" "$BIN/$bin" "${FLAGS[@]}" >> "$OUT/$dir/$cfg.txt"
}

for r in $(seq 1 $ROUNDS); do
  echo "round $r/$ROUNDS"
  for procs in default 1; do
    if [ "$procs" = 1 ]; then dir=p1; G=(GOMAXPROCS=1); else dir=pdefault; G=(WAZERO_UNUSED=1); fi
    sample "$dir" a a.test "${G[@]}"
    sample "$dir" d d.test "${G[@]}"
    for n in "${INTERVALS[@]}"; do
      sample "$dir" "b_n$n" b.test "${G[@]}" "WAZERO_INTERRUPT_CHECK_INTERVAL=$n"
    done
  done
done
echo ALL_DONE
