#!/bin/bash
# BenchmarkInvocation across every approach, with and without WithCloseOnContextDone, at
# GOMAXPROCS=1 and unset.
#
# The guest here is TinyGo-compiled code with real loops, so with the feature on the interrupt
# check is compiled into them: this is the same question BenchmarkContextDoneOverhead asks, on
# something less synthetic. The interpreter variants are skipped -- they dominate the wall time and
# no approach touches the interpreter.
#
# Interleaved: one sample per configuration per round, so drift over the run spreads across
# configurations instead of tracking the order they ran in.
#
# Raw output lands in invocation/<procs>/<config>.txt, where <procs> is "p1" or "pdefault"
# and <config> is a, d, or b_n<N>. Regenerate with:
#
#	./_interrupt_bench/run_invocation.sh
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

OUT=invocation
rm -rf "$OUT"; mkdir -p "$OUT/p1" "$OUT/pdefault"

FLAGS=(-skip-interpreter -test.run XXX -test.bench BenchmarkInvocation -test.benchtime 500ms -test.count 1)
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
