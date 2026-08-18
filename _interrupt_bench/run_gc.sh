#!/bin/bash
# BenchmarkGCPauseWithSpinningGuests and BenchmarkHostProgressWhileSpinning across every approach,
# at GOMAXPROCS=1 and unset.
#
# Both always enable WithCloseOnContextDone: they measure what a spinning guest costs the rest of
# the Go process, which is only a question when the guest can be interrupted at all. Both size their
# spinner pool from GOMAXPROCS, so GOMAXPROCS=1 means one spinning guest.
#
# The two want different benchtimes -- a forced GC is milliseconds, an allocation is nanoseconds --
# so each configuration is sampled once for each in every round.
#
# Interleaved: one sample per configuration per round, so drift over the run spreads across
# configurations instead of tracking the order they ran in.
#
# Raw output lands in gcpause/<procs>/<config>.txt and hostprogress/<procs>/<config>.txt, where
# <procs> is "p1" or "pdefault" and <config> is a, d, or b_n<N>. Regenerate with:
#
#	./_interrupt_bench/run_gc.sh
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

rm -rf gcpause hostprogress
mkdir -p gcpause/p1 gcpause/pdefault hostprogress/p1 hostprogress/pdefault

PAUSE=(-test.run XXX -test.bench BenchmarkGCPauseWithSpinningGuests -test.benchtime 10x -test.count 1)
PROG=(-test.run XXX -test.bench BenchmarkHostProgressWhileSpinning -test.benchtime 200000x -test.count 1)
INTERVALS=(16 64 256 1024 4096)
ROUNDS=6

sample() { # sample <outdir> <config> <binary> <env...>
  local dir=$1 cfg=$2 bin=$3; shift 3
  env "$@" "$BIN/$bin" "${PAUSE[@]}" >> "gcpause/$dir/$cfg.txt"
  env "$@" "$BIN/$bin" "${PROG[@]}"  >> "hostprogress/$dir/$cfg.txt"
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
