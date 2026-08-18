"""Format the mixed-workload benchmarks into the tables used in INTERRUPT_DESIGN.md.

BenchmarkMixedWorkload reports sec/op (throughput: wall time per request with all workers running)
plus p50/p99/max request latency and a timeout count. BenchmarkGuestCallFrequency reports only
sec/op, once per (call count, feature on/off). Both carry the on/off split in the sub-benchmark
name, so unlike the other sweeps there is nothing to select beyond which benchmark to print.

All-cores only -- see the header of run_mixed.sh for why there is no GOMAXPROCS=1 leg.
"""
import re, statistics, sys

CFGS = [("A", "a"), ("D", "d"), ("B16", "b_n16"), ("B64", "b_n64"),
        ("B256", "b_n256"), ("B1024", "b_n1024"), ("B4096", "b_n4096")]
OFF, ON = "without_close_on_ctx_done", "with_close_on_ctx_done"


def load(root, cfg):
    """(sub-benchmark name, metric) -> median across rounds."""
    out = {}
    for line in open(f"{root}/{cfg}.txt"):
        parts = line.split()
        if not parts or not parts[0].startswith("Benchmark"):
            continue
        name = re.sub(r"-\d+$", "", parts[0]).split("/", 1)[1]
        # parts[1] is the iteration count; the rest are value/unit pairs.
        for i in range(2, len(parts) - 1, 2):
            out.setdefault((name, parts[i + 1]), []).append(float(parts[i]))
    return {k: statistics.median(v) for k, v in out.items()}


def t(ns):
    if ns >= 1e6:
        return f"{ns/1e6:.2f} ms"
    if ns >= 1e3:
        return f"{ns/1e3:.1f} µs"
    return f"{ns:.0f} ns"


def header():
    print("| | " + " | ".join(n for n, _ in CFGS) + " |")
    print("|---|" + "---|" * len(CFGS))


def mixed():
    data = {n: load("mixed", f) for n, f in CFGS}
    print("\n**Mixed workload, 56 concurrent requests on 14 Ps**\n")
    header()
    for lbl, metric in (("throughput / op", "ns/op"), ("p50 / req", "p50-ns/req"),
                        ("p99 / req", "p99-ns/req"), ("max / req", "max-ns/req")):
        for split, tag in ((OFF, "off"), (ON, "on")):
            cells = [t(data[n][(split, metric)]) for n, _ in CFGS]
            print(f"| {lbl} ({tag}) | " + " | ".join(cells) + " |")
    cells = [f"{data[n][(ON, 'timeouts')]:.0f}" for n, _ in CFGS]
    print("| timeouts / 2000 (on) | " + " | ".join(cells) + " |")


def freq():
    data = {n: load("callfreq", f) for n, f in CFGS}
    calls = sorted({k[0].split("/")[0] for k in data["A"]},
                   key=lambda c: int(c.split("_")[1]))
    print("\n**Guest call frequency, off / on**\n")
    header()
    for c in calls:
        cells = [f"{t(data[n][(c+'/off','ns/op')])} / {t(data[n][(c+'/on','ns/op')])}"
                 for n, _ in CFGS]
        print(f"| {c} | " + " | ".join(cells) + " |")
    # Per-call cost with the feature on: slope from calls_1 to calls_128 over the 127 extra calls.
    print("\n**Per extra `Call`, feature on** (calls_128 - calls_1, / 127)\n")
    header()
    cells = [t((data[n][("calls_128/on", "ns/op")] - data[n][("calls_1/on", "ns/op")]) / 127)
             for n, _ in CFGS]
    print("| cost per Call | " + " | ".join(cells) + " |")


(mixed if sys.argv[1] == "mixed" else freq)()
