"""Format BenchmarkInterruptLatency medians into the tables used in INTERRUPT_DESIGN.md.

Reports ns/interrupt (mean over the round's samples) and max-ns/interrupt (worst seen), which the
benchmark emits as custom metrics; sec/op is dominated by the fixed pre-deadline budget and is not
used. The GOMAXPROCS suffix is present at the default and absent at GOMAXPROCS=1.
"""
import re, statistics

CFGS = [("A","a"),("D","d"),("B16","b_n16"),("B64","b_n64"),
        ("B256","b_n256"),("B1024","b_n1024"),("B4096","b_n4096")]

def load(procs, cfg):
    out = {}
    for line in open(f"latency/{procs}/{cfg}.txt"):
        parts = line.split()
        if not parts or not parts[0].startswith("BenchmarkInterruptLatency/"):
            continue
        name = re.sub(r"-\d+$", "", parts[0]).split("/", 1)[1]
        vals = {}
        for i, tok in enumerate(parts):
            if tok in ("ns/interrupt", "max-ns/interrupt"):
                vals[tok] = float(parts[i-1])
        for k, v in vals.items():
            out.setdefault((name, k), []).append(v)
    return {k: statistics.median(v) for k, v in out.items()}

def unit(ns):
    if ns < 1e3:  return f"{ns:.0f} ns"
    if ns < 1e6:  return f"{ns/1e3:.1f} µs"
    return f"{ns/1e6:.2f} ms"

for procs, label in (("pdefault","GOMAXPROCS=14"), ("p1","GOMAXPROCS=1")):
    data = {name: load(procs, f) for name, f in CFGS}
    def bodysize(b):
        m = re.search(r"body_(\d+)(k?)$", b)
        return int(m.group(1)) * (1000 if m.group(2) else 1) if m else 0
    order = {"alone": 0, "one_of": 1, "all_of": 2}
    benches = sorted({k[0] for k in data["A"]},
                     key=lambda b: (order.get(b.split("/")[0].split("_1")[0], 9), bodysize(b)))
    print(f"\n**{label}** -- mean / worst, per interruption\n")
    print("| variant, loop body | " + " | ".join(n for n, _ in CFGS) + " |")
    print("|---|" + "---|"*len(CFGS))
    for b in benches:
        cells = []
        for n, _ in CFGS:
            m = data[n].get((b, "ns/interrupt"))
            w = data[n].get((b, "max-ns/interrupt"))
            cells.append(f"{unit(m)} / {unit(w)}" if m is not None else "-")
        print(f"| {b} | " + " | ".join(cells) + " |")
