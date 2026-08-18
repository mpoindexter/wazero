"""Format BenchmarkInvocation medians into the tables used in INTERRUPT_DESIGN.md.

Note the GOMAXPROCS suffix ("-14") is present at the default and absent at GOMAXPROCS=1, so it is
stripped only when it is actually a "-<digits>" tail -- benchmark names like fib_for_5 end in
"_<digits>" and must not be touched.
"""
import re, statistics

CFGS = [("A","a"),("D","d"),("B16","b_n16"),("B64","b_n64"),
        ("B256","b_n256"),("B1024","b_n1024"),("B4096","b_n4096")]

def load(procs, cfg):
    out = {}
    for line in open(f"invocation/{procs}/{cfg}.txt"):
        parts = line.split()
        if len(parts) < 4 or not parts[0].startswith("BenchmarkInvocation/compiler/"):
            continue
        if parts[3] != "ns/op":
            continue
        name = re.sub(r"-\d+$", "", parts[0])
        _, _, variant, bench = name.split("/", 3)
        out.setdefault((variant, bench), []).append(float(parts[2]))
    return {k: statistics.median(v) for k, v in out.items()}

def unit(ns):
    if ns < 1e3:  return f"{ns:.1f} ns"
    if ns < 1e6:  return f"{ns/1e3:.2f} µs"
    return f"{ns/1e6:.3f} ms"

for procs, label in (("pdefault","GOMAXPROCS=14"), ("p1","GOMAXPROCS=1")):
    data = {name: load(procs, f) for name, f in CFGS}
    order = [k[1] for k in data["A"] if k[0] == "without_close_on_ctx_done"]
    for variant, vlabel in (("without_close_on_ctx_done","feature off"),
                            ("with_close_on_ctx_done","feature on")):
        print(f"\n**{label}, {vlabel}**\n")
        print("| | " + " | ".join(n for n, _ in CFGS) + " |")
        print("|---|" + "---|"*len(CFGS))
        for bench in order:
            print(f"| {bench} | " + " | ".join(unit(data[n][(variant,bench)]) for n,_ in CFGS) + " |")

print("\n\n=== on/off ratio (cost of enabling the feature) ===")
for procs, label in (("pdefault","GOMAXPROCS=14"), ("p1","GOMAXPROCS=1")):
    data = {name: load(procs, f) for name, f in CFGS}
    order = [k[1] for k in data["A"] if k[0] == "without_close_on_ctx_done"]
    print(f"\n**{label}**\n")
    print("| | " + " | ".join(n for n, _ in CFGS) + " |")
    print("|---|" + "---|"*len(CFGS))
    for bench in order:
        cells = []
        for n, _ in CFGS:
            off = data[n][("without_close_on_ctx_done", bench)]
            on  = data[n][("with_close_on_ctx_done", bench)]
            cells.append(f"{on/off:.2f}x")
        print(f"| {bench} | " + " | ".join(cells) + " |")
