"""Format the GC-pressure benchmarks into the tables used in INTERRUPT_DESIGN.md.

gcpause reports sec/op (a forced runtime.GC cycle) plus max-ns/gc; hostprogress reports sec/op (one
allocation on an ordinary Go goroutine) plus max-ns/alloc. The GOMAXPROCS suffix is present at the
default and absent at GOMAXPROCS=1.
"""
import re, statistics, sys

CFGS = [("A","a"),("D","d"),("B16","b_n16"),("B64","b_n64"),
        ("B256","b_n256"),("B1024","b_n1024"),("B4096","b_n4096")]

def load(root, procs, cfg, extra):
    out = {}
    for line in open(f"{root}/{procs}/{cfg}.txt"):
        parts = line.split()
        if not parts or not parts[0].startswith("Benchmark"):
            continue
        name = re.sub(r"-\d+$", "", parts[0]).split("/", 1)[1]
        vals = {"sec/op": float(parts[2])}
        for i, tok in enumerate(parts):
            if tok == extra:
                vals[extra] = float(parts[i-1])
        for k, v in vals.items():
            out.setdefault((name, k), []).append(v)
    return {k: statistics.median(v) for k, v in out.items()}

def ms(ns):
    return f"{ns/1e6:.2f} ms" if ns >= 1e5 else (f"{ns/1e3:.1f} µs" if ns >= 1e3 else f"{ns:.0f} ns")

def bodykey(b):
    if b == "no_guests": return -1
    m = re.search(r"body_(\d+)(k?)$", b)
    return int(m.group(1)) * (1000 if m.group(2) else 1) if m else 0

def table(root, extra, procs, label, fmt_mean):
    data = {n: load(root, procs, f, extra) for n, f in CFGS}
    benches = sorted({k[0] for k in data["A"]}, key=bodykey)
    print(f"\n**{label}**\n")
    print("| guests | " + " | ".join(n for n, _ in CFGS) + " |")
    print("|---|" + "---|"*len(CFGS))
    for b in benches:
        cells = [f"{fmt_mean(data[n][(b,'sec/op')])} / {ms(data[n][(b,extra)])}" for n, _ in CFGS]
        print(f"| {b} | " + " | ".join(cells) + " |")

which = sys.argv[1]
if which == "pause":
    for procs, lbl in (("pdefault","GOMAXPROCS=14"), ("p1","GOMAXPROCS=1")):
        table("gcpause", "max-ns/gc", procs, f"{lbl} -- forced GC cycle, mean / worst", ms)
else:
    for procs, lbl in (("pdefault","GOMAXPROCS=14"), ("p1","GOMAXPROCS=1")):
        table("hostprogress", "max-ns/alloc", procs,
              f"{lbl} -- host allocation, mean / worst single alloc",
              lambda ns: f"{ns:.0f} ns")
