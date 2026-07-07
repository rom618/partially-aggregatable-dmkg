#!/usr/bin/env python3
"""Same-curve comparison report.

The main report runs the pairing-free protocols (neji, btsof, kalai2022) on
Jubjub and the aggregatable ones (gurkan, aggregatable2025) on BLS12-381 G1 -
each protocol on the curve its design calls for. That mixes two variables (the
protocol AND the curve) into one measurement. This report removes the curve
variable: it re-runs the pairing-free protocols on the SAME BLS12-381 G1 curve
the aggregatable protocols are forced onto, and plots Jubjub vs BLS side by side.

Inputs:
  report/bench_sweep.csv            (default/Jubjub build)  -> pairing-free on Jubjub
  report/bls/bench_sweep_bls.csv    (--features pf-bls)     -> pairing-free on BLS G1

Outputs:
  report/bls/data/sweep_bycurve.csv
  report/bls/data/curve_tax.csv
  report/bls/graphs/*.png
"""
import csv
import math
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
os.makedirs(os.path.join(HERE, "graphs"), exist_ok=True)

PF = ["neji", "btsof", "kalai2022"]          # pairing-free: run on both curves
AGG = ["gurkan", "aggregatable2025"]         # always BLS (curve is fixed by design)
METRICS = ["deal_ms", "verify_ms", "keygen_ms", "total_bytes"]


def read(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def collapse(path):
    """Sum aggregatable2025's tree+broadcast rows into per-(protocol,n) totals."""
    agg = {}
    for r in read(path):
        key = (r["protocol"], int(r["n"]))
        d = agg.setdefault(key, {"deal_ms": float(r["deal_ms"]),
                                 "verify_ms": float(r["verify_ms"]),
                                 "keygen_ms": float(r["keygen_ms"]),
                                 "total_bytes": 0})
        d["total_bytes"] += int(r["bytes"])
    return agg


jj = collapse(os.path.join(ROOT, "report", "bench_sweep.csv"))
bls = collapse(os.path.join(HERE, "bench_sweep_bls.csv"))

# ---- tidy: one row per (protocol, curve, n) --------------------------------
rows = []
for (p, n), d in sorted(jj.items()):
    if p in PF:                       # Jubjub numbers only meaningful for pairing-free
        rows.append(("Jubjub", p, n, d))
for (p, n), d in sorted(bls.items()):
    rows.append(("BLS12-381", p, n, d))

with open(os.path.join(HERE, "data", "sweep_bycurve.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["curve", "protocol", "n"] + METRICS)
    for curve, p, n, d in rows:
        w.writerow([curve, p, n] + [d[m] for m in METRICS])

# ---- curve tax: BLS / Jubjub ratio per pairing-free protocol ---------------
with open(os.path.join(HERE, "data", "curve_tax.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["protocol", "n"] + [m + "_x" for m in METRICS])
    for p in PF:
        for n in sorted({n for (pp, n) in jj if pp == p}):
            j, b = jj[(p, n)], bls[(p, n)]
            w.writerow([p, n] + [round(b[m] / j[m], 2) for m in METRICS])

# ---- Fig A: per pairing-free protocol, Jubjub vs BLS on 3 metrics -----------
STYLE = {"Jubjub": ("#2ca02c", "o", "-"), "BLS12-381": ("#d62728", "s", "--")}
plot_metrics = [("verify_ms", "verify (ms)"),
                ("keygen_ms", "keygen (ms)"),
                ("total_bytes", "total bytes")]
for p in PF:
    fig, axs = plt.subplots(1, 3, figsize=(15, 4.5))
    for ax, (m, ylab) in zip(axs, plot_metrics):
        for curve in ("Jubjub", "BLS12-381"):
            pts = sorted((n, d[m]) for (c, pp, n, d) in rows
                         if pp == p and c == curve)
            if not pts:
                continue
            c, mk, ls = STYLE[curve]
            ax.plot([n for n, _ in pts], [y for _, y in pts],
                    color=c, marker=mk, ls=ls, label=curve)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("n")
        ax.set_ylabel(ylab)
        ax.set_title(m)
        ax.grid(True, which="both", ls=":", alpha=0.5)
        ax.legend(fontsize=8)
    fig.suptitle(f"{p}: same protocol, Jubjub vs BLS12-381 G1", y=1.02)
    fig.tight_layout()
    fig.savefig(os.path.join(HERE, "graphs", f"curve_{p}.png"),
                dpi=130, bbox_inches="tight")
    plt.close(fig)

# ---- Fig B: the "curve tax" - BLS/Jubjub slowdown, averaged over n ----------
fig, ax = plt.subplots(figsize=(8, 5))
labels = ["verify", "keygen", "bytes"]
tax_metrics = ["verify_ms", "keygen_ms", "total_bytes"]
x = range(len(PF))
w = 0.25
for i, (m, lab) in enumerate(zip(tax_metrics, labels)):
    vals = []
    for p in PF:
        ratios = [bls[(p, n)][m] / jj[(p, n)][m]
                  for n in sorted({n for (pp, n) in jj if pp == p})]
        vals.append(sum(ratios) / len(ratios))
    ax.bar([xi + (i - 1) * w for xi in x], vals, width=w, label=lab)
ax.axhline(1, color="gray", ls=":", lw=1)
ax.text(len(PF) - 0.5, 1.03, "Jubjub baseline", fontsize=8, color="gray")
ax.set_xticks(list(x))
ax.set_xticklabels(PF)
ax.set_ylabel("BLS12-381 / Jubjub  (x slower / bigger)")
ax.set_title("Curve tax: cost of forcing the pairing-free protocols onto BLS12-381 G1")
ax.legend(fontsize=9)
ax.grid(True, axis="y", ls=":", alpha=0.5)
fig.tight_layout()
fig.savefig(os.path.join(HERE, "graphs", "curve_tax.png"),
            dpi=130, bbox_inches="tight")
plt.close(fig)

# ---- Fig C: protocol vs curve, all five together on verify (log-log) -------
# On ONE identical curve (BLS), the *protocol* differences are what remain.
fig, ax = plt.subplots(figsize=(8, 5))
COL = {"neji": "#1f77b4", "gurkan": "#d62728", "btsof": "#2ca02c",
       "kalai2022": "#9467bd", "aggregatable2025": "#ff7f0e"}
for p in PF + AGG:
    pts = sorted((n, d["verify_ms"]) for (c, pp, n, d) in rows
                 if pp == p and c == "BLS12-381")
    ax.plot([n for n, _ in pts], [y for _, y in pts],
            color=COL[p], marker="o", label=p)
ax.set_xscale("log", base=2)
ax.set_yscale("log")
ax.set_xlabel("n")
ax.set_ylabel("verify (ms)")
ax.set_title("All five protocols on the SAME curve (BLS12-381 G1): verify vs n")
ax.grid(True, which="both", ls=":", alpha=0.5)
ax.legend(fontsize=8, bbox_to_anchor=(1.01, 1), loc="upper left")
fig.tight_layout()
fig.savefig(os.path.join(HERE, "graphs", "same_curve_verify.png"),
            dpi=130, bbox_inches="tight")
plt.close(fig)

print("BLS comparison graphs + data written under report/bls/")
