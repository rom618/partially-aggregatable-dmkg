#!/usr/bin/env python3
import csv
import math
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

matplotlib.rcParams["axes.unicode_minus"] = False

HERE = os.path.dirname(os.path.abspath(__file__))
G = os.path.join(HERE, "graphs")
BG = os.path.join(HERE, "bls", "graphs")
D = os.path.join(HERE, "data")
BD = os.path.join(HERE, "bls", "data")
os.makedirs(G, exist_ok=True)
os.makedirs(BG, exist_ok=True)

SINGLE = ["neji", "gurkan"]
MULTI = ["btsof", "kalai2022", "aggregatable2025"]
PF = ["neji", "btsof", "kalai2022"]
AGG = ["gurkan", "aggregatable2025"]

COL = {"neji": "#1f77b4", "gurkan": "#d62728", "btsof": "#2ca02c",
       "kalai2022": "#9467bd", "aggregatable2025": "#ff7f0e"}
MK = {"neji": "o", "gurkan": "s", "btsof": "^", "kalai2022": "D",
      "aggregatable2025": "v"}
NS = [8, 16, 32, 64]
AUDIT = []


def read(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def logx(ax):
    ax.set_xscale("log", base=2)
    ax.set_xticks(NS)
    ax.set_xticklabels([str(n) for n in NS])
    ax.set_xlabel("n (participants)")


def series_n(rows, protocol, col):
    pts = sorted((int(r["n"]), float(r[col])) for r in rows
                 if r["protocol"] == protocol)
    return [n for n, _ in pts], [y for _, y in pts]


sweep_n = read(os.path.join(D, "sweep_n.csv"))
bycurve = read(os.path.join(BD, "sweep_bycurve.csv"))


# ---------------------------------------------------------------- A1 messages
def a1_messages():
    fig, axs = plt.subplots(1, 2, figsize=(13, 5))
    for ax, group, title in ((axs[0], SINGLE, "single-secret"),
                             (axs[1], MULTI, "multi-secret")):
        for p in group:
            x, y = series_n(sweep_n, p, "total_messages")
            ax.plot(x, y, color=COL[p], marker=MK[p], label=p)
            AUDIT.append(("A1_messages_vs_n [%s]" % title,
                          "data/sweep_n.csv", "%s: total_messages vs n" % p))
        logx(ax)
        ax.set_yscale("log")
        ax.set_ylabel("point-to-point messages")
        ax.set_title("Messages vs n (%s)" % title)
        ax.grid(True, which="both", ls=":", alpha=0.5)
        ax.legend()
    fig.suptitle("Communication volume in message count (natural curve)")
    fig.tight_layout()
    fig.savefig(os.path.join(G, "A1_messages_vs_n.png"), dpi=130,
                bbox_inches="tight")
    plt.close(fig)


# ------------------------------------------------------------------ A1 rounds
def rounds_for(p, n):
    log = math.ceil(math.log2(n))
    if p == "gurkan":
        return log
    if p == "aggregatable2025":
        return log + 1
    return 1


def a1_rounds():
    fig, axs = plt.subplots(1, 2, figsize=(13, 5))
    for ax, group, title in ((axs[0], SINGLE, "single-secret"),
                             (axs[1], MULTI, "multi-secret")):
        for p in group:
            y = [rounds_for(p, n) for n in NS]
            ax.plot(NS, y, color=COL[p], marker=MK[p], label=p)
            AUDIT.append(("A1_rounds_vs_n [%s]" % title, "derived (network model)",
                          "%s: rounds vs n (broadcast=1, tree=ceil(log2 n))" % p))
        logx(ax)
        ax.set_ylabel("sequential latency rounds")
        ax.set_title("Rounds vs n (%s)" % title)
        ax.grid(True, which="both", ls=":", alpha=0.5)
        ax.legend()
    fig.suptitle("Communication rounds (broadcast = 1, tree gossip = ceil(log2 n))")
    fig.tight_layout()
    fig.savefig(os.path.join(G, "A1_rounds_vs_n.png"), dpi=130,
                bbox_inches="tight")
    plt.close(fig)


# ----------------------------------------------- A2 multi-secret comms scaling
def bycurve_series(curve, protocol, col):
    pts = sorted((int(r["n"]), float(r[col])) for r in bycurve
                 if r["protocol"] == protocol and r["curve"] == curve)
    return [n for n, _ in pts], [y for _, y in pts]


def a2_comms(curve_label, curve_key, out, dirpath, tag):
    fig, axs = plt.subplots(1, 2, figsize=(13, 5))
    for p in MULTI:
        if curve_key is None:
            x, y = series_n(sweep_n, p, "total_bytes")
            src = "data/sweep_n.csv"
        else:
            x, y = bycurve_series(curve_key, p, "total_bytes")
            src = "bls/data/sweep_bycurve.csv"
        if x:
            axs[0].plot(x, y, color=COL[p], marker=MK[p], label=p)
            AUDIT.append((out + " [bytes]", src,
                          "%s: total_bytes vs n (%s)" % (p, curve_label)))
    for p in MULTI:
        x, y = series_n(sweep_n, p, "total_messages")
        axs[1].plot(x, y, color=COL[p], marker=MK[p], label=p)
        AUDIT.append((out + " [messages]", "data/sweep_n.csv",
                      "%s: total_messages vs n" % p))
    for ax, ylab, t in ((axs[0], "transcript bytes", "bytes"),
                        (axs[1], "point-to-point messages", "messages")):
        logx(ax)
        ax.set_yscale("log")
        ax.set_ylabel(ylab)
        ax.set_title("Multi-secret %s vs n" % t)
        ax.grid(True, which="both", ls=":", alpha=0.5)
        ax.legend()
    fig.suptitle("Multi-secret communication scaling (%s)" % tag)
    fig.tight_layout()
    fig.savefig(os.path.join(dirpath, out), dpi=130, bbox_inches="tight")
    plt.close(fig)


# --------------------------------------------- A3 same-curve protocol-only cost
def a3_same_curve():
    fig, axs = plt.subplots(1, 3, figsize=(16, 5.5))
    plan = [("deal_ms", "deal (ms)"), ("verify_ms", "verify (ms)"),
            ("keygen_ms", "keygen (ms)")]
    for ax, (m, ylab) in zip(axs, plan):
        for p in PF + AGG:
            x, y = bycurve_series("BLS12-381", p, m)
            if x:
                ax.plot(x, y, color=COL[p], marker=MK[p], label=p)
                AUDIT.append(("A3_same_curve_costs [%s]" % m,
                              "bls/data/sweep_bycurve.csv",
                              "%s: %s vs n (BLS12-381)" % (p, m)))
        logx(ax)
        ax.set_yscale("log")
        ax.set_ylabel(ylab)
        ax.set_title(m)
        ax.grid(True, which="both", ls=":", alpha=0.5)
        ax.legend(fontsize=8)
    fig.suptitle("All five protocols on the SAME curve (BLS12-381 G1): protocol-only cost")
    fig.tight_layout()
    fig.savefig(os.path.join(BG, "A3_same_curve_costs.png"), dpi=130,
                bbox_inches="tight")
    plt.close(fig)


# ------------------------------------------------------- A4 multi-secret premium
def premium(numer, denom, rows, curve, getter):
    out = {}
    for m in ("deal_ms", "verify_ms", "keygen_ms", "total_bytes"):
        vals = []
        for n in NS:
            a = getter(rows, numer, n, m, curve)
            b = getter(rows, denom, n, m, curve)
            vals.append(a / b if (a and b) else float("nan"))
        out[m] = vals
    return out


def get_sweep_n(rows, p, n, m, curve):
    for r in rows:
        if r["protocol"] == p and int(r["n"]) == n:
            return float(r[m])
    return None


def get_bycurve(rows, p, n, m, curve):
    for r in rows:
        if r["protocol"] == p and int(r["n"]) == n and r["curve"] == curve:
            return float(r[m])
    return None


def a4_premium(pairs, rows, curve, getter, out, tag, src):
    labels = {"deal_ms": "deal", "verify_ms": "verify",
              "keygen_ms": "keygen", "total_bytes": "bytes"}
    fig, axs = plt.subplots(2, 2, figsize=(12, 9))
    axs = axs.ravel()
    for ax, m in zip(axs, ["deal_ms", "verify_ms", "keygen_ms", "total_bytes"]):
        for numer, denom, color in pairs:
            r = premium(numer, denom, rows, curve, getter)
            lab = "%s / %s" % (numer, denom)
            ax.plot(NS, r[m], color=color, marker="o", label=lab)
            AUDIT.append((out + " [%s]" % labels[m], src,
                          "%s divided by %s, %s vs n" % (numer, denom, m)))
        logx(ax)
        ax.axhline(1, color="gray", ls=":", lw=1)
        ax.set_ylabel("x more than single-secret")
        ax.set_title(labels[m])
        ax.grid(True, which="both", ls=":", alpha=0.5)
        ax.legend(fontsize=8)
    fig.suptitle("Multi-secret premium over single-secret same-family analogue (%s)" % tag)
    fig.tight_layout()
    fig.savefig(os.path.join(G, out), dpi=130, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------- B1 layer split bars
def b1_layer_split():
    rows = read(os.path.join(D, "agg_layer_split.csv"))
    rows.sort(key=lambda r: int(r["n"]))
    ns = [int(r["n"]) for r in rows]
    z_b = [int(r["z_bytes"]) for r in rows]
    xy_b = [int(r["xy_bytes"]) for r in rows]
    z_m = [int(r["z_messages"]) for r in rows]
    xy_m = [int(r["xy_messages"]) for r in rows]
    x = range(len(ns))
    fig, axs = plt.subplots(1, 2, figsize=(13, 5))
    axs[0].bar(x, z_b, color="#4c72b0", label="z-layer (SCRAPE tree gossip)")
    axs[0].bar(x, xy_b, bottom=z_b, color="#dd8452",
               label="xy-layer (Franklin-Yung broadcast)")
    axs[0].set_ylabel("transcript bytes")
    axs[0].set_title("Bytes by layer")
    axs[1].bar(x, z_m, color="#4c72b0", label="z-layer (SCRAPE tree gossip)")
    axs[1].bar(x, xy_m, bottom=z_m, color="#dd8452",
               label="xy-layer (Franklin-Yung broadcast)")
    axs[1].set_ylabel("point-to-point messages")
    axs[1].set_title("Messages by layer")
    for ax in axs:
        ax.set_yscale("log")
        ax.set_xticks(list(x))
        ax.set_xticklabels([str(n) for n in ns])
        ax.set_xlabel("n (participants)")
        ax.grid(True, axis="y", which="both", ls=":", alpha=0.5)
        ax.legend()
    AUDIT.append(("B1_layer_split [bytes]", "data/agg_layer_split.csv",
                  "aggregatable2025: z_bytes + xy_bytes stacked vs n"))
    AUDIT.append(("B1_layer_split [messages]", "data/agg_layer_split.csv",
                  "aggregatable2025: z_messages + xy_messages stacked vs n"))
    fig.suptitle("aggregatable2025 communication split by layer (multi-secret only)")
    fig.tight_layout()
    fig.savefig(os.path.join(G, "B1_layer_split.png"), dpi=130,
                bbox_inches="tight")
    plt.close(fig)


# ------------------------------------------------------------- B2 z-fraction
def b2_z_fraction():
    rows = read(os.path.join(D, "z_fraction_sweep.csv"))
    rows.sort(key=lambda r: float(r["z_fraction"]))
    zf = [float(r["z_fraction"]) for r in rows]
    cms = [float(r["complaint_ms"]) for r in rows]
    comp = [int(r["complaints_filed"]) for r in rows]
    qagg = [int(r["qagg_count"]) for r in rows]
    fig, axs = plt.subplots(1, 2, figsize=(13, 5))
    axs[0].plot(zf, cms, color="#ff7f0e", marker="v")
    axs[0].set_ylabel("complaint management (ms)")
    axs[0].set_title("Complaint cost vs fraction of faults in z-layer")
    axs[1].plot(zf, comp, color="#9467bd", marker="D",
                label="complaints filed (xy-layer)")
    axs[1].plot(zf, qagg, color="#2ca02c", marker="^",
                label="Qagg count (z-layer, caught free)")
    axs[1].set_ylabel("count")
    axs[1].set_title("Where the 31 faults are caught")
    axs[1].legend()
    for ax in axs:
        ax.set_xlabel("fraction of faults placed in the z-layer")
        ax.grid(True, ls=":", alpha=0.5)
    AUDIT.append(("B2_z_fraction [complaint_ms]", "data/z_fraction_sweep.csv",
                  "complaint_ms vs z_fraction"))
    AUDIT.append(("B2_z_fraction [counts]", "data/z_fraction_sweep.csv",
                  "complaints_filed and qagg_count vs z_fraction"))
    fig.suptitle("n=64, t=32, 31 malicious dealers: Qagg absorbs z-layer faults (multi-secret only)")
    fig.tight_layout()
    fig.savefig(os.path.join(G, "B2_z_fraction.png"), dpi=130,
                bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------- A5 malicious n64
def a5_malicious():
    rows = read(os.path.join(D, "sweep_malicious_n64.csv"))
    order = ["neji", "gurkan", "btsof", "kalai2022",
             "aggregatable2025_z", "aggregatable2025_xy",
             "aggregatable2025_mixed"]
    style = {
        "neji": (COL["neji"], "-", MK["neji"], 6),
        "gurkan": (COL["gurkan"], "-", MK["gurkan"], 6),
        "btsof": (COL["btsof"], "--", MK["btsof"], 10),
        "kalai2022": (COL["kalai2022"], "-", MK["kalai2022"], 6),
        "aggregatable2025_z": (COL["aggregatable2025"], "-", "v", 6),
        "aggregatable2025_xy": (COL["aggregatable2025"], ":", "P", 6),
        "aggregatable2025_mixed": (COL["aggregatable2025"], "-.", "X", 6),
    }

    def series_m(name, col):
        pts = sorted((int(r["num_malicious"]), float(r[col])) for r in rows
                     if r["series"] == name)
        return [x for x, _ in pts], [y for _, y in pts]

    panels = [("faulty_count", "|Qagg| (faulty_count)", 1),
              ("complaints", "complaints filed", 2),
              ("complaint_ms", "complaint management (ms)", 3)]
    fig, axs = plt.subplots(3, 1, figsize=(9, 12), sharex=True)
    for ax, (col, ylabel, panel) in zip(axs, panels):
        for name in order:
            color, ls, mk, ms = style[name]
            x, y = series_m(name, col)
            ax.plot(x, y, color=color, ls=ls, marker=mk, markersize=ms,
                    label=name)
            AUDIT.append(("A5_malicious_n64 [panel %d]" % panel,
                          "data/sweep_malicious_n64.csv",
                          "%s: %s vs num_malicious" % (name, col)))
        ax.set_ylabel(ylabel)
        ax.grid(True, ls=":", alpha=0.5)
    axs[0].set_title("Committee response to malicious dealers (n=64, t=32)")
    axs[0].text(0.30, 0.08,
                "btsof, neji, kalai2022, aggregatable2025_xy overlap at 0",
                transform=axs[0].transAxes, fontsize=8)
    axs[2].text(0.02, 0.9, "btsof overlaps kalai2022",
                transform=axs[2].transAxes, fontsize=8)
    axs[-1].set_xlabel("num_malicious")
    axs[-1].set_xticks(sorted(set(int(r["num_malicious"]) for r in rows)))
    axs[0].legend(fontsize=8, loc="upper left", ncol=2)
    fig.tight_layout()
    fig.savefig(os.path.join(G, "A5_malicious_n64.png"), dpi=130,
                bbox_inches="tight")
    plt.close(fig)


a1_messages()
a1_rounds()
a2_comms("BLS12-381", "BLS12-381", "A2_multisecret_comms_bls.png", BG,
         "same curve BLS12-381 G1")
a2_comms("natural", None, "A2_multisecret_comms_natural.png", G,
         "natural curve: btsof and kalai2022 on Jubjub, aggregatable2025 on BLS")
a3_same_curve()
a4_premium([("btsof", "neji", COL["btsof"]),
            ("kalai2022", "neji", COL["kalai2022"])],
           sweep_n, None, get_sweep_n, "A4_premium_pairingfree.png",
           "pairing-free family, Jubjub", "data/sweep_n.csv")
a4_premium([("aggregatable2025", "gurkan", COL["aggregatable2025"])],
           bycurve, "BLS12-381", get_bycurve, "A4_premium_aggregatable.png",
           "aggregatable family, BLS12-381 G1", "bls/data/sweep_bycurve.csv")
b1_layer_split()
b2_z_fraction()
a5_malicious()

for fig, src, series in AUDIT:
    print("%-40s | %-30s | %s" % (fig, src, series))
