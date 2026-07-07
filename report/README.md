# DKG / DMKG benchmark report

Comparison figures for the five protocols, in two groups:

- **single-secret:** `neji`, `gurkan`
- **multi-secret:** `btsof`, `kalai2022`, `aggregatable2025`

Single-secret and multi-secret protocols are never drawn on the same axes, except
the sanctioned cross-cardinality figures (A3 same-curve, A4 premium).

Natural curves: `neji`, `btsof`, `kalai2022` on **Jubjub** (~252-bit, no pairing);
`gurkan`, `aggregatable2025` on **BLS12-381 G1** (~381-bit pairing curve). Speed
comparisons hold the curve constant (all-BLS data under `bls/`); as-designed cost
uses each protocol's natural curve.

## Regenerate

```bash
python3 report/plot_graphs.py      # Parts A1, A2 (natural), A4, B1, B2  -> report/graphs/
                                   #        A2 (BLS), A3                 -> report/bls/graphs/
python3 report/bls/plot_bls.py     # curve-tax figures                  -> report/bls/graphs/
```

Both scripts are ASCII-only, `axes.unicode_minus=False`, log-log for anything vs n,
n on a log2 axis, one fixed color per protocol across every figure.

## Figures and their exact sources

| Figure | Source CSV | Series drawn |
|---|---|---|
| `graphs/A1_messages_vs_n.png` | `data/sweep_n.csv` | `total_messages` vs n; single panel {neji,gurkan}, multi panel {btsof,kalai2022,aggregatable2025} |
| `graphs/A1_rounds_vs_n.png` | derived (network model) | rounds vs n; broadcast=1, tree=`ceil(log2 n)` (gurkan and the agg2025 z-layer are tree) |
| `bls/graphs/A2_multisecret_comms_bls.png` | `bls/data/sweep_bycurve.csv` (bytes), `data/sweep_n.csv` (messages) | btsof, kalai2022, aggregatable2025 all on BLS12-381 G1 |
| `graphs/A2_multisecret_comms_natural.png` | `data/sweep_n.csv` | same three protocols on their natural curves (labelled) |
| `bls/graphs/A3_same_curve_costs.png` | `bls/data/sweep_bycurve.csv` | all five, deal/verify/keygen vs n, held on BLS12-381 G1 |
| `graphs/A4_premium_pairingfree.png` | `data/sweep_n.csv` | ratios btsof/neji and kalai2022/neji per metric (Jubjub) |
| `graphs/A4_premium_aggregatable.png` | `bls/data/sweep_bycurve.csv` | ratio aggregatable2025/gurkan per metric (BLS) |
| `graphs/B1_layer_split.png` | `data/agg_layer_split.csv` | aggregatable2025 z-layer vs xy-layer, bytes and messages, stacked |
| `graphs/B2_z_fraction.png` | `data/z_fraction_sweep.csv` | complaint_ms, complaints_filed, qagg_count vs z-fraction |
| `bls/graphs/curve_*.png`, `curve_tax.png`, `same_curve_verify.png` | `bls/data/*` | see `bls/README.md` |

`report/plot_graphs.py` prints this figure -> CSV -> series mapping on every run.

## New benchmark runs added in this rebuild

### B1 - per-layer communication split (`data/agg_layer_split.csv`)

Columns `n,z_bytes,xy_bytes,z_messages,xy_messages`. Derived from the raw
`bench_sweep.csv`: aggregatable2025 already emits one network row per pattern, and
those patterns *are* the layers - `tree` is the aggregated SCRAPE z-layer,
`broadcast` is the Franklin-Yung Pedersen xy-layer. No new instrumentation needed;
the split was already present in the raw sweep and is only reshaped here.

The figure shows the aggregated z-layer is a small, near-fixed slice while the
broadcast xy-layer dominates - which is why aggregatable2025 stays at ~n^3 bytes
despite being *partially* aggregatable.

### B2 - z-fraction sweep (`data/z_fraction_sweep.csv`)

New run. Fixed n=64, t=32, 31 malicious dealers (= t-1). The fraction of those
faults placed in the z-layer is swept 0.0 -> 1.0 (the rest go to the xy-layer):

```bash
./target/release/dmkg_bench --protocol aggregatable2025 --n 64 --threshold 32 \
  --malicious "<k ids>:z,<31-k ids>:xy" --seed 7 --samples 3 --out <csv>
```

`qagg_count` is read as the length of the `faulty` column (the Qagg set the
public z-verification exports). Result: as more corruption lands in the
publicly-verifiable z-layer, complaints filed fall 31 -> 0, Qagg rises 0 -> 31, and
complaint-management time drops from ~1400 ms to ~0, with reconstruction succeeding
throughout. This generalizes the discrete `_z`/`_xy`/`_mixed` malicious series into
a continuous curve: corruption caught free by Qagg costs nothing, corruption in the
non-aggregatable xy-layer pays the full disputation price.

## Data files

Inputs carried over from the prior sweeps (unchanged):
`bench_sweep.csv`, `latency_sweep.csv`, `data/sweep_n.csv`, `data/sweep_latency*.csv`,
`data/sweep_malicious_n{16,64}.csv`, `data/gurkan_verify_breakdown.csv`,
`data/scaling_exponents.csv`, `bls/bench_sweep_bls.csv`, `bls/data/*.csv`.

New in this rebuild: `data/agg_layer_split.csv`, `data/z_fraction_sweep.csv`.
