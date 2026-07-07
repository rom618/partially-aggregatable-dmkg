# Same-curve comparison report — pairing-free protocols on BLS12-381 G1

This is a **new, self-contained report** that does not touch or overwrite the main
report under `report/`. It answers one question the main report could not:

> The main report runs each protocol on the curve its design calls for —
> `neji`, `btsof`, `kalai2022` on **Jubjub** (~252-bit, no pairing), and
> `gurkan`, `aggregatable2025` on **BLS12-381 G1** (~381-bit pairing curve).
> That confounds two variables: *the protocol* and *the curve*. Are the
> aggregatable protocols slower because they are aggregatable, or just because
> they sit on a heavier curve?

To separate the two, the pairing-free protocols were **re-run on the exact same
BLS12-381 G1 curve** the aggregatable protocols are forced onto (build flag
`--features pf-bls`), and plotted against their Jubjub numbers. The Jubjub data is
kept; nothing is lost.

## How it was produced

The whole pairing-free code path in `bin/dmkg_bench.rs` is generic over the curve;
only three type aliases (`J`, `JAffine`, `JFr`) move. They are Jubjub by default
and become BLS12-381 `G1` under the `pf-bls` Cargo feature.

```bash
# Jubjub build (default) — already the source of report/bench_sweep.csv
cargo build --release --features network --bin dmkg_bench

# BLS12-381 build — pairing-free protocols on G1
cargo build --release --features "network pf-bls" --bin dmkg_bench
for n in 8 16 32 64; do t=$((n/2)); for p in neji gurkan btsof kalai2022 aggregatable2025; do
  ./target/release/dmkg_bench --protocol $p --n $n --threshold $t --seed 7 --samples 3 \
    --out report/bls/bench_sweep_bls.csv
done; done

python3 report/bls/plot_bls.py     # -> report/bls/{data,graphs}/
```

## Data

| File | Content |
|---|---|
| `bench_sweep_bls.csv` | raw sweep, all five protocols on BLS12-381 G1 (`seed=7`, `t=n/2`) |
| `data/sweep_bycurve.csv` | tidy: one row per (curve, protocol, n) |
| `data/curve_tax.csv` | BLS/Jubjub ratio per pairing-free protocol per metric |

## Graphs

| File | Content |
|---|---|
| `graphs/curve_neji.png`, `curve_btsof.png`, `curve_kalai2022.png` | same protocol, Jubjub vs BLS, on verify / keygen / bytes |
| `graphs/curve_tax.png` | the "curve tax" — how much slower/bigger BLS is than Jubjub, per protocol |
| `graphs/same_curve_verify.png` | all five protocols on the **same** BLS curve: verify vs n |

## Findings

### 1. The curve tax is a flat ~2× on compute, 1.5× on bytes

Moving the pairing-free protocols from Jubjub to BLS12-381 G1 costs, uniformly
across `neji`, `btsof`, `kalai2022` and across `n ∈ {8,16,32,64}`:

| metric | BLS / Jubjub |
|---|---|
| deal | ~1.9× |
| verify | ~1.8–2.1× |
| keygen | ~1.9–2.1× |
| transcript bytes | **1.5×** exactly |

The compute tax (~2×) is the larger field: BLS12-381's base field is ~381 bits vs
Jubjub's ~252, so each group op costs roughly `(381/252)² ≈ 2.3×` in the
schoolbook regime — matching the measured ~2×. The bytes tax is exactly `1.5×`
because a compressed G1 point is 48 bytes vs a compressed Jubjub point 32 bytes
(`48/32 = 1.5`), and every transcript is a fixed count of group elements. This
is a **pure curve cost**, independent of `n` and of the protocol.

### 2. On one identical curve, the aggregatable protocols are *still* slower

`graphs/same_curve_verify.png` puts all five on BLS12-381 G1. Even with the curve
held constant, `gurkan` and `aggregatable2025` sit **above** `kalai2022`/`btsof`
in verify. So the verify gap is **not** merely the curve — the aggregatable
design adds intrinsic work on top: the SCRAPE PVSS pairing check (2·n pairings per
node) and the batched Schnorr proofs-of-knowledge of `cᵢ` (see the main report's
Fig. 1c breakdown, ~50/50 pairings vs PoK). The curve tax and the
aggregation-machinery tax are **two separate, additive penalties**; this report
isolates the first, and the main report's Fig. 1c isolates the second.

### 3. Confirmation: aggregatable protocols *cannot* use a smaller curve

Yes — confirmed, and it is structural, not an implementation choice:

- **Aggregation needs public verifiability, which needs a pairing.** Gurkan's
  z-layer is verified by a bilinear pairing equation
  `e(·, ĥ) = e(g, ·)` on the SCRAPE transcript. A bilinear pairing `e: G1×G2→GT`
  only exists on **pairing-friendly** curves. Jubjub (and any plain prime-order
  curve) has **no pairing**, so it cannot host this check — remove the pairing and
  you lose the public, complaint-free verification that *is* the aggregatability.
- **Pairing-friendly ⟹ large field.** To admit an efficient pairing a curve needs
  a controlled embedding degree, which forces a large base field: BLS12-381 is
  ~381 bits precisely to hit ~128-bit security through the pairing. There is no
  ~256-bit pairing-friendly curve at this security level. So aggregatable
  protocols are locked onto a heavy field — the ~1.5–2× tax measured above is
  **unavoidable** for them.
- **Pairing-free protocols are not.** Feldman/Pedersen verification is just
  discrete-log exponent checks (`gˢ =? ∏ CMⱼ^{…}`), which need only a plain
  prime-order group. `neji`, `btsof`, `kalai2022` can therefore live on Jubjub and
  keep the ~2× / 1.5× savings — this report quantifies exactly what they save.

**Net:** aggregatability buys `O(k·n log n)` verification and a complaint-free
happy path, but permanently costs the pairing curve (~2× compute, 1.5× bytes) plus
the ZK/pairing machinery on top. The pairing-free protocols pay neither, at the
price of `O(k·n²)` complaint-based verification.
