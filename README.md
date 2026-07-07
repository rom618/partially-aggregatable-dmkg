# Partially Aggregatable Distributed Multi-Key Generation (DMKG)

> **⚠️ Research code — not for production.** This is a fork of Gurkan et al.'s
> aggregatable DKG and inherits their warning. Nothing here is production-ready
> cryptography; it is not constant-time and has not been audited.

A Rust implementation of the **Partially Aggregatable Distributed Multi-Key
Generation** protocol of R. Kalai, W. Neji and N. Ben Rajeb (2024), built on top of
the [Aggregatable Distributed Key Generation](https://eprint.iacr.org/2021/005) of
Gurkan et al. (EUROCRYPT 2021).

It comes with a full test suite, a benchmark harness, a LaTeX evaluation report, and
an **interactive web UI** for stepping through the protocol and inspecting each
participant's public vs. private state.

---

## 1. What the protocol does

The committee jointly generates a *traceable* key pair

```
sk = (x1, x2, y1, y2, z)
pk = (c1, c2, c3) = ( g1^x1·g2^x2 ,  g1^y1·g2^y2 ,  g1^z )
```

using **two independent sharing machineries** per dealer — hence *partially*
aggregatable:

| Secret(s)         | Mechanism                                   | Aggregatable? |
|-------------------|---------------------------------------------|:-------------:|
| `z`               | Gurkan enhanced SCRAPE PVSS (BLS12-381)      | **yes** (`O(n)` messages, `O(log n)` rounds) |
| `x1,x2,y1,y2`     | four-generator Pedersen + Franklin–Yung MSS | no (`O(n²)` all-to-all) |

The `z` layer is publicly verifiable and aggregated up a binary tree; the four
remaining secrets are shared with encrypted Pedersen shares and a complaint phase
that is *short-circuited* by the `z` layer's set of reported-dishonest dealers
(`Qagg`). The protocol follows Kalai, Neji and Ben Rajeb, *Partially Aggregatable
Distributed Multi-Key Generation Protocol* (2024); see `docs/` for the source papers.

---

## 2. Repository map

```
src/dkg/
  pvss.rs, share.rs, srs.rs, config.rs,
  dealer.rs, participant.rs, node.rs        upstream SCRAPE PVSS (the z layer)
  aggregator.rs                             z verification + the Qagg set        (Phase 1)
  mss.rs                                    Franklin–Yung multi-secret polynomials (Phase 2)
  pedersen.rs                               four-generator commitments + Eq.(1)  (Phase 3)
  encryption.rs                             lifted-ElGamal share encryption       (Phase 4)
  complaint.rs                              simplified complaint management       (Phase 5)
  dmkg.rs                                   end-to-end DMKG node + reconstruction (Phase 6)
  network.rs                                Tokio network simulation              (Phase 7)
src/sim/mod.rs                              phase-steppable DkgSession (drives the UI)
src/signature/                              BLS / Schnorr / algebraic signatures (upstream)
ui/                                         interactive web UI (server + frontend)
bin/dmkg_bench.rs                           benchmark harness
report/                                      benchmark data, plots and figures
docs/                                        source papers (Gurkan, Neji, BTSOF, Kalai)
```

Each protocol module carries unit tests; **68 tests** pass in total.

---

## 3. Installation

Install a recent stable Rust toolchain with [rustup](https://rustup.rs/). The crate
pins `arkworks 0.2` on purpose (to reuse Gurkan's PVSS verbatim); no other setup is
required.

---

## 4. Build, test, bench

```bash
cargo build                                   # library
cargo test                                    # upstream + DMKG unit tests
cargo test --features network                 # + the network-simulation tests (68 total)

# Per-phase benchmark (compute and network reported separately), n = powers of two:
cargo run --release --features network --example dmkg_bench

# Upstream Criterion benches:
cargo bench --features dkg-bench

cargo fmt && cargo clippy --features "network ui"
```

The benchmark numbers and their analysis are in [`REPORT.md`](REPORT.md); a
paper-style write-up (in the form of Gurkan's "Implementation" section) is in
[`report/implementation.tex`](report/implementation.tex), ready to drop into
Overleaf.

---

## 5. Interactive UI

Launch a browser-based visualiser that runs the protocol **one phase at a time**:

```bash
cargo run --release --features ui --bin dkg_ui
# then open http://127.0.0.1:8080  (set PORT=... to change the port)
```

It is a self-contained, dependency-light local web app (a tiny std-only HTTP server
bundling a vanilla-JS frontend; the only extra dependency is `serde_json`). From the
browser you can:

- **Pick `n ∈ [2, 10]`** participants and set the **threshold `t`** (the polynomial
  degree). The default is `t = ⌊n/2⌋`, matching the paper's `t−1 < n/2` adversary
  bound; you can change it freely (the UI warns if the bound is exceeded).
- **Mark any participant malicious, per layer.** Each participant has a malice
  selector with three corruption modes, so you can demonstrate the two
  disqualification paths in isolation:
  - **`z`** — tampers its `z` commitment only. Caught by the publicly-verifiable
    `z` layer (lands in `Qagg`) *before* `z` is aggregated; honest in the Pedersen
    layer, so nobody complains.
  - **`Pedersen`** — honest in `z` (never in `Qagg`), but deals one inconsistent
    Pedersen share. Caught *only* by the complaint phase — *after* `Qagg` is
    resolved — so the `Qagg` short-circuit does **not** apply and a full
    Neji-style disputation runs (disqualification reason `LostDisputation`).
  - **`both`** — corrupts both layers (the original demo dealer): it is in `Qagg`
    *and* the target of a complaint, so the `Qagg` short-circuit disqualifies it
    without a disputation.
- **Advance the protocol with a button** through
  `Setup → Distribution → z-Aggregation → Verification → Complaints → KeyGeneration → Done`,
  watching `Qagg`, the complaints, `QUAL`, and the final `pk = (c1,c2,c3)` (with a
  badge confirming it reconstructs from any `t+1` shares).
- **Watch the `z`-layer aggregate up a binary tree.** The `z-Aggregation` phase is
  itself stepped one tree level at a time: each dealer's PVSS share is verified at
  the leaves (building `Qagg`), then transcripts are folded pairwise up the
  `⌈log₂ n⌉`-level gossip tree (each internal node labelled with its aggregator).
  Once a single candidate transcript remains, the **root broadcasts it to everyone
  and each participant verifies & approves it** (the publicly-verifiable approval
  that lets the `z` layer skip a per-dealer complaint round) before it is folded
  into each node's `z`-secret share.
- **Inspect any participant** by clicking its card. The inspector splits that
  participant's state into **Public** (green — on the broadcast channel: signature /
  ElGamal public keys, the `z`-share verification & transcript-approval status, the
  `z` commitment, the Pedersen commitments `CMₖ`, the public-key contributions, the
  ciphertexts it dealt), **Private** (amber — known only to it: its secret keys, the
  secrets `x1,x2,y1,y2,z_i`, the shares it decrypted, and its accumulated `z`-secret
  share), and **Communication** (blue — the messages it sends/receives on each public
  channel: its PVSS-share broadcast, the `n` Pedersen shares it deals and receives,
  its partial-transcript gossip up the tree, and the final-transcript broadcast).

> The malicious flag is itself displayed — this is a teaching tool. In the real
> protocol corruption is not observable; the UI surfaces it so you can correlate a
> dealer's behaviour with its fate (`Qagg`, complaints, disqualification).

Internally the UI reuses the exact `src/dkg/*` cryptography via the
`src/sim::DkgSession` state machine; it never reimplements any of it. (Because the
SCRAPE layer uses a Radix2 domain, the `z` layer pads its participant set to the
next power of two with throwaway keys; the real protocol, public key, and
reconstruction always use the chosen `n`.)

---

## 6. License & attribution

Forked from [`kobigurk/aggregatable-dkg`](https://github.com/kobigurk/aggregatable-dkg).
The DMKG extension follows Kalai–Neji–Ben Rajeb (2024). Upstream license terms apply.
</content>
