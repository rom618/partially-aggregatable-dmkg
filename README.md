# Partially Aggregatable DMKG

> Research code — not for production. It is not constant-time and has not been audited.

A Rust implementation of the partially aggregatable distributed multi-key
generation protocol of Kalai, Neji and Ben Rajeb, built on top of Gurkan et al.'s
[aggregatable DKG](https://eprint.iacr.org/2021/005) over BLS12-381.

The committee jointly generates a traceable key pair

```
sk = (x1, x2, y1, y2, z)
pk = (c1, c2, c3) = (g1^x1·g2^x2, g1^y1·g2^y2, g1^z)
```

with two sharing layers:

- **`z`** : aggregatable SCRAPE PVSS, gossiped and combined up a binary tree
  (`O(n)` messages, `O(log n)` rounds); failed dealers are collected in `Qagg`.
- **`(x1,x2,y1,y2)`** : four-generator Pedersen / Franklin–Yung sharing with
  encrypted shares and a complaint phase that `Qagg` short-circuits.

## Build & test

```
cargo test                      # unit tests
cargo test --features network   # + network-simulation tests
```

## Benchmarks

```
cargo run --release --features network --example dmkg_bench
cargo bench --features dkg-bench
```

## Interactive UI

A browser visualiser that steps through the protocol one phase at a time:

```
cargo run --release --features ui --bin dkg_ui   # http://127.0.0.1:8080
```

Pick `n` and the threshold `t`, optionally mark participants malicious (corrupting
the `z` layer, the Pedersen layer, or both), advance phase by phase, and inspect
each participant's public vs. private state.
