//! Command-line benchmark harness comparing three key-generation protocols over
//! the same BLS12-381 primitives:
//!
//! * `gurkan` - the single-secret aggregatable SCRAPE PVSS DKG (EUROCRYPT 2021),
//!   the floor for "everything aggregatable": one secret, publicly verifiable, no
//!   complaint phase.
//! * `btsof` - the original five-secret DMKG of Ma, Xu & Li (BTSOF, ICICS 2020,
//!   Fig 3/4): the same Pedersen-VSS + Franklin-Yung MSS shape as `kalai2022`, but
//!   faithful to the paper's `z` carrier, which commits with only TWO generators
//!   (`cm_k = g1^{a''} h1^{b''}`) and encrypts two share components, where
//!   `kalai2022` conservatively over-counts `z` with the four-generator carrier.
//! * `kalai2022` - the public-channel DMKG that shares all five secret components
//!   through VMSS and resolves every failure with the disputation-based complaint
//!   phase; nothing aggregatable, the ceiling for "complaints for everything".
//! * `aggregatable2025` - the partially-aggregatable DMKG implemented in this
//!   crate: z the Gurkan way, (x1,x2,y1,y2) the Kalai way, with a Qagg handoff
//!   between the two layers.
//!
//! It reuses the crate's cryptographic modules unchanged and only sequences them
//! into each protocol's shape. Computation and network are measured on separate
//! clocks; the network layer reuses the Tokio simulation in `dkg::network` and
//! only times the message pattern (latency rounds, message and byte counts) from
//! the real serialized message sizes - it never re-runs the cryptography.
//!
//! One configuration per invocation; one CSV row per network pattern (so the
//! 2025 protocol, which uses both a tree and a broadcast pattern, emits two rows
//! sharing the same compute and outcome columns).
//!
//! Run:
//! ```text
//! cargo run --release --features network --bin dmkg_bench -- \
//!   --protocol aggregatable2025 --n 16 --threshold 8 \
//!   --malicious 1:z,4:xy --latency-ms 100 --seed 7 --samples 10 --out runs.csv
//! ```

use aggregatable_dkg::{
    dkg::{
        aggregator::DKGAggregator,
        complaint::{run_complaint_phase, Complaint},
        config::Config,
        dealer::Dealer,
        dmkg::{
            self, aggregate_public_key, reconstruct_pk_components, DMKGContribution, DMKGDealer,
        },
        encryption::{ElGamalBase, ElGamalCiphertext, ElGamalKeypair, EncryptedPedersenShare},
        mss::MSSPolynomial,
        neji::{
            self, Complaint as NejiComplaint, FeldmanDistribution, NejiGenerators, ShamirPolynomial,
        },
        network::{run_broadcast_round, run_tree_gossip},
        node::Node,
        participant::{Participant, ParticipantState},
        pedersen::{PedersenDistribution, PedersenGenerators, PedersenShare},
        share::{message_from_c_i, DKGShare, DKGTranscript},
        srs::SRS,
    },
    signature::{
        bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        scheme::SignatureScheme,
    },
};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::marker::PhantomData;
use std::path::Path;
use std::time::{Duration, Instant};

type E = Bls12_381;
type SPOK = BLSSignature<BLSSignatureG2<Bls12_381>>;
type SSIG = BLSSignature<BLSSignatureG1<Bls12_381>>;

// The aggregatable protocols (gurkan, aggregatable2025) need BLS12-381's pairing,
// so their Pedersen `(x1,x2,y1,y2)` layer lives in `G1` to share that curve. The
// pairing-free DMKGs (neji, btsof, kalai2022) use no pairing, so per their papers
// (a generic prime-order group) they run on Jubjub — a non-pairing curve over
// BLS12-381's scalar field. `G1` is the curve for the BLS-side Pedersen layer.
type G1 = G1Projective;

// Curve for the pairing-free protocols (neji, btsof, kalai2022). By default they
// run on Jubjub (`ark-ed-on-bls12-381`), a ~252-bit non-pairing curve — the
// natural, cheapest setting for a scheme that needs no pairing. Building with
// `--features pf-bls` re-points these aliases at BLS12-381's `G1` (the same
// ~381-bit pairing curve the aggregatable protocols are forced onto), so the two
// protocol families can be compared on ONE identical curve, isolating the
// protocol cost from the curve cost. The whole pairing-free code path is generic
// over the curve, so only these three aliases move.
#[cfg(not(feature = "pf-bls"))]
type J = ark_ed_on_bls12_381::EdwardsProjective;
#[cfg(not(feature = "pf-bls"))]
type JAffine = ark_ed_on_bls12_381::EdwardsAffine;
#[cfg(not(feature = "pf-bls"))]
type JFr = ark_ed_on_bls12_381::Fr;

#[cfg(feature = "pf-bls")]
type J = G1Projective;
#[cfg(feature = "pf-bls")]
type JAffine = G1Affine;
#[cfg(feature = "pf-bls")]
type JFr = Fr;

// ----------------------------------------------------------------------------
// Protocols and the cross-protocol malicious model.
// ----------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Gurkan,
    Neji,
    Btsof,
    Kalai2022,
    Aggregatable2025,
}

impl Protocol {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "gurkan" => Ok(Protocol::Gurkan),
            "neji" => Ok(Protocol::Neji),
            "btsof" => Ok(Protocol::Btsof),
            "kalai2022" => Ok(Protocol::Kalai2022),
            "aggregatable2025" => Ok(Protocol::Aggregatable2025),
            other => Err(format!(
                "unknown protocol '{}' (expected gurkan|neji|btsof|kalai2022|aggregatable2025)",
                other
            )),
        }
    }
    fn label(&self) -> &'static str {
        match self {
            Protocol::Gurkan => "gurkan",
            Protocol::Neji => "neji",
            Protocol::Btsof => "btsof",
            Protocol::Kalai2022 => "kalai2022",
            Protocol::Aggregatable2025 => "aggregatable2025",
        }
    }
}

/// The layer a malicious dealer corrupts. The same `(id, layer)` injection maps
/// onto each protocol's own corruption mechanism, so the "same logical
/// misbehaviour" is measured across protocols.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Layer {
    Z,
    Xy,
}

/// Parse `--malicious "1:z,4:xy"` into a per-id layer map, rejecting layers a
/// protocol does not have.
fn parse_malicious(spec: &str, protocol: Protocol) -> Result<BTreeMap<usize, Layer>, String> {
    let mut out = BTreeMap::new();
    let spec = spec.trim();
    if spec.is_empty() || spec == "none" {
        return Ok(out);
    }
    for entry in spec.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (id_s, layer_s) = entry
            .split_once(':')
            .ok_or_else(|| format!("malicious entry '{}' must be id:layer", entry))?;
        let id: usize = id_s
            .trim()
            .parse()
            .map_err(|_| format!("bad id in '{}'", entry))?;
        let layer = match layer_s.trim() {
            "z" => Layer::Z,
            "xy" => Layer::Xy,
            other => return Err(format!("unknown layer '{}' (expected z|xy)", other)),
        };
        if protocol == Protocol::Gurkan && layer == Layer::Xy {
            return Err(format!(
                "protocol gurkan has no xy layer; rejected malicious entry '{}'",
                entry
            ));
        }
        out.insert(id, layer);
    }
    Ok(out)
}

// ----------------------------------------------------------------------------
// Metrics.
// ----------------------------------------------------------------------------

/// Single-threaded compute timings, milliseconds, separated by phase.
struct Compute {
    deal_ms: f64,
    verify_ms: f64,
    complaint_ms: f64,
    keygen_ms: f64,
}

/// Outcome / correctness metrics for one run.
struct Outcome {
    /// Ids caught by public verification (Gurkan / 2025-z). Empty for Kalai.
    faulty: BTreeSet<usize>,
    /// Number of complaints filed.
    complaints: usize,
    /// Final qualified set size.
    qual: usize,
    /// Did pk reconstruct from t+1 shares and match the directly-aggregated pk.
    reconstructed_ok: Option<bool>,
}

/// One network pattern's timing and volume (separate clock).
struct NetRow {
    pattern: &'static str,
    wall_ms: f64,
    messages: usize,
    bytes: usize,
    rounds: usize,
}

/// Best-of-`iters` wall time for a single isolated operation (plus one warm-up).
fn best_of<T, F: FnMut() -> T>(iters: usize, mut f: F) -> Duration {
    let _ = f();
    let mut best = Duration::from_secs(u64::MAX);
    for _ in 0..iters.max(1) {
        let start = Instant::now();
        let _ = f();
        let d = start.elapsed();
        if d < best {
            best = d;
        }
    }
    best
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

// ----------------------------------------------------------------------------
// Shared environment (same primitives for all three protocols).
// ----------------------------------------------------------------------------

struct Env {
    n: usize,
    degree: usize,
    samples: usize,
    /// SCRAPE Radix2 domain size: `next_power_of_two(n)`. Real participants are
    /// `0..n`; slots `n..domain_size` are padding with throwaway keys, used only
    /// by the z layer of the aggregatable protocols.
    domain_size: usize,
    config: Config<E>,
    scheme_pok: SPOK,
    scheme_sig: SSIG,
    // BLS12-381 `G1` Pedersen setup, used by the aggregatable2025 xy layer.
    generators: PedersenGenerators<G1>,
    base: ElGamalBase<G1>,
    sig_sk: Vec<Fr>,
    elgamal: Vec<ElGamalKeypair<G1>>,
    participants_map: BTreeMap<usize, Participant<E, SSIG>>,
    receiver_pks: Vec<G1Affine>,
    // Jubjub setup, used by the pairing-free DMKGs (neji, btsof, kalai2022).
    jj_generators: PedersenGenerators<J>,
    jj_neji: NejiGenerators<J>,
    jj_base: ElGamalBase<J>,
    jj_elgamal: Vec<ElGamalKeypair<J>>,
    jj_receiver_pks: Vec<JAffine>,
    malice: BTreeMap<usize, Layer>,
}

impl Env {
    fn build(
        n: usize,
        degree: usize,
        samples: usize,
        malice: BTreeMap<usize, Layer>,
        rng: &mut ChaCha20Rng,
    ) -> Result<Self, String> {
        let srs = SRS::<E>::setup(rng).map_err(|e| e.to_string())?;
        let scheme_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.h_g2,
                g_signature: srs.g_g1,
            },
        };
        let scheme_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.g_g1,
                g_signature: srs.h_g2,
            },
        };
        let u_1 = G2Projective::rand(rng).into_affine();
        let config = Config {
            srs: srs.clone(),
            u_1,
            degree,
        };
        let generators = PedersenGenerators::<G1>::setup().map_err(|e| e.to_string())?;
        let base = ElGamalBase::<G1>::setup().map_err(|e| e.to_string())?;
        let jj_generators = PedersenGenerators::<J>::setup().map_err(|e| e.to_string())?;
        let jj_neji = NejiGenerators::<J>::setup().map_err(|e| e.to_string())?;
        let jj_base = ElGamalBase::<J>::setup().map_err(|e| e.to_string())?;

        let mut sig_sk = Vec::with_capacity(n);
        let mut sig_pk = Vec::with_capacity(n);
        let mut elgamal = Vec::with_capacity(n);
        let mut jj_elgamal = Vec::with_capacity(n);
        for _ in 0..n {
            let (sk, pk) = scheme_sig
                .generate_keypair(rng)
                .map_err(|e| e.to_string())?;
            sig_sk.push(sk);
            sig_pk.push(pk);
            elgamal.push(ElGamalKeypair::<G1>::generate(&base, rng));
            jj_elgamal.push(ElGamalKeypair::<J>::generate(&jj_base, rng));
        }
        let jj_receiver_pks = jj_elgamal.iter().map(|k| k.pk).collect::<Vec<_>>();

        let m = n.next_power_of_two();
        let mut participants_map = BTreeMap::new();
        for (id, pk) in sig_pk.iter().enumerate() {
            participants_map.insert(id, Self::participant(id, *pk));
        }
        for id in n..m {
            let (_dummy_sk, dummy_pk) = scheme_sig
                .generate_keypair(rng)
                .map_err(|e| e.to_string())?;
            participants_map.insert(id, Self::participant(id, dummy_pk));
        }
        let receiver_pks = elgamal.iter().map(|k| k.pk).collect::<Vec<_>>();

        Ok(Self {
            n,
            degree,
            samples,
            domain_size: m,
            config,
            scheme_pok,
            scheme_sig,
            generators,
            base,
            sig_sk,
            elgamal,
            participants_map,
            receiver_pks,
            jj_generators,
            jj_neji,
            jj_base,
            jj_elgamal,
            jj_receiver_pks,
            malice,
        })
    }

    fn participant(id: usize, pk: G2Affine) -> Participant<E, SSIG> {
        Participant::<E, SSIG> {
            pairing_type: PhantomData,
            id,
            public_key_sig: pk,
            state: ParticipantState::Dealer,
        }
    }

    fn build_node(&self, id: usize) -> Node<E, SPOK, SSIG> {
        Node {
            aggregator: DKGAggregator {
                config: self.config.clone(),
                scheme_pok: self.scheme_pok.clone(),
                scheme_sig: self.scheme_sig.clone(),
                participants: self.participants_map.clone(),
                transcript: DKGTranscript::empty(self.degree, self.domain_size),
                qagg: BTreeSet::new(),
            },
            dealer: Dealer {
                private_key_sig: self.sig_sk[id],
                accumulated_secret: G2Projective::zero().into_affine(),
                participant: self.participants_map[&id].clone(),
            },
        }
    }

    fn neutral_count(&self) -> usize {
        self.n.saturating_sub(2).max(1)
    }
}

// ----------------------------------------------------------------------------
// Gurkan baseline: single-secret aggregatable DKG.
// ----------------------------------------------------------------------------

fn run_gurkan(
    env: &Env,
    latency: Duration,
    rng: &mut ChaCha20Rng,
) -> (Compute, Outcome, Vec<NetRow>) {
    let n = env.n;
    let degree = env.degree;

    // ---- Deal one z-share per dealer (a z-cheater corrupts its commitment). ----
    let mut shares: Vec<DKGShare<E, SPOK, SSIG>> = Vec::with_capacity(n);
    for i in 0..n {
        let mut node = env.build_node(i);
        let mut share = node.share(rng).expect("share");
        if env.malice.get(&i) == Some(&Layer::Z) {
            // The only corruption available to a Gurkan dealer: break its single
            // PVSS contribution so public verification rejects it.
            share.c_i = G1Projective::rand(rng).into_affine();
        }
        shares.push(share);
    }

    // ---- Public verification + aggregation: bad transcripts feed the faulty set. --
    let mut aggregator = env.build_node(0).aggregator;
    for share in shares.iter() {
        let _ = aggregator.receive_share(rng, share);
    }
    let faulty = aggregator.qagg.clone();
    let transcript = aggregator.transcript.clone();

    // Combined commitment c = sum_i w_i * c_i over the accepted contributions.
    let mut c = G1Projective::zero();
    for contribution in transcript.contributions.values() {
        c += contribution.c_i.mul(Fr::from(contribution.weight));
    }
    let c = c.into_affine();

    // ---- Reconstruct sk = h_g2^{F(0)} from t+1 receivers' decrypted shares. ----
    let domain = Radix2EvaluationDomain::<Fr>::new(env.domain_size).expect("domain");
    let mut indices = Vec::with_capacity(degree + 1);
    let mut secrets_g2 = Vec::with_capacity(degree + 1);
    for j in 0..(degree + 1).min(n) {
        let mut node = env.build_node(j);
        if node
            .receive_transcript_and_decrypt(rng, transcript.clone())
            .is_ok()
        {
            indices.push(domain.group_gen.pow([j as u64]));
            secrets_g2.push(node.dealer.accumulated_secret);
        }
    }
    let reconstructed_ok = gurkan_reconstruct_ok(env, c, &indices, &secrets_g2);

    // ---- Timings (single isolated operations, best of `samples`). ----
    let samples = env.samples;
    let deal = best_of(samples, || {
        let mut node = env.build_node(0);
        node.share(rng).expect("share");
    });
    let verify = best_of(samples, || {
        let mut node = env.build_node(0);
        let _ = node.receive_transcript_and_decrypt(rng, transcript.clone());
    });
    let keygen = best_of(samples, || {
        gurkan_reconstruct_ok(env, c, &indices, &secrets_g2);
    });

    let compute = Compute {
        deal_ms: ms(deal),
        verify_ms: ms(verify),
        complaint_ms: 0.0, // no complaint phase exists in Gurkan
        keygen_ms: ms(keygen),
    };
    let outcome = Outcome {
        complaints: 0,
        qual: transcript.contributions.len(),
        faulty,
        reconstructed_ok,
    };

    // Gurkan gossips DKG transcripts up a binary tree (latency-bound, cheap).
    let payload = shares[0].serialized_size();
    let net = run_tree_gossip(n, latency, payload);
    let rows = vec![NetRow {
        pattern: "tree",
        wall_ms: ms(net.wall),
        messages: net.messages,
        bytes: net.bytes,
        rounds: net.rounds,
    }];

    (compute, outcome, rows)
}

/// Interpolate `h_g2^{F(0)}` in the exponent and check it against the combined
/// commitment `c = g1^{F(0)}` via a pairing: `e(c, h_g2) == e(g1, h_g2^{F(0)})`.
fn gurkan_reconstruct_ok(
    env: &Env,
    c: G1Affine,
    indices: &[Fr],
    secrets_g2: &[G2Affine],
) -> Option<bool> {
    if indices.len() < env.degree + 1 {
        return None;
    }
    let lambdas = MSSPolynomial::<Fr>::lagrange_coefficients(Fr::zero(), indices).ok()?;
    let mut acc = G2Projective::zero();
    for (lambda, s) in lambdas.iter().zip(secrets_g2.iter()) {
        acc += s.mul(lambda.into_repr());
    }
    let reconstructed = acc.into_affine();
    let lhs = <E as PairingEngine>::pairing(c, env.config.srs.h_g2);
    let rhs = <E as PairingEngine>::pairing(env.config.srs.g_g1, reconstructed);
    Some(lhs == rhs)
}

// ----------------------------------------------------------------------------
// Kalai 2022 baseline: five-secret, non-aggregatable, complaint-based.
// ----------------------------------------------------------------------------

/// One dealer's Kalai contribution. The (x1,x2,y1,y2) carriers live in one
/// four-generator Pedersen distribution; the z carrier is modelled by a second
/// distribution checked by its own equation. Both go through the complaint
/// pipeline - z is not special here. Modelling the z carrier with a full
/// four-generator distribution slightly over-counts its commitment work (the
/// paper's z carrier uses two generators), which is a conservative upper bound.
struct KalaiContribution {
    xy_commitments: Vec<JAffine>,
    xy_enc: Vec<EncryptedPedersenShare<J>>,
    xy_openings: Vec<PedersenShare<J>>,
    z_commitments: Vec<JAffine>,
    z_enc: Vec<EncryptedPedersenShare<J>>,
    z_openings: Vec<PedersenShare<J>>,
    c1: JAffine,
    c2: JAffine,
    c3: JAffine,
}

fn deal_kalai(env: &Env, malice: Option<Layer>, rng: &mut ChaCha20Rng) -> KalaiContribution {
    let n = env.n;
    let victim = 0usize; // any fixed receiver; the cheater deals it a bad share

    let (mut xy, xy_secrets) =
        PedersenDistribution::deal(&env.jj_generators, env.degree, n, rng).expect("xy deal");
    let (mut z, z_secrets) =
        PedersenDistribution::deal(&env.jj_generators, env.degree, n, rng).expect("z deal");

    match malice {
        Some(Layer::Xy) => xy.shares[victim].sf += JFr::rand(rng),
        Some(Layer::Z) => z.shares[victim].sf += JFr::rand(rng),
        None => {}
    }

    let xy_enc = encrypt_all(
        &env.jj_generators,
        &env.jj_base,
        &env.jj_receiver_pks,
        &xy,
        rng,
    );
    let z_enc = encrypt_all(
        &env.jj_generators,
        &env.jj_base,
        &env.jj_receiver_pks,
        &z,
        rng,
    );

    // pk contributions: c1=g1^{x1}g2^{x2}, c2=g1^{y1}g2^{y2}, c3=g1^{z}.
    let c1 = (env.jj_generators.g1.mul(xy_secrets.x1.into_repr())
        + env.jj_generators.g2.mul(xy_secrets.x2.into_repr()))
    .into_affine();
    let c2 = (env.jj_generators.g1.mul(xy_secrets.y1.into_repr())
        + env.jj_generators.g2.mul(xy_secrets.y2.into_repr()))
    .into_affine();
    let c3 = env
        .jj_generators
        .g1
        .mul(z_secrets.x1.into_repr())
        .into_affine();

    KalaiContribution {
        xy_commitments: xy.commitments.clone(),
        xy_enc,
        xy_openings: xy.shares,
        z_commitments: z.commitments.clone(),
        z_enc,
        z_openings: z.shares,
        c1,
        c2,
        c3,
    }
}

fn encrypt_all<C: ProjectiveCurve>(
    generators: &PedersenGenerators<C>,
    base: &ElGamalBase<C>,
    receiver_pks: &[C::Affine],
    dist: &PedersenDistribution<C>,
    rng: &mut ChaCha20Rng,
) -> Vec<EncryptedPedersenShare<C>> {
    (0..dist.shares.len())
        .map(|j| {
            EncryptedPedersenShare::encrypt(
                generators,
                base,
                &receiver_pks[j],
                &dist.shares[j],
                rng,
            )
        })
        .collect()
}

fn run_kalai(
    env: &Env,
    latency: Duration,
    rng: &mut ChaCha20Rng,
) -> (Compute, Outcome, Vec<NetRow>) {
    let n = env.n;

    // ---- Deal every dealer's six-value contribution. ----
    let mut contributions: Vec<KalaiContribution> = Vec::with_capacity(n);
    for i in 0..n {
        contributions.push(deal_kalai(env, env.malice.get(&i).copied(), rng));
    }

    // ---- Verification: each receiver checks both equations, files complaints. ----
    let mut complaints_xy: Vec<Complaint> = vec![];
    let mut complaints_z: Vec<Complaint> = vec![];
    for (dealer, contribution) in contributions.iter().enumerate() {
        for j in 0..n {
            let sk = env.jj_elgamal[j].sk;
            if contribution.xy_enc[j]
                .decrypt(sk)
                .verify(&contribution.xy_commitments, j + 1)
                .is_err()
            {
                complaints_xy.push(Complaint {
                    dealer,
                    complainer: j + 1,
                });
            }
            if contribution.z_enc[j]
                .decrypt(sk)
                .verify(&contribution.z_commitments, j + 1)
                .is_err()
            {
                complaints_z.push(Complaint {
                    dealer,
                    complainer: j + 1,
                });
            }
        }
    }
    let complaints = complaints_xy.len() + complaints_z.len();

    // ---- Complaint management. z and xy are both resolved by disputation;
    // there is no Qagg short-circuit in Kalai, so it is empty for both runs. ----
    let all_dealers: BTreeSet<usize> = (0..n).collect();
    let empty_qagg = BTreeSet::new();
    let (mut xy_cms, mut xy_ops) = (BTreeMap::new(), BTreeMap::new());
    let (mut z_cms, mut z_ops) = (BTreeMap::new(), BTreeMap::new());
    for (id, contribution) in contributions.iter().enumerate() {
        xy_cms.insert(id, contribution.xy_commitments.clone());
        xy_ops.insert(id, contribution.xy_openings.clone());
        z_cms.insert(id, contribution.z_commitments.clone());
        z_ops.insert(id, contribution.z_openings.clone());
    }
    let neutral_count = env.neutral_count();
    let resolve = |rng: &mut ChaCha20Rng| -> BTreeSet<usize> {
        let mut disq = BTreeSet::new();
        let out_xy = run_complaint_phase(
            &env.jj_generators,
            env.degree,
            &all_dealers,
            &empty_qagg,
            &xy_cms,
            &xy_ops,
            &complaints_xy,
            neutral_count,
            rng,
        )
        .expect("xy complaint phase");
        let out_z = run_complaint_phase(
            &env.jj_generators,
            env.degree,
            &all_dealers,
            &empty_qagg,
            &z_cms,
            &z_ops,
            &complaints_z,
            neutral_count,
            rng,
        )
        .expect("z complaint phase");
        for d in out_xy.disqualified.keys().chain(out_z.disqualified.keys()) {
            disq.insert(*d);
        }
        disq
    };

    let disqualified = resolve(rng);
    let qual: BTreeSet<usize> = all_dealers.difference(&disqualified).copied().collect();

    // ---- Key generation + reconstruction. ----
    let reconstructed_ok = kalai_reconstruct_ok(env, &contributions, &qual);

    // ---- Timings. ----
    let samples = env.samples;
    let deal = best_of(samples, || {
        deal_kalai(env, None, rng);
    });
    let verify = best_of(samples, || {
        // Per-node work: receiver 0 checks both equations for all n dealers.
        let sk = env.jj_elgamal[0].sk;
        for contribution in contributions.iter() {
            let _ = contribution.xy_enc[0]
                .decrypt(sk)
                .verify(&contribution.xy_commitments, 1);
            let _ = contribution.z_enc[0]
                .decrypt(sk)
                .verify(&contribution.z_commitments, 1);
        }
    });
    let complaint = best_of(samples, || {
        resolve(rng);
    });
    let keygen = best_of(samples, || {
        kalai_reconstruct_ok(env, &contributions, &qual);
    });

    let compute = Compute {
        deal_ms: ms(deal),
        verify_ms: ms(verify),
        complaint_ms: ms(complaint),
        keygen_ms: ms(keygen),
    };
    let outcome = Outcome {
        complaints,
        qual: qual.len(),
        faulty: BTreeSet::new(), // nothing is caught by public verification here
        reconstructed_ok,
    };

    // Kalai broadcasts all shares all-to-all (bandwidth-bound, O(n^2) volume).
    let payload = kalai_payload(&contributions[0]);
    let net = run_broadcast_round(n, latency, payload);
    let rows = vec![NetRow {
        pattern: "broadcast",
        wall_ms: ms(net.wall),
        messages: net.messages,
        bytes: net.bytes,
        rounds: net.rounds,
    }];

    (compute, outcome, rows)
}

fn kalai_payload(contribution: &KalaiContribution) -> usize {
    let mut total = 0usize;
    for cm in contribution
        .xy_commitments
        .iter()
        .chain(contribution.z_commitments.iter())
    {
        total += cm.serialized_size();
    }
    for ct in contribution.xy_enc.iter().chain(contribution.z_enc.iter()) {
        total += ct.serialized_size();
    }
    total += contribution.c1.serialized_size()
        + contribution.c2.serialized_size()
        + contribution.c3.serialized_size();
    total
}

fn kalai_reconstruct_ok(
    env: &Env,
    contributions: &[KalaiContribution],
    qual: &BTreeSet<usize>,
) -> Option<bool> {
    if qual.is_empty() || env.degree + 1 > env.n {
        return None;
    }
    // Directly-aggregated pk over QUAL.
    let (mut a1, mut a2, mut a3) = (J::zero(), J::zero(), J::zero());
    for &id in qual.iter() {
        a1 += contributions[id].c1.into_projective();
        a2 += contributions[id].c2.into_projective();
        a3 += contributions[id].c3.into_projective();
    }
    let (agg1, agg2, agg3) = (a1.into_affine(), a2.into_affine(), a3.into_affine());

    // Per-receiver aggregated group-element messages over QUAL.
    let mut xy_msgs = Vec::with_capacity(env.n);
    let mut z_mf = Vec::with_capacity(env.n);
    for j in 0..env.n {
        let sk = env.jj_elgamal[j].sk;
        let (mut mf, mut mg, mut zf) = (J::zero(), J::zero(), J::zero());
        for &id in qual.iter() {
            let rec_xy = contributions[id].xy_enc[j].decrypt(sk);
            mf += rec_xy.m_sf.into_projective();
            mg += rec_xy.m_sg.into_projective();
            zf += contributions[id].z_enc[j]
                .decrypt(sk)
                .m_sf
                .into_projective();
        }
        xy_msgs.push((j + 1, mf.into_affine(), mg.into_affine()));
        z_mf.push((j + 1, zf.into_affine()));
    }
    let subset = &xy_msgs[..env.degree + 1];
    let (c1, c2) = reconstruct_pk_components::<J>(subset).ok()?;

    // c3 = g1^{z}: the z carrier pins z at the special point -1, so lambda1
    // recovers it from the g1^{sf} messages.
    let indices: Vec<JFr> = z_mf[..env.degree + 1]
        .iter()
        .map(|(j, _)| MSSPolynomial::<JFr>::point(*j as i64))
        .collect();
    let lambda1 = MSSPolynomial::<JFr>::lambda1(&indices).ok()?;
    let mut c3 = J::zero();
    for (lambda, (_, mf)) in lambda1.iter().zip(z_mf.iter()) {
        c3 += mf.mul(lambda.into_repr());
    }

    Some(c1 == agg1 && c2 == agg2 && c3.into_affine() == agg3)
}

// ----------------------------------------------------------------------------
// BTSOF (Ma, Xu & Li, ICICS 2020): the original five-secret DMKG, Fig 3/4.
//
// Structurally the same Pedersen-VSS + Franklin-Yung MSS protocol as `kalai2022`:
// (x1,x2,y1,y2) ride one four-generator carrier, z rides its own, every failure
// is resolved by the disputation-based complaint phase, and nothing is aggregated
// (so there is no Qagg short-circuit). The faithful difference from the
// `kalai2022` baseline is the z carrier: Fig 3 commits z with only TWO generators
// (cm_k = g1^{a''_k} h1^{b''_k}) under a single masking polynomial, so each z
// commitment is a 2-base MSM and each receiver gets two encrypted z components
// rather than four. `kalai2022` deliberately over-counts z with the
// four-generator carrier as a conservative upper bound; `btsof` measures the
// paper's actual cost.
// ----------------------------------------------------------------------------

/// A faithful BTSOF z carrier (Fig 3): z is pinned at the special point -1 of a
/// degree-t MSS polynomial `h` (the -2 slot carries a throwaway), masked by `h'`,
/// and committed with two generators only.
struct BtsofZCarrier {
    /// cm_k = g1^{h_k} * h1^{h'_k}, a 2-base MSM (k in [0,t]).
    commitments: Vec<JAffine>,
    /// Per receiver: (Enc g1^{sf}, Enc h1^{sf'}) - two ciphertexts, not four.
    enc: Vec<(ElGamalCiphertext<J>, ElGamalCiphertext<J>)>,
    /// Cleartext openings (sf, sf', with sg=sg'=0) fed to the complaint phase,
    /// whose 4-generator disputation cancels the unused g2/h2 terms.
    openings: Vec<PedersenShare<J>>,
    z: JFr,
}

fn deal_btsof_z(env: &Env, malicious: bool, rng: &mut ChaCha20Rng) -> BtsofZCarrier {
    let n = env.n;
    let g1 = env.jj_generators.g1;
    let h1 = env.jj_generators.h1;

    let z = JFr::rand(rng);
    let throwaway = JFr::rand(rng);
    let h = MSSPolynomial::<JFr>::sample(env.degree, z, throwaway, rng).expect("z poly");
    let beta = JFr::rand(rng);
    let beta_prime = JFr::rand(rng);
    let h_prime = MSSPolynomial::<JFr>::sample(env.degree, beta, beta_prime, rng).expect("z mask");

    let commitments = (0..=env.degree)
        .map(|k| {
            (g1.mul(h.coeffs[k].into_repr()) + h1.mul(h_prime.coeffs[k].into_repr())).into_affine()
        })
        .collect::<Vec<_>>();

    let sf = h.shares(n);
    let sf_prime = h_prime.shares(n);
    let mut openings = (0..n)
        .map(|i| PedersenShare::<J> {
            sf: sf[i],
            sf_prime: sf_prime[i],
            sg: JFr::zero(),
            sg_prime: JFr::zero(),
        })
        .collect::<Vec<_>>();

    // z-layer fault: corrupt one receiver's share before encryption, so it fails
    // the receiver's check and the dealer loses the disputation.
    if malicious {
        openings[0].sf += JFr::rand(rng);
    }

    let enc = (0..n)
        .map(|j| {
            let m_sf = g1.mul(openings[j].sf.into_repr()).into_affine();
            let m_sf_prime = h1.mul(openings[j].sf_prime.into_repr()).into_affine();
            (
                ElGamalCiphertext::encrypt(&env.jj_base, &env.jj_receiver_pks[j], m_sf, rng),
                ElGamalCiphertext::encrypt(&env.jj_base, &env.jj_receiver_pks[j], m_sf_prime, rng),
            )
        })
        .collect::<Vec<_>>();

    BtsofZCarrier {
        commitments,
        enc,
        openings,
        z,
    }
}

/// Receiver-side 2-generator check of the z share: g1^{sf}*h1^{sf'} == prod cm_k^{j^k}.
fn verify_btsof_z(commitments: &[JAffine], j: usize, m_sf: JAffine, m_sf_prime: JAffine) -> bool {
    let j_fr = JFr::from(j as u64);
    let lhs = m_sf.into_projective() + m_sf_prime.into_projective();
    let mut rhs = J::zero();
    let mut power = JFr::one();
    for cm in commitments.iter() {
        rhs += cm.mul(power.into_repr());
        power *= j_fr;
    }
    lhs == rhs
}

/// One dealer's full BTSOF contribution: the four-generator (x1,x2,y1,y2) carrier
/// (identical to `kalai2022`) plus the faithful two-generator z carrier.
struct BtsofContribution {
    xy_commitments: Vec<JAffine>,
    xy_enc: Vec<EncryptedPedersenShare<J>>,
    xy_openings: Vec<PedersenShare<J>>,
    z: BtsofZCarrier,
    c1: JAffine,
    c2: JAffine,
    c3: JAffine,
}

fn deal_btsof(env: &Env, malice: Option<Layer>, rng: &mut ChaCha20Rng) -> BtsofContribution {
    let n = env.n;
    let (mut xy, xy_secrets) =
        PedersenDistribution::deal(&env.jj_generators, env.degree, n, rng).expect("xy deal");
    if let Some(Layer::Xy) = malice {
        xy.shares[0].sf += JFr::rand(rng);
    }
    let xy_enc = encrypt_all(
        &env.jj_generators,
        &env.jj_base,
        &env.jj_receiver_pks,
        &xy,
        rng,
    );

    let z = deal_btsof_z(env, matches!(malice, Some(Layer::Z)), rng);

    let c1 = (env.jj_generators.g1.mul(xy_secrets.x1.into_repr())
        + env.jj_generators.g2.mul(xy_secrets.x2.into_repr()))
    .into_affine();
    let c2 = (env.jj_generators.g1.mul(xy_secrets.y1.into_repr())
        + env.jj_generators.g2.mul(xy_secrets.y2.into_repr()))
    .into_affine();
    let c3 = env.jj_generators.g1.mul(z.z.into_repr()).into_affine();

    BtsofContribution {
        xy_commitments: xy.commitments,
        xy_enc,
        xy_openings: xy.shares,
        z,
        c1,
        c2,
        c3,
    }
}

fn btsof_payload(contribution: &BtsofContribution) -> usize {
    let mut total = 0usize;
    for cm in contribution
        .xy_commitments
        .iter()
        .chain(contribution.z.commitments.iter())
    {
        total += cm.serialized_size();
    }
    for ct in contribution.xy_enc.iter() {
        total += ct.serialized_size();
    }
    for (a, b) in contribution.z.enc.iter() {
        total += a.serialized_size() + b.serialized_size();
    }
    total += contribution.c1.serialized_size()
        + contribution.c2.serialized_size()
        + contribution.c3.serialized_size();
    total
}

fn btsof_reconstruct_ok(
    env: &Env,
    contributions: &[BtsofContribution],
    qual: &BTreeSet<usize>,
) -> Option<bool> {
    if qual.is_empty() || env.degree + 1 > env.n {
        return None;
    }
    let (mut a1, mut a2, mut a3) = (J::zero(), J::zero(), J::zero());
    for &id in qual.iter() {
        a1 += contributions[id].c1.into_projective();
        a2 += contributions[id].c2.into_projective();
        a3 += contributions[id].c3.into_projective();
    }
    let (agg1, agg2, agg3) = (a1.into_affine(), a2.into_affine(), a3.into_affine());

    let mut xy_msgs = Vec::with_capacity(env.n);
    let mut z_mf = Vec::with_capacity(env.n);
    for j in 0..env.n {
        let sk = env.jj_elgamal[j].sk;
        let (mut mf, mut mg, mut zf) = (J::zero(), J::zero(), J::zero());
        for &id in qual.iter() {
            let rec = contributions[id].xy_enc[j].decrypt(sk);
            mf += rec.m_sf.into_projective();
            mg += rec.m_sg.into_projective();
            zf += contributions[id].z.enc[j].0.decrypt(sk).into_projective();
        }
        xy_msgs.push((j + 1, mf.into_affine(), mg.into_affine()));
        z_mf.push((j + 1, zf.into_affine()));
    }
    let subset = &xy_msgs[..env.degree + 1];
    let (c1, c2) = reconstruct_pk_components::<J>(subset).ok()?;

    // c3 = g1^{z}: z is pinned at the special point -1, so lambda1 recovers it
    // from the g1^{sf} messages in the exponent.
    let indices: Vec<JFr> = z_mf[..env.degree + 1]
        .iter()
        .map(|(j, _)| MSSPolynomial::<JFr>::point(*j as i64))
        .collect();
    let lambda1 = MSSPolynomial::<JFr>::lambda1(&indices).ok()?;
    let mut c3 = J::zero();
    for (lambda, (_, mf)) in lambda1.iter().zip(z_mf.iter()) {
        c3 += mf.mul(lambda.into_repr());
    }

    Some(c1 == agg1 && c2 == agg2 && c3.into_affine() == agg3)
}

fn run_btsof(
    env: &Env,
    latency: Duration,
    rng: &mut ChaCha20Rng,
) -> (Compute, Outcome, Vec<NetRow>) {
    let n = env.n;

    // ---- Deal every dealer's contribution. ----
    let mut contributions: Vec<BtsofContribution> = Vec::with_capacity(n);
    for i in 0..n {
        contributions.push(deal_btsof(env, env.malice.get(&i).copied(), rng));
    }

    // ---- Verification: each receiver checks xy (4-gen) and z (2-gen). ----
    let mut complaints_xy: Vec<Complaint> = vec![];
    let mut complaints_z: Vec<Complaint> = vec![];
    for (dealer, contribution) in contributions.iter().enumerate() {
        for j in 0..n {
            let sk = env.jj_elgamal[j].sk;
            if contribution.xy_enc[j]
                .decrypt(sk)
                .verify(&contribution.xy_commitments, j + 1)
                .is_err()
            {
                complaints_xy.push(Complaint {
                    dealer,
                    complainer: j + 1,
                });
            }
            let m_sf = contribution.z.enc[j].0.decrypt(sk);
            let m_sf_prime = contribution.z.enc[j].1.decrypt(sk);
            if !verify_btsof_z(&contribution.z.commitments, j + 1, m_sf, m_sf_prime) {
                complaints_z.push(Complaint {
                    dealer,
                    complainer: j + 1,
                });
            }
        }
    }
    let complaints = complaints_xy.len() + complaints_z.len();

    // ---- Complaint management. No Qagg short-circuit (z is not aggregatable). ----
    let all_dealers: BTreeSet<usize> = (0..n).collect();
    let empty_qagg = BTreeSet::new();
    let (mut xy_cms, mut xy_ops) = (BTreeMap::new(), BTreeMap::new());
    let (mut z_cms, mut z_ops) = (BTreeMap::new(), BTreeMap::new());
    for (id, contribution) in contributions.iter().enumerate() {
        xy_cms.insert(id, contribution.xy_commitments.clone());
        xy_ops.insert(id, contribution.xy_openings.clone());
        z_cms.insert(id, contribution.z.commitments.clone());
        z_ops.insert(id, contribution.z.openings.clone());
    }
    let neutral_count = env.neutral_count();
    let resolve = |rng: &mut ChaCha20Rng| -> BTreeSet<usize> {
        let mut disq = BTreeSet::new();
        let out_xy = run_complaint_phase(
            &env.jj_generators,
            env.degree,
            &all_dealers,
            &empty_qagg,
            &xy_cms,
            &xy_ops,
            &complaints_xy,
            neutral_count,
            rng,
        )
        .expect("xy complaint phase");
        let out_z = run_complaint_phase(
            &env.jj_generators,
            env.degree,
            &all_dealers,
            &empty_qagg,
            &z_cms,
            &z_ops,
            &complaints_z,
            neutral_count,
            rng,
        )
        .expect("z complaint phase");
        for d in out_xy.disqualified.keys().chain(out_z.disqualified.keys()) {
            disq.insert(*d);
        }
        disq
    };

    let disqualified = resolve(rng);
    let qual: BTreeSet<usize> = all_dealers.difference(&disqualified).copied().collect();

    // ---- Key generation + reconstruction. ----
    let reconstructed_ok = btsof_reconstruct_ok(env, &contributions, &qual);

    // ---- Timings. ----
    let samples = env.samples;
    let deal = best_of(samples, || {
        deal_btsof(env, None, rng);
    });
    let verify = best_of(samples, || {
        let sk = env.jj_elgamal[0].sk;
        for contribution in contributions.iter() {
            let _ = contribution.xy_enc[0]
                .decrypt(sk)
                .verify(&contribution.xy_commitments, 1);
            let m_sf = contribution.z.enc[0].0.decrypt(sk);
            let m_sf_prime = contribution.z.enc[0].1.decrypt(sk);
            let _ = verify_btsof_z(&contribution.z.commitments, 1, m_sf, m_sf_prime);
        }
    });
    let complaint = best_of(samples, || {
        resolve(rng);
    });
    let keygen = best_of(samples, || {
        btsof_reconstruct_ok(env, &contributions, &qual);
    });

    let compute = Compute {
        deal_ms: ms(deal),
        verify_ms: ms(verify),
        complaint_ms: ms(complaint),
        keygen_ms: ms(keygen),
    };
    let outcome = Outcome {
        complaints,
        qual: qual.len(),
        faulty: BTreeSet::new(), // nothing is caught by public verification here
        reconstructed_ok,
    };

    // BTSOF broadcasts all shares all-to-all (bandwidth-bound, O(n^2) volume).
    let payload = btsof_payload(&contributions[0]);
    let net = run_broadcast_round(n, latency, payload);
    let rows = vec![NetRow {
        pattern: "broadcast",
        wall_ms: ms(net.wall),
        messages: net.messages,
        bytes: net.bytes,
        rounds: net.rounds,
    }];

    (compute, outcome, rows)
}

// ----------------------------------------------------------------------------
// Neji (Wafa Neji thesis): single-secret Feldman-VSS DKG with disputation.
//
// The one-secret ancestor of the Pedersen DMKGs: one secret per dealer committed
// with Feldman commitments (single generator g^{a_k}), encrypted shares on public
// channels, and the disputation-based complaint phase (no Qagg, no z/xy split).
// pk = h^{sk} with sk = sum of honest dealers' secrets. The `--malicious` layer
// tag is ignored (there is only one layer); any flagged dealer deals one bad share.
// ----------------------------------------------------------------------------

struct NejiContribution {
    commitments: Vec<JAffine>,
    /// One ElGamal ciphertext of g^{s_j} per receiver.
    enc: Vec<ElGamalCiphertext<J>>,
    /// Cleartext shares s_j, opened during a disputation.
    openings: Vec<JFr>,
    /// pk contribution h^{s_i}.
    pk_contrib: JAffine,
    /// g^{s_i} = commitments[0], the public commitment to the dealer's secret.
    c0: JAffine,
}

fn deal_neji(
    env: &Env,
    gens: &NejiGenerators<J>,
    malicious: bool,
    rng: &mut ChaCha20Rng,
) -> NejiContribution {
    let n = env.n;
    let (dist, secrets) =
        FeldmanDistribution::deal(gens, env.degree, n, rng).expect("feldman deal");
    let mut openings = dist.shares.clone();
    if malicious {
        openings[0] += JFr::rand(rng); // one bad share to receiver 1
    }
    let enc = (0..n)
        .map(|j| {
            neji::encrypt_share(
                gens,
                &env.jj_base,
                &env.jj_receiver_pks[j],
                openings[j],
                rng,
            )
        })
        .collect::<Vec<_>>();
    let pk_contrib = gens.h.mul(secrets.secret.into_repr()).into_affine();
    NejiContribution {
        c0: dist.commitments[0],
        commitments: dist.commitments,
        enc,
        openings,
        pk_contrib,
    }
}

fn neji_payload(contribution: &NejiContribution) -> usize {
    let mut total = 0usize;
    for cm in contribution.commitments.iter() {
        total += cm.serialized_size();
    }
    for ct in contribution.enc.iter() {
        total += ct.serialized_size();
    }
    total += contribution.pk_contrib.serialized_size() + contribution.c0.serialized_size();
    total
}

fn neji_reconstruct_ok(
    env: &Env,
    contributions: &[NejiContribution],
    qual: &BTreeSet<usize>,
) -> Option<bool> {
    if qual.is_empty() || env.degree + 1 > env.n {
        return None;
    }
    // Directly-aggregated g^{sk} = prod over QUAL of g^{s_i}.
    let mut agg = J::zero();
    for &id in qual.iter() {
        agg += contributions[id].c0.into_projective();
    }
    // Per-receiver aggregated group-element share g^{S_j} over QUAL.
    let mut pts = Vec::with_capacity(env.n);
    for j in 0..env.n {
        let sk = env.jj_elgamal[j].sk;
        let mut m = J::zero();
        for &id in qual.iter() {
            m += contributions[id].enc[j].decrypt(sk).into_projective();
        }
        pts.push((j + 1, m.into_affine()));
    }
    let subset = &pts[..env.degree + 1];
    let indices: Vec<JFr> = subset.iter().map(|(j, _)| JFr::from(*j as u64)).collect();
    let lambdas = ShamirPolynomial::<JFr>::lambda_at_zero(&indices).ok()?;
    let mut recon = J::zero();
    for (lambda, (_, m)) in lambdas.iter().zip(subset.iter()) {
        recon += m.mul(lambda.into_repr());
    }
    Some(recon.into_affine() == agg.into_affine())
}

fn run_neji(
    env: &Env,
    latency: Duration,
    rng: &mut ChaCha20Rng,
) -> (Compute, Outcome, Vec<NetRow>) {
    let n = env.n;
    let gens = &env.jj_neji;

    // ---- Deal every dealer's single-secret Feldman contribution. ----
    let mut contributions: Vec<NejiContribution> = Vec::with_capacity(n);
    for i in 0..n {
        contributions.push(deal_neji(env, &gens, env.malice.contains_key(&i), rng));
    }

    // ---- Verification: each receiver decrypts g^{s} and checks Feldman. ----
    let mut complaints: Vec<NejiComplaint> = vec![];
    for (dealer, contribution) in contributions.iter().enumerate() {
        for j in 0..n {
            let m = contribution.enc[j].decrypt(env.jj_elgamal[j].sk);
            if !FeldmanDistribution::<J>::verify_in_exponent(&contribution.commitments, j + 1, m) {
                complaints.push(NejiComplaint {
                    dealer,
                    complainer: j + 1,
                });
            }
        }
    }
    let complaint_count = complaints.len();

    // ---- Complaint management: disputation only (no Qagg). ----
    let all_dealers: BTreeSet<usize> = (0..n).collect();
    let (mut cms, mut ops) = (BTreeMap::new(), BTreeMap::new());
    for (id, contribution) in contributions.iter().enumerate() {
        cms.insert(id, contribution.commitments.clone());
        ops.insert(id, contribution.openings.clone());
    }
    let neutral_count = env.neutral_count();
    let resolve = |rng: &mut ChaCha20Rng| -> BTreeSet<usize> {
        neji::run_complaint_phase(
            &gens,
            env.degree,
            &all_dealers,
            &cms,
            &ops,
            &complaints,
            neutral_count,
            rng,
        )
        .expect("neji complaint phase")
        .disqualified
        .keys()
        .copied()
        .collect()
    };
    let disqualified = resolve(rng);
    let qual: BTreeSet<usize> = all_dealers.difference(&disqualified).copied().collect();

    // ---- Key generation + reconstruction. ----
    let reconstructed_ok = neji_reconstruct_ok(env, &contributions, &qual);

    // ---- Timings. ----
    let samples = env.samples;
    let deal = best_of(samples, || {
        deal_neji(env, &gens, false, rng);
    });
    let verify = best_of(samples, || {
        for contribution in contributions.iter() {
            let m = contribution.enc[0].decrypt(env.jj_elgamal[0].sk);
            let _ = FeldmanDistribution::<J>::verify_in_exponent(&contribution.commitments, 1, m);
        }
    });
    let complaint = best_of(samples, || {
        resolve(rng);
    });
    let keygen = best_of(samples, || {
        neji_reconstruct_ok(env, &contributions, &qual);
    });

    let compute = Compute {
        deal_ms: ms(deal),
        verify_ms: ms(verify),
        complaint_ms: ms(complaint),
        keygen_ms: ms(keygen),
    };
    let outcome = Outcome {
        complaints: complaint_count,
        qual: qual.len(),
        faulty: BTreeSet::new(),
        reconstructed_ok,
    };

    // Neji broadcasts all (encrypted) shares all-to-all.
    let payload = neji_payload(&contributions[0]);
    let net = run_broadcast_round(n, latency, payload);
    let rows = vec![NetRow {
        pattern: "broadcast",
        wall_ms: ms(net.wall),
        messages: net.messages,
        bytes: net.bytes,
        rounds: net.rounds,
    }];

    (compute, outcome, rows)
}

// ----------------------------------------------------------------------------
// Aggregatable 2025: z the Gurkan way, (x1,x2,y1,y2) the Kalai way, Qagg handoff.
// ----------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
fn build_2025_contributions(
    env: &Env,
    rng: &mut ChaCha20Rng,
) -> (
    BTreeMap<usize, DMKGContribution<E, SPOK, SSIG>>,
    BTreeMap<usize, PedersenDistribution<G1>>,
) {
    let n = env.n;
    let mut contributions = BTreeMap::new();
    let mut distributions = BTreeMap::new();
    for i in 0..n {
        // Inline the z dealing so an xy-cheater can corrupt the cleartext share
        // BEFORE encryption (dmkg::deal encrypts internally).
        let mut node = env.build_node(i);
        let (pvss_share, pvss_secrets) = node.share_pvss(rng).expect("pvss");
        let z_i = pvss_secrets.f_0;
        let c_i = env.config.srs.g_g1.mul(z_i.into_repr()).into_affine();
        let msg = message_from_c_i::<E>(c_i).expect("msg");
        let pok_keypair = env.scheme_pok.from_sk(&z_i).expect("pok key");
        let c_i_pok = env.scheme_pok.sign(rng, &pok_keypair.0, &msg).expect("pok");
        let sig_keypair = env.scheme_sig.from_sk(&env.sig_sk[i]).expect("sig key");
        let signature_on_c_i = env.scheme_sig.sign(rng, &sig_keypair.0, &msg).expect("sig");
        let mut dkg_share = DKGShare {
            participant_id: i,
            c_i,
            pvss_share,
            c_i_pok,
            signature_on_c_i,
        };

        let (mut distribution, secrets) =
            PedersenDistribution::deal(&env.generators, env.degree, n, rng).expect("ped deal");

        let victim = (i + 1) % n;
        match env.malice.get(&i).copied() {
            Some(Layer::Z) => dkg_share.c_i = G1Projective::rand(rng).into_affine(),
            Some(Layer::Xy) => distribution.shares[victim].sf += Fr::rand(rng),
            None => {}
        }

        let encrypted_shares = encrypt_all(
            &env.generators,
            &env.base,
            &env.receiver_pks,
            &distribution,
            rng,
        );
        let c1_i = (env.generators.g1.mul(secrets.x1.into_repr())
            + env.generators.g2.mul(secrets.x2.into_repr()))
        .into_affine();
        let c2_i = (env.generators.g1.mul(secrets.y1.into_repr())
            + env.generators.g2.mul(secrets.y2.into_repr()))
        .into_affine();
        let c3_i = env.generators.g1.mul(z_i.into_repr()).into_affine();

        contributions.insert(
            i,
            DMKGContribution {
                dealer_id: i,
                dkg_share,
                commitments: distribution.commitments.clone(),
                encrypted_shares,
                c1_i,
                c2_i,
                c3_i,
            },
        );
        distributions.insert(i, distribution);
    }
    (contributions, distributions)
}

fn run_2025(
    env: &Env,
    latency: Duration,
    rng: &mut ChaCha20Rng,
) -> (Compute, Outcome, Vec<NetRow>) {
    let n = env.n;
    let (contributions, distributions) = build_2025_contributions(env, rng);

    // ---- z verification + aggregation builds Qagg and the folded transcript. ----
    let mut aggregator = env.build_node(0).aggregator;
    for i in 0..n {
        let _ = aggregator.receive_share(rng, &contributions[&i].dkg_share);
    }
    let qagg = aggregator.qagg.clone();
    let transcript = aggregator.transcript.clone();

    // ---- Pedersen verification: receivers decrypt + check Eq. (1), complain. ----
    let mut complaints: Vec<Complaint> = vec![];
    for (&dealer, contribution) in contributions.iter() {
        for j in 0..n {
            if contribution.encrypted_shares[j]
                .decrypt(env.elgamal[j].sk)
                .verify(&contribution.commitments, j + 1)
                .is_err()
            {
                complaints.push(Complaint {
                    dealer,
                    complainer: j + 1,
                });
            }
        }
    }
    let complaint_count = complaints.len();

    // ---- Complaint management: Qagg short-circuits the z-cheaters. ----
    let all_dealers: BTreeSet<usize> = (0..n).collect();
    let (mut cms, mut ops) = (BTreeMap::new(), BTreeMap::new());
    for (&id, contribution) in contributions.iter() {
        cms.insert(id, contribution.commitments.clone());
        ops.insert(id, distributions[&id].shares.clone());
    }
    let neutral_count = env.neutral_count();
    let resolve = |rng: &mut ChaCha20Rng| -> BTreeSet<usize> {
        let outcome = run_complaint_phase(
            &env.generators,
            env.degree,
            &all_dealers,
            &qagg,
            &cms,
            &ops,
            &complaints,
            neutral_count,
            rng,
        )
        .expect("complaint phase");
        let mut disq: BTreeSet<usize> = outcome.disqualified.keys().copied().collect();
        for &m in qagg.iter() {
            disq.insert(m);
        }
        disq
    };
    let disqualified = resolve(rng);
    let qual: BTreeSet<usize> = all_dealers.difference(&disqualified).copied().collect();

    // ---- Key generation + reconstruction of (c1,c2). ----
    let pk = aggregate_public_key(&contributions, &qual);
    let reconstructed_ok = reconstruct_2025_ok(env, &contributions, &qual, &pk);

    // ---- Timings. ----
    let samples = env.samples;
    let deal = best_of(samples, || {
        let mut dealer = DMKGDealer {
            node: env.build_node(0),
            elgamal: env.elgamal[0].clone(),
        };
        dmkg::deal(
            &mut dealer,
            &env.generators,
            &env.base,
            &env.receiver_pks,
            rng,
        )
        .expect("deal");
    });
    let verify = best_of(samples, || {
        // Per-node work: verify the ONE folded z transcript, then check every
        // dealer's Pedersen share addressed to this node.
        let mut node = env.build_node(0);
        let _ = node.receive_transcript_and_decrypt(rng, transcript.clone());
        for contribution in contributions.values() {
            let _ = contribution.encrypted_shares[0]
                .decrypt(env.elgamal[0].sk)
                .verify(&contribution.commitments, 1);
        }
    });
    let complaint = best_of(samples, || {
        resolve(rng);
    });
    let keygen = best_of(samples, || {
        let pk = aggregate_public_key(&contributions, &qual);
        reconstruct_2025_ok(env, &contributions, &qual, &pk);
    });

    let compute = Compute {
        deal_ms: ms(deal),
        verify_ms: ms(verify),
        complaint_ms: ms(complaint),
        keygen_ms: ms(keygen),
    };
    let outcome = Outcome {
        complaints: complaint_count,
        qual: qual.len(),
        faulty: qagg.clone(),
        reconstructed_ok,
    };

    // 2025 uses both patterns: tree gossip for z, all-to-all broadcast for xy.
    let z_payload = contributions[&0].dkg_share.serialized_size();
    let xy_payload = pedersen_payload(&contributions[&0]);
    let tree = run_tree_gossip(n, latency, z_payload);
    let bcast = run_broadcast_round(n, latency, xy_payload);
    let rows = vec![
        NetRow {
            pattern: "tree",
            wall_ms: ms(tree.wall),
            messages: tree.messages,
            bytes: tree.bytes,
            rounds: tree.rounds,
        },
        NetRow {
            pattern: "broadcast",
            wall_ms: ms(bcast.wall),
            messages: bcast.messages,
            bytes: bcast.bytes,
            rounds: bcast.rounds,
        },
    ];

    (compute, outcome, rows)
}

fn pedersen_payload(contribution: &DMKGContribution<E, SPOK, SSIG>) -> usize {
    let mut total = 0usize;
    for cm in contribution.commitments.iter() {
        total += cm.serialized_size();
    }
    for ct in contribution.encrypted_shares.iter() {
        total += ct.serialized_size();
    }
    total += contribution.c1_i.serialized_size()
        + contribution.c2_i.serialized_size()
        + contribution.c3_i.serialized_size();
    total
}

fn reconstruct_2025_ok(
    env: &Env,
    contributions: &BTreeMap<usize, DMKGContribution<E, SPOK, SSIG>>,
    qual: &BTreeSet<usize>,
    pk: &dmkg::PublicKey<E>,
) -> Option<bool> {
    if qual.is_empty() || env.degree + 1 > env.n {
        return None;
    }
    let mut receiver_msgs = Vec::with_capacity(env.n);
    for j in 0..env.n {
        let (mut mf, mut mg) = (G1Projective::zero(), G1Projective::zero());
        for &id in qual.iter() {
            let rec = contributions[&id].encrypted_shares[j].decrypt(env.elgamal[j].sk);
            mf += rec.m_sf.into_projective();
            mg += rec.m_sg.into_projective();
        }
        receiver_msgs.push((j + 1, mf.into_affine(), mg.into_affine()));
    }
    let subset = &receiver_msgs[..env.degree + 1];
    let (c1, c2) = reconstruct_pk_components::<G1>(subset).ok()?;
    Some(c1 == pk.c1 && c2 == pk.c2)
}

// ----------------------------------------------------------------------------
// CLI + CSV.
// ----------------------------------------------------------------------------

struct Args {
    protocol: Protocol,
    n: usize,
    threshold: usize,
    malicious_spec: String,
    latency_ms: u64,
    seed: u64,
    samples: usize,
    out: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut map: HashMap<String, String> = HashMap::new();
    let mut i = 0;
    while i < raw.len() {
        let key = &raw[i];
        if let Some(name) = key.strip_prefix("--") {
            let value = raw
                .get(i + 1)
                .ok_or_else(|| format!("missing value for --{}", name))?;
            map.insert(name.to_string(), value.clone());
            i += 2;
        } else {
            return Err(format!("unexpected argument '{}'", key));
        }
    }

    let protocol = Protocol::parse(map.get("protocol").ok_or("missing required --protocol")?)?;
    let n: usize = map
        .get("n")
        .ok_or("missing required --n")?
        .parse()
        .map_err(|_| "bad --n")?;
    if n < 2 {
        return Err("--n must be >= 2".to_string());
    }
    let threshold: usize = match map.get("threshold") {
        Some(s) => s.parse().map_err(|_| "bad --threshold")?,
        None => (n / 2).max(1), // paper bound: t-1 < n/2
    };
    if threshold < 1 || threshold >= n {
        return Err(format!(
            "--threshold (degree t) must satisfy 1 <= t < n (got t={}, n={})",
            threshold, n
        ));
    }
    let malicious_spec = map.get("malicious").cloned().unwrap_or_default();
    let latency_ms: u64 = match map.get("latency-ms") {
        Some(s) => s.parse().map_err(|_| "bad --latency-ms")?,
        None => 0,
    };
    let seed: u64 = match map.get("seed") {
        Some(s) => s.parse().map_err(|_| "bad --seed")?,
        None => 0,
    };
    let samples: usize = match map.get("samples") {
        Some(s) => s.parse().map_err(|_| "bad --samples")?,
        None => 10,
    };

    Ok(Args {
        protocol,
        n,
        threshold,
        malicious_spec,
        latency_ms,
        seed,
        samples: samples.max(1),
        out: map.get("out").cloned(),
    })
}

const CSV_HEADER: &str = "protocol,n,threshold,malicious_spec,latency_ms,seed,samples,deal_ms,verify_ms,complaint_ms,keygen_ms,pattern,wall_ms,messages,bytes,rounds,faulty,complaints,qual,reconstructed_ok,padded";

fn csv_row(args: &Args, c: &Compute, o: &Outcome, net: &NetRow, padded: bool) -> String {
    let faulty = o
        .faulty
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let recon = match o.reconstructed_ok {
        Some(true) => "true",
        Some(false) => "false",
        None => "na",
    };
    let spec = args.malicious_spec.trim();
    format!(
        "{},{},{},\"{}\",{},{},{},{:.4},{:.4},{:.4},{:.4},{},{:.4},{},{},{},\"{}\",{},{},{},{}",
        args.protocol.label(),
        args.n,
        args.threshold,
        if spec.is_empty() { "none" } else { spec },
        args.latency_ms,
        args.seed,
        args.samples,
        c.deal_ms,
        c.verify_ms,
        c.complaint_ms,
        c.keygen_ms,
        net.pattern,
        net.wall_ms,
        net.messages,
        net.bytes,
        net.rounds,
        faulty,
        o.complaints,
        o.qual,
        recon,
        padded,
    )
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            eprintln!(
                "usage: dmkg_bench --protocol <gurkan|neji|btsof|kalai2022|aggregatable2025> --n <usize> \
                 [--threshold <t>] [--malicious id:layer,...] [--latency-ms <ms>] \
                 [--seed <u64>] [--samples <usize>] [--out <path.csv>]"
            );
            std::process::exit(2);
        }
    };

    let malice = match parse_malicious(&args.malicious_spec, args.protocol) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(2);
        }
    };
    if let Some((&bad, _)) = malice.iter().find(|(&id, _)| id >= args.n) {
        eprintln!("error: malicious id {} out of range [0,{})", bad, args.n);
        std::process::exit(2);
    }

    // Warnings (not hard failures), so adversarial sweeps stay possible.
    if args.threshold.saturating_sub(1) >= args.n.div_ceil(2) {
        eprintln!(
            "warning: t-1={} is not < n/2={}; the paper's adversary bound is exceeded",
            args.threshold.saturating_sub(1),
            args.n / 2
        );
    }
    // Only the aggregatable protocols use the SCRAPE Radix2 domain for z, which
    // pads n up to a power of two; btsof and kalai2022 share z via Pedersen at
    // integer points and work for any n >= 2.
    let padded = args.n != args.n.next_power_of_two();
    let z_uses_scrape_domain =
        args.protocol == Protocol::Gurkan || args.protocol == Protocol::Aggregatable2025;
    if padded && z_uses_scrape_domain {
        eprintln!(
            "warning: n={} is not a power of two; the z layer pads to {} with throwaway keys",
            args.n,
            args.n.next_power_of_two()
        );
    }

    let mut rng = ChaCha20Rng::seed_from_u64(args.seed);
    let env = match Env::build(args.n, args.threshold, args.samples, malice, &mut rng) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: setup failed: {}", e);
            std::process::exit(1);
        }
    };

    let latency = Duration::from_millis(args.latency_ms);
    let (compute, outcome, rows) = match args.protocol {
        Protocol::Gurkan => run_gurkan(&env, latency, &mut rng),
        Protocol::Neji => run_neji(&env, latency, &mut rng),
        Protocol::Btsof => run_btsof(&env, latency, &mut rng),
        Protocol::Kalai2022 => run_kalai(&env, latency, &mut rng),
        Protocol::Aggregatable2025 => run_2025(&env, latency, &mut rng),
    };

    // Emit: header to stdout, one CSV row per network pattern.
    println!("{}", CSV_HEADER);
    let mut lines = vec![];
    for net in rows.iter() {
        let line = csv_row(&args, &compute, &outcome, net, padded);
        println!("{}", line);
        lines.push(line);
    }

    if let Some(path) = args.out.as_ref() {
        if let Err(e) = append_csv(path, &lines) {
            eprintln!("error: writing {}: {}", path, e);
            std::process::exit(1);
        }
    }
}

fn append_csv(path: &str, lines: &[String]) -> std::io::Result<()> {
    let needs_header = !Path::new(path).exists()
        || std::fs::metadata(path)
            .map(|m| m.len() == 0)
            .unwrap_or(true);
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if needs_header {
        writeln!(file, "{}", CSV_HEADER)?;
    }
    for line in lines {
        writeln!(file, "{}", line)?;
    }
    Ok(())
}
