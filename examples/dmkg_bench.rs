//! DMKG benchmark harness.
//!
//! Benchmarks the two layers separately, keeping computation and network timing
//! apart. Sweeps the number of participants over powers of two and the injected
//! WAN latency, and prints tables.
//!
//! Run: cargo run --release --features network --example dmkg_bench

use aggregatable_dkg::{
    dkg::{
        aggregator::DKGAggregator,
        config::Config,
        dealer::Dealer,
        dmkg::{self, DMKGContribution, DMKGDealer},
        encryption::{ElGamalBase, ElGamalKeypair, EncryptedPedersenShare},
        node::Node,
        participant::{Participant, ParticipantState},
        pedersen::PedersenDistribution,
        pedersen::PedersenGenerators,
        share::DKGTranscript,
        srs::SRS,
    },
    signature::{
        bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        scheme::SignatureScheme,
    },
};
use ark_bls12_381::{Bls12_381, G2Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

type E = Bls12_381;
type SPOK = BLSSignature<BLSSignatureG2<Bls12_381>>;
type SSIG = BLSSignature<BLSSignatureG1<Bls12_381>>;

/// Per-`n` verification timings kept for the Part B complexity comparison.
struct Metrics {
    n: usize,
    z_tx_verify: f64,
    z_verify1: f64,
    ped_verify1: f64,
}

/// Time `f`, returning the best of `iters` runs (steady-state, less noisy).
fn best_of<T, F: FnMut() -> T>(iters: usize, mut f: F) -> (Duration, T) {
    let mut best = Duration::from_secs(u64::MAX);
    let mut last = f();
    for _ in 0..iters {
        let start = Instant::now();
        last = f();
        let d = start.elapsed();
        if d < best {
            best = d;
        }
    }
    (best, last)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() {
    let rng = &mut thread_rng();
    let srs = SRS::<E>::setup(rng).unwrap();
    let bls_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
        srs: BLSSRS {
            g_public_key: srs.h_g2,
            g_signature: srs.g_g1,
        },
    };
    let bls_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
        srs: BLSSRS {
            g_public_key: srs.g_g1,
            g_signature: srs.h_g2,
        },
    };
    let generators = PedersenGenerators::<E>::setup().unwrap();
    let base = ElGamalBase::<E>::setup().unwrap();

    println!("# DMKG benchmark (BLS12-381, single thread for compute)\n");

    // ---------------------------------------------------------------
    // Part A - computation, swept over n (powers of two).
    // ---------------------------------------------------------------
    println!("## A. Computation (per-operation, milliseconds)\n");
    println!(
        "{:>5} {:>6} | {:>10} {:>12} | {:>10} {:>11} {:>13} | {:>10} {:>9}",
        "n",
        "t",
        "z_share",
        "z_tx_verify",
        "ped_deal",
        "ped_enc/n",
        "ped_verify/1",
        "complaint",
        "msg_KiB",
    );
    println!("{}", "-".repeat(110));

    let ns: &[usize] = &[2, 4, 8, 16, 32, 64, 128, 256];
    // Store per-n payload sizes for the network part.
    let mut payload_bytes: BTreeMap<usize, usize> = BTreeMap::new();
    // Per-n metrics retained for the Part B complexity comparison.
    let mut metrics: Vec<Metrics> = vec![];

    for &n in ns {
        let degree = (n / 2).max(1); // t = n/2 ⇒ t-1 < n/2
        let u_1 = G2Projective::rand(rng).into_affine();
        let dkg_config = Config {
            srs: srs.clone(),
            u_1,
            degree,
        };

        // Build participants + receiver ElGamal keys.
        let mut sig_keys = vec![];
        let mut elgamal = vec![];
        for _ in 0..n {
            sig_keys.push(bls_sig.generate_keypair(rng).unwrap());
            elgamal.push(ElGamalKeypair::<E>::generate(&base, rng));
        }
        let participants = (0..n)
            .map(|i| {
                (
                    i,
                    Participant::<E, SSIG> {
                        pairing_type: PhantomData,
                        id: i,
                        public_key_sig: sig_keys[i].1,
                        state: ParticipantState::Dealer,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let receiver_pks = elgamal.iter().map(|k| k.pk).collect::<Vec<_>>();

        let make_node = |i: usize| Node::<E, SPOK, SSIG> {
            aggregator: DKGAggregator {
                config: dkg_config.clone(),
                scheme_pok: bls_pok.clone(),
                scheme_sig: bls_sig.clone(),
                participants: participants.clone(),
                transcript: DKGTranscript::empty(degree, n),
                qagg: BTreeSet::new(),
            },
            dealer: Dealer {
                private_key_sig: sig_keys[i].0,
                accumulated_secret: G2Projective::zero().into_affine(),
                participant: participants[&i].clone(),
            },
        };

        // z layer: one dealer's PVSS share.
        let mut node0 = make_node(0);
        let (t_z_share, _share0) = best_of(3, || node0.share(rng).unwrap());

        // Build a full aggregated transcript across all n dealers (for tx verify).
        let mut agg = make_node(0).aggregator;
        let mut nodes: Vec<Node<E, SPOK, SSIG>> = (0..n).map(make_node).collect();
        for node in nodes.iter_mut() {
            let share = node.share(rng).unwrap();
            agg.receive_share(rng, &share).unwrap();
        }
        let transcript = agg.transcript.clone();
        // z AGGREGATED verification: each node verifies ONE transcript that already
        // folds in all n dealings - the partial-aggregatability win.
        let (t_z_tx_verify, _) = best_of(3, || {
            let mut node = make_node(0);
            node.receive_transcript_and_decrypt(rng, transcript.clone())
                .unwrap();
        });
        // z INDIVIDUAL verification: cost of verifying a single dealer's PVSS share
        // (what a node would pay per dealer WITHOUT aggregation).
        let one_share = make_node(1).share(rng).unwrap();
        let (t_z_verify1, _) = best_of(3, || {
            let mut a = make_node(0).aggregator;
            a.share_verify(rng, &one_share).unwrap();
        });

        // Pedersen layer: one dealer's distribution.
        let (t_ped_deal, (dist, _secrets)) = best_of(3, || {
            PedersenDistribution::deal(&generators, degree, n, rng).unwrap()
        });

        // Pedersen encryption of all n shares (per dealer), reported per-share.
        let (t_ped_enc_all, _) = best_of(3, || {
            (0..n)
                .map(|j| {
                    EncryptedPedersenShare::encrypt(
                        &generators,
                        &base,
                        &receiver_pks[j],
                        &dist.shares[j],
                        rng,
                    )
                })
                .collect::<Vec<_>>()
        });
        let t_ped_enc_per = t_ped_enc_all / (n as u32);

        // Pedersen verify + decrypt for one (dealer, receiver) pair.
        let ct0 = EncryptedPedersenShare::encrypt(
            &generators,
            &base,
            &receiver_pks[0],
            &dist.shares[0],
            rng,
        );
        let (t_ped_verify1, _) = best_of(5, || {
            let recovered = ct0.decrypt(elgamal[0].sk);
            recovered.verify(&dist.commitments, 1).unwrap();
        });

        // One complaint disputation (neutral set of size n-2).
        let neutrals = n.saturating_sub(2).max(1);
        let (t_complaint, _) = best_of(3, || {
            aggregatable_dkg::dkg::complaint::resolve_disputation(
                &generators,
                &dist.commitments,
                1,
                &dist.shares[0],
                neutrals,
                rng,
            )
        });

        // Real on-wire message size of one dealer's full DMKG contribution.
        let mut dealer = DMKGDealer {
            node: make_node(0),
            elgamal: elgamal[0].clone(),
        };
        let (contribution, _s, _d) =
            dmkg::deal(&mut dealer, &generators, &base, &receiver_pks, rng).unwrap();
        let size = serialized_contribution_size(&contribution);
        payload_bytes.insert(n, size);

        println!(
            "{:>5} {:>6} | {:>10.3} {:>12.3} | {:>10.3} {:>11.4} {:>13.4} | {:>10.3} {:>9.1}",
            n,
            degree,
            ms(t_z_share),
            ms(t_z_tx_verify),
            ms(t_ped_deal),
            ms(t_ped_enc_per),
            ms(t_ped_verify1),
            ms(t_complaint),
            size as f64 / 1024.0,
        );

        metrics.push(Metrics {
            n,
            z_tx_verify: ms(t_z_tx_verify),
            z_verify1: ms(t_z_verify1),
            ped_verify1: ms(t_ped_verify1),
        });
    }

    // ---------------------------------------------------------------
    // Part B - per-node verification work: aggregated vs non-aggregated.
    // ---------------------------------------------------------------
    // The aggregatable z layer lets a node verify ONE folded transcript instead of
    // n separate dealings. We contrast:
    //   z_agg/node      = verify 1 aggregated transcript        (this protocol)
    //   z_noagg/node    = n × verify 1 individual PVSS dealing  (non-aggregated z)
    //   ped/node        = n × verify 1 Pedersen share           (always non-agg)
    println!("\n## B. Per-node verification work (ms): aggregation vs none\n");
    println!(
        "{:>5} | {:>12} {:>14} {:>12} | {:>12}",
        "n", "z_agg/node", "z_noagg/node", "ped/node", "agg_speedup"
    );
    println!("{}", "-".repeat(64));
    for m in metrics.iter() {
        let z_agg = m.z_tx_verify;
        let z_noagg = m.z_verify1 * m.n as f64;
        let ped = m.ped_verify1 * m.n as f64;
        println!(
            "{:>5} | {:>12.2} {:>14.2} {:>12.2} | {:>12.1}",
            m.n,
            z_agg,
            z_noagg,
            ped,
            z_noagg / z_agg.max(1e-9),
        );
    }

    // ---------------------------------------------------------------
    // Part C - network simulation (Tokio), swept over latency.
    // ---------------------------------------------------------------
    #[cfg(feature = "network")]
    {
        use aggregatable_dkg::dkg::network::{run_broadcast_round, run_tree_gossip};
        println!("\n## C. Network (Tokio sim): all-to-all (Pedersen) vs tree gossip (z)\n");
        println!(
            "{:>6} {:>9} | {:>10} {:>9} {:>11} | {:>10} {:>9} {:>11}",
            "n", "latency", "bcast_ms", "bcast_msg", "bcast_MiB", "tree_ms", "tree_msg", "tree_MiB",
        );
        println!("{}", "-".repeat(92));
        let net_ns: &[usize] = &[16, 64, 256, 1024];
        let latencies: &[u64] = &[0, 50, 100, 200];
        for &n in net_ns {
            // Use a representative payload: the n=256 contribution size if measured,
            // else the largest available.
            let payload = *payload_bytes
                .get(&n)
                .or_else(|| payload_bytes.values().max())
                .unwrap_or(&1024);
            for &lat in latencies {
                let l = Duration::from_millis(lat);
                let b = run_broadcast_round(n, l, payload);
                let t = run_tree_gossip(n, l, payload);
                println!(
                    "{:>6} {:>7}ms | {:>10.1} {:>9} {:>11.2} | {:>10.1} {:>9} {:>11.2}",
                    n,
                    lat,
                    ms(b.wall),
                    b.messages,
                    b.bytes as f64 / (1024.0 * 1024.0),
                    ms(t.wall),
                    t.messages,
                    t.bytes as f64 / (1024.0 * 1024.0),
                );
            }
        }
    }
    #[cfg(not(feature = "network"))]
    {
        println!("\n(Network simulation skipped: build with --features network)");
    }
}

/// Serialized size of a dealer's full DMKG contribution (z share + Pedersen
/// commitments + encrypted shares + pk contributions).
fn serialized_contribution_size(contribution: &DMKGContribution<E, SPOK, SSIG>) -> usize {
    let mut bytes = vec![];
    contribution.dkg_share.serialize(&mut bytes).unwrap();
    let mut total = bytes.len();
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
