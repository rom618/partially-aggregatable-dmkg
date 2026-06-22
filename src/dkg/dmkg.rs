//! End-to-end Distributed Multi-Key Generation node.
//!
//! A run produces the traceable key pair
//!
//! ```text
//! sk = (x1, x2, y1, y2, z)
//! pk = (c1, c2, c3) = (g1^x1·g2^x2, g1^y1·g2^y2, g1^z)
//! ```
//!
//! by combining two sharing layers over the qualified set: the aggregatable
//! SCRAPE PVSS for `z` (a tampered contribution puts its dealer in `Qagg`), and the
//! four-generator Pedersen / Franklin-Yung layer for `(x1,x2,y1,y2)` with encrypted
//! shares and complaint handling. To bind `z` to the Pedersen generator `g1`, each
//! dealer also publishes `c3_i = g1^{z_i}` alongside its SCRAPE commitment.
//!
//! Since the encrypted shares are group elements, each receiver holds `g1^{f(j)}`
//! and `g2^{g(j)}`. Summing over the qualified dealers and interpolating in the
//! exponent at the special points recovers c1 and c2:
//!
//! ```text
//! c1 = sum_j lambda1_j·(Mf(j) + Mg(j)) = g1^x1·g2^x2
//! c2 = sum_j lambda2_j·(Mf(j) + Mg(j)) = g1^y1·g2^y2
//! ```

use crate::{
    dkg::{
        encryption::{ElGamalBase, ElGamalKeypair, EncryptedPedersenShare},
        errors::DKGError,
        mss::MSSPolynomial,
        node::Node,
        participant::ParticipantState,
        pedersen::{PedersenDealerSecrets, PedersenDistribution, PedersenGenerators},
        share::{message_from_c_i, DKGShare},
    },
    signature::scheme::BatchVerifiableSignatureScheme,
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};

/// The common DMKG public key `pk = (c1, c2, c3)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<E: PairingEngine> {
    pub c1: E::G1Affine,
    pub c2: E::G1Affine,
    pub c3: E::G1Affine,
}

/// One dealer's complete public contribution to a DMKG run.
pub struct DMKGContribution<
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    pub dealer_id: usize,
    /// `z`-layer SCRAPE PVSS share.
    pub dkg_share: DKGShare<E, SPOK, SSIG>,
    /// Pedersen commitments `CMₖ` for the `(x1,x2,y1,y2)` layer.
    pub commitments: Vec<E::G1Affine>,
    /// Encrypted share quadruples, one per receiver `j ∈ [1,n]`.
    pub encrypted_shares: Vec<EncryptedPedersenShare<E>>,
    /// This dealer's contributions to the public key: `(g1^{x1ᵢ}g2^{x2ᵢ},
    /// g1^{y1ᵢ}g2^{y2ᵢ}, g1^{zᵢ})`.
    pub c1_i: E::G1Affine,
    pub c2_i: E::G1Affine,
    pub c3_i: E::G1Affine,
}

/// Aggregate the per-dealer public-key contributions over `qual` into `pk`.
pub fn aggregate_public_key<E, SPOK, SSIG>(
    contributions: &BTreeMap<usize, DMKGContribution<E, SPOK, SSIG>>,
    qual: &BTreeSet<usize>,
) -> PublicKey<E>
where
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
{
    let mut c1 = E::G1Projective::zero();
    let mut c2 = E::G1Projective::zero();
    let mut c3 = E::G1Projective::zero();
    for id in qual.iter() {
        if let Some(contribution) = contributions.get(id) {
            c1 += contribution.c1_i.into_projective();
            c2 += contribution.c2_i.into_projective();
            c3 += contribution.c3_i.into_projective();
        }
    }
    PublicKey {
        c1: c1.into_affine(),
        c2: c2.into_affine(),
        c3: c3.into_affine(),
    }
}

/// Reconstruct `(c1, c2)` from `t+1` receivers' aggregated group-element shares
/// via Lagrange-in-exponent at the Franklin-Yung special points `-1` and `-2`.
///
/// Each entry is `(j, Mf(j), Mg(j))` with `Mf(j)=g1^{F(j)}`, `Mg(j)=g2^{G(j)}`.
pub fn reconstruct_pk_components<E: PairingEngine>(
    receivers: &[(usize, E::G1Affine, E::G1Affine)],
) -> Result<(E::G1Affine, E::G1Affine), DKGError<E>> {
    let indices: Vec<E::Fr> = receivers
        .iter()
        .map(|(j, _, _)| MSSPolynomial::<E>::point(*j as i64))
        .collect();
    let lambda1 = MSSPolynomial::<E>::lambda1(&indices)?;
    let lambda2 = MSSPolynomial::<E>::lambda2(&indices)?;

    let mut c1 = E::G1Projective::zero();
    let mut c2 = E::G1Projective::zero();
    for (idx, (_, mf, mg)) in receivers.iter().enumerate() {
        // c1 uses λ1 (recovers value at -1: x1, x2).
        c1 += mf.mul(lambda1[idx].into_repr());
        c1 += mg.mul(lambda1[idx].into_repr());
        // c2 uses λ2 (recovers value at -2: y1, y2).
        c2 += mf.mul(lambda2[idx].into_repr());
        c2 += mg.mul(lambda2[idx].into_repr());
    }
    Ok((c1.into_affine(), c2.into_affine()))
}

/// A built-but-not-yet-published DMKG dealer: the `z`-layer node plus the receiver
/// ElGamal keypair used to decrypt Pedersen shares addressed to it.
pub struct DMKGDealer<
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    pub node: Node<E, SPOK, SSIG>,
    pub elgamal: ElGamalKeypair<E>,
}

/// Produce one dealer's full contribution (both layers) plus the dealer-local
/// Pedersen secrets needed to open shares during complaints.
///
/// `receiver_pks` are the ElGamal public keys of all `n` receivers (1-based order
/// matches receiver index `j`).
#[allow(clippy::type_complexity)]
pub fn deal<E, SPOK, SSIG, R>(
    dealer: &mut DMKGDealer<E, SPOK, SSIG>,
    generators: &PedersenGenerators<E>,
    base: &ElGamalBase<E>,
    receiver_pks: &[E::G1Affine],
    rng: &mut R,
) -> Result<
    (
        DMKGContribution<E, SPOK, SSIG>,
        PedersenDealerSecrets<E>,
        PedersenDistribution<E>,
    ),
    DKGError<E>,
>
where
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
    R: Rng,
{
    let dealer_id = dealer.node.dealer.participant.id;
    let degree = dealer.node.aggregator.config.degree;
    let n = receiver_pks.len();

    // ---- z layer: SCRAPE PVSS (reusing the upstream machinery) ----
    let (pvss_share, pvss_secrets) = dealer.node.share_pvss(rng)?;
    let z_i = pvss_secrets.f_0;
    let c_i = dealer
        .node
        .aggregator
        .config
        .srs
        .g_g1
        .mul(z_i.into_repr())
        .into_affine();
    let pok_keypair = dealer.node.aggregator.scheme_pok.from_sk(&z_i)?;
    let c_i_pok = dealer.node.aggregator.scheme_pok.sign(
        rng,
        &pok_keypair.0,
        &message_from_c_i::<E>(c_i)?,
    )?;
    let sig_keypair = dealer
        .node
        .aggregator
        .scheme_sig
        .from_sk(&dealer.node.dealer.private_key_sig)?;
    let signature_on_c_i = dealer.node.aggregator.scheme_sig.sign(
        rng,
        &sig_keypair.0,
        &message_from_c_i::<E>(c_i)?,
    )?;
    let dkg_share = DKGShare {
        participant_id: dealer_id,
        c_i,
        pvss_share,
        c_i_pok,
        signature_on_c_i,
    };
    dealer.node.dealer.participant.state = ParticipantState::DealerShared;

    // ---- (x1,x2,y1,y2) layer: Pedersen / Franklin-Yung ----
    let (distribution, secrets) = PedersenDistribution::deal(generators, degree, n, rng)?;

    let encrypted_shares = (0..n)
        .map(|j| {
            EncryptedPedersenShare::encrypt(
                generators,
                base,
                &receiver_pks[j],
                &distribution.shares[j],
                rng,
            )
        })
        .collect::<Vec<_>>();

    // Public-key contributions.
    let c1_i = (generators.g1.mul(secrets.x1.into_repr())
        + generators.g2.mul(secrets.x2.into_repr()))
    .into_affine();
    let c2_i = (generators.g1.mul(secrets.y1.into_repr())
        + generators.g2.mul(secrets.y2.into_repr()))
    .into_affine();
    let c3_i = generators.g1.mul(z_i.into_repr()).into_affine();

    let contribution = DMKGContribution {
        dealer_id,
        dkg_share,
        commitments: distribution.commitments.clone(),
        encrypted_shares,
        c1_i,
        c2_i,
        c3_i,
    };
    Ok((contribution, secrets, distribution))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        dkg::aggregator::DKGAggregator,
        dkg::complaint::{run_complaint_phase, Complaint},
        dkg::config::Config,
        dkg::dealer::Dealer,
        dkg::participant::Participant,
        dkg::share::DKGTranscript,
        dkg::srs::SRS,
        signature::bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        signature::scheme::SignatureScheme,
    };
    use ark_bls12_381::{Bls12_381, G2Projective};
    use ark_ff::UniformRand;
    use rand::thread_rng;
    use std::marker::PhantomData;

    type E = Bls12_381;
    type SPOK = BLSSignature<BLSSignatureG2<Bls12_381>>;
    type SSIG = BLSSignature<BLSSignatureG1<Bls12_381>>;

    // Full end-to-end DMKG: honest nodes agree on pk, a tampered dealer is
    // excluded via Qagg, and pk is reconstructable from t+1 receivers' shares.
    fn run_end_to_end(n: usize, degree: usize, tampered: &[usize]) {
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
        let u_1 = G2Projective::rand(rng).into_affine();
        let dkg_config = Config {
            srs: srs.clone(),
            u_1,
            degree,
        };
        let generators = PedersenGenerators::<E>::setup().unwrap();
        let base = ElGamalBase::<E>::setup().unwrap();

        // Build dealers (sig keypair + elgamal keypair).
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

        // ---- Distribution ----
        let mut contributions: BTreeMap<usize, DMKGContribution<E, SPOK, SSIG>> = BTreeMap::new();
        let mut all_secrets: BTreeMap<usize, PedersenDealerSecrets<E>> = BTreeMap::new();
        let mut all_distributions: BTreeMap<usize, PedersenDistribution<E>> = BTreeMap::new();
        for i in 0..n {
            let mut dealer = DMKGDealer {
                node: make_node(i),
                elgamal: elgamal[i].clone(),
            };
            let (mut contribution, secrets, distribution) =
                deal(&mut dealer, &generators, &base, &receiver_pks, rng).unwrap();
            if tampered.contains(&i) {
                // Corrupt the z-layer commitment so the dealer is reported in Qagg.
                contribution.dkg_share.c_i =
                    <E as PairingEngine>::G1Projective::rand(rng).into_affine();
            }
            contributions.insert(i, contribution);
            all_secrets.insert(i, secrets);
            all_distributions.insert(i, distribution);
        }

        // ---- z verification: a single aggregator builds Qagg ----
        let mut aggregator = make_node(0).aggregator;
        for i in 0..n {
            let share = contributions[&i].dkg_share.clone();
            let _ = aggregator.receive_share(rng, &share);
        }
        for &t in tampered {
            assert!(
                aggregator.qagg.contains(&t),
                "tampered dealer must be in Qagg"
            );
        }

        // ---- Pedersen verification: receivers decrypt + check, file complaints ----
        let mut complaints: Vec<Complaint> = vec![];
        for (&dealer_id, contribution) in contributions.iter() {
            for (j, ct) in contribution.encrypted_shares.iter().enumerate() {
                let recovered = ct.decrypt(elgamal[j].sk);
                if recovered.verify(&contribution.commitments, j + 1).is_err() {
                    complaints.push(Complaint {
                        dealer: dealer_id,
                        complainer: j + 1,
                    });
                }
            }
        }

        // ---- Complaint phase → QUAL ----
        let all_dealers: BTreeSet<usize> = (0..n).collect();
        let mut pedersen_commitments = BTreeMap::new();
        let mut pedersen_openings = BTreeMap::new();
        for (&id, contribution) in contributions.iter() {
            pedersen_commitments.insert(id, contribution.commitments.clone());
            pedersen_openings.insert(id, all_distributions[&id].shares.clone());
        }
        // A dealer disqualified by the z layer (in Qagg) must be excluded too.
        let mut qagg = aggregator.qagg.clone();
        for &t in tampered {
            qagg.insert(t);
            // Ensure there is at least one accusation so the phase examines it.
            complaints.push(Complaint {
                dealer: t,
                complainer: 1,
            });
        }
        let neutral_count = n.saturating_sub(2).max(1);
        let outcome = run_complaint_phase(
            &generators,
            degree,
            &all_dealers,
            &qagg,
            &pedersen_commitments,
            &pedersen_openings,
            &complaints,
            neutral_count,
            rng,
        )
        .unwrap();

        for &t in tampered {
            assert!(
                !outcome.qual.contains(&t),
                "tampered dealer excluded from QUAL"
            );
        }
        // Honest dealers all survive.
        for i in 0..n {
            if !tampered.contains(&i) {
                assert!(outcome.qual.contains(&i), "honest dealer {} in QUAL", i);
            }
        }

        // ---- Public key: every honest node computes the same pk from public data ----
        let pk = aggregate_public_key(&contributions, &outcome.qual);

        // ---- Reconstruction from t+1 receivers (in the exponent) ----
        // Per receiver j, aggregate the secret-carrying messages over QUAL.
        let mut receiver_msgs: Vec<(
            usize,
            <E as PairingEngine>::G1Affine,
            <E as PairingEngine>::G1Affine,
        )> = vec![];
        for j in 0..n {
            let mut mf = <E as PairingEngine>::G1Projective::zero();
            let mut mg = <E as PairingEngine>::G1Projective::zero();
            for id in outcome.qual.iter() {
                let recovered = contributions[id].encrypted_shares[j].decrypt(elgamal[j].sk);
                mf += recovered.m_sf.into_projective();
                mg += recovered.m_sg.into_projective();
            }
            receiver_msgs.push((j + 1, mf.into_affine(), mg.into_affine()));
        }
        // Use exactly t+1 receivers.
        let subset = &receiver_msgs[..degree + 1];
        let (c1_rec, c2_rec) = reconstruct_pk_components::<E>(subset).unwrap();
        assert_eq!(c1_rec, pk.c1, "reconstructed c1 matches aggregated pk");
        assert_eq!(c2_rec, pk.c2, "reconstructed c2 matches aggregated pk");

        // c3 = g1^{z} = Σ_{QUAL} g1^{zᵢ} (already in pk.c3); sanity: non-trivial.
        assert!(!pk.c3.is_zero());
    }

    #[test]
    fn test_dmkg_n4_honest() {
        run_end_to_end(4, 2, &[]);
    }

    #[test]
    fn test_dmkg_n8_one_corrupt() {
        run_end_to_end(8, 3, &[2]);
    }

    #[test]
    fn test_dmkg_n16_two_corrupt() {
        run_end_to_end(16, 7, &[3, 10]);
    }
}
