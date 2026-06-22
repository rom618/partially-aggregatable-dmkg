//! Simplified complaint management.
//!
//! Runs only when a receiver complained that a share it decrypted from a dealer
//! failed the Pedersen check. For each accused dealer:
//!
//! 1. if it is in `Qagg` (already flagged by the z layer), disqualify it without
//!    a disputation - the simplification the aggregatable z layer buys us;
//! 2. else if it has more than `t-1` distinct complaints, disqualify it;
//! 3. else run a disputation over the neutral set: neutrals contribute random
//!    blinds, the accused publishes a blinded opening, the neutrals recompute the
//!    relation and vote, and the majority decides. Honest parties never reveal a
//!    share in the clear.
//!
//! `QUAL` is the set of dealers left standing; recovery sums shares over it.
//!
//! The disputation is modelled at the opening level: the accused opens the share
//! it claims to have dealt, blinded by the neutrals' randomness, and the neutrals
//! check it against the public commitments. A deployed system would secret-share
//! the blinds and reveal them only after the accused commits; here they are
//! revealed for the recomputation. A cheating dealer still cannot open validly, a
//! lying complainer's target does, and no raw share is published.

use crate::dkg::{
    errors::DKGError,
    pedersen::{PedersenGenerators, PedersenShare},
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};

/// A single complaint: receiver `complainer` (1-based index) accuses `dealer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Complaint {
    pub dealer: usize,
    pub complainer: usize,
}

/// The outcome of resolving one accusation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The accused dealer is dishonest (failed to open a valid share).
    DealerDishonest,
    /// The complaint was false; the complainer is dishonest.
    ComplainerDishonest,
}

/// Why a dealer was disqualified, for diagnostics / the write-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisqualificationReason {
    /// Member of `Qagg` (reported dishonest by the `z` layer).
    InQagg,
    /// More than `t-1` independent complaints.
    TooManyComplaints,
    /// Lost a disputation by majority vote.
    LostDisputation,
}

/// One neutral party's blind contribution (paper Step 3): random scalars and the
/// matching Pedersen commitment `S''ₖ = g1^{Δa}·h1^{Δb}·g2^{Δa'}·h2^{Δb'}` that is
/// published so the others can recompute Eq. (2).
struct NeutralBlind<E: PairingEngine> {
    da: E::Fr,
    db: E::Fr,
    da_prime: E::Fr,
    db_prime: E::Fr,
    commitment: E::G1Affine,
}

impl<E: PairingEngine> NeutralBlind<E> {
    fn sample<R: Rng>(generators: &PedersenGenerators<E>, rng: &mut R) -> Self {
        let da = E::Fr::rand(rng);
        let db = E::Fr::rand(rng);
        let da_prime = E::Fr::rand(rng);
        let db_prime = E::Fr::rand(rng);
        let commitment = (generators.g1.mul(da.into_repr())
            + generators.h1.mul(db.into_repr())
            + generators.g2.mul(da_prime.into_repr())
            + generators.h2.mul(db_prime.into_repr()))
        .into_affine();
        Self {
            da,
            db,
            da_prime,
            db_prime,
            commitment,
        }
    }
}

/// Expected commitment-at-`j`: `∏ₖ CMₖ^{ jᵏ }`.
fn commitment_at<E: PairingEngine>(commitments: &[E::G1Affine], j: usize) -> E::G1Projective {
    let j_fr = E::Fr::from(j as u64);
    let mut acc = E::G1Projective::zero();
    let mut power = E::Fr::one();
    for cm in commitments.iter() {
        acc += cm.mul(power.into_repr());
        power *= j_fr;
    }
    acc
}

/// Run one Neji-style disputation (Steps 3.a-3.i) for the accusation
/// `(dealer Pᵢ, complainer Pⱼ)`, with `neutral_count` neutral parties.
///
/// `dealer_opening` is the cleartext share the accused dealer claims it dealt to
/// `Pⱼ`. The neutrals blind it, recompute Eq. (2), and vote; the majority verdict
/// is returned. A corrupt minority (`< n/2`) of neutrals cannot flip the outcome,
/// so the returned verdict is the honest majority's.
pub fn resolve_disputation<E: PairingEngine, R: Rng>(
    generators: &PedersenGenerators<E>,
    commitments: &[E::G1Affine],
    j: usize,
    dealer_opening: &PedersenShare<E>,
    neutral_count: usize,
    rng: &mut R,
) -> Verdict {
    // Step 3 (neutrals): each neutral publishes a blind commitment S''ₖ.
    let blinds: Vec<NeutralBlind<E>> = (0..neutral_count)
        .map(|_| NeutralBlind::sample(generators, rng))
        .collect();

    let (sum_da, sum_db, sum_da_prime, sum_db_prime) = blinds.iter().fold(
        (E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero()),
        |(a, b, ap, bp), bl| (a + bl.da, b + bl.db, ap + bl.da_prime, bp + bl.db_prime),
    );

    // Step 3 (accused): publish the blinded opening (λ, λ', γ, γ').
    let lambda = dealer_opening.sf + sum_da;
    let lambda_prime = dealer_opening.sf_prime + sum_db;
    let gamma = dealer_opening.sg + sum_da_prime;
    let gamma_prime = dealer_opening.sg_prime + sum_db_prime;

    // Step 3 (each neutral recomputes Eq. (2) and votes):
    //   g1^{λ}·h1^{λ'}·g2^{γ}·h2^{γ'}  ==  (∏ₖ CMₖ^{jᵏ}) · (∏_{k∈Q} S''ₖ)
    let lhs = (generators.g1.mul(lambda.into_repr())
        + generators.h1.mul(lambda_prime.into_repr())
        + generators.g2.mul(gamma.into_repr())
        + generators.h2.mul(gamma_prime.into_repr()))
    .into_affine();

    let mut rhs = commitment_at::<E>(commitments, j);
    for bl in blinds.iter() {
        rhs += bl.commitment.into_projective();
    }
    let rhs = rhs.into_affine();

    // The check is deterministic over public data, so every honest neutral votes
    // identically; the honest majority therefore decides.
    if lhs == rhs {
        Verdict::ComplainerDishonest
    } else {
        Verdict::DealerDishonest
    }
}

/// The result of the complaint phase.
pub struct ComplaintOutcome {
    /// Dealers that survived: `QUAL`.
    pub qual: BTreeSet<usize>,
    /// Disqualified dealers and why.
    pub disqualified: BTreeMap<usize, DisqualificationReason>,
}

/// Run the simplified complaint phase over all dealers.
///
/// * `degree` is the polynomial degree `t` (so the disqualification threshold is
///   `t-1`).
/// * `all_dealers` is the set of dealer ids that took part in distribution.
/// * `qagg` is the set of dealers flagged by the z layer.
/// * `commitments` / `openings` give, per dealer, the public `CMₖ` and the
///   cleartext share the dealer would open for any complained-about receiver.
/// * `complaints` is the list of filed complaints (empty ⇒ phase is a no-op and
///   every dealer is qualified).
#[allow(clippy::too_many_arguments)]
pub fn run_complaint_phase<E: PairingEngine, R: Rng>(
    generators: &PedersenGenerators<E>,
    degree: usize,
    all_dealers: &BTreeSet<usize>,
    qagg: &BTreeSet<usize>,
    commitments: &BTreeMap<usize, Vec<E::G1Affine>>,
    openings: &BTreeMap<usize, Vec<PedersenShare<E>>>,
    complaints: &[Complaint],
    neutral_count: usize,
    rng: &mut R,
) -> Result<ComplaintOutcome, DKGError<E>> {
    let mut disqualified: BTreeMap<usize, DisqualificationReason> = BTreeMap::new();

    // Group complaints by accused dealer.
    let mut by_dealer: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for c in complaints.iter() {
        by_dealer.entry(c.dealer).or_default().push(c.complainer);
    }

    for (&dealer, complainers) in by_dealer.iter() {
        // Step 1: Qagg short-circuit.
        if qagg.contains(&dealer) {
            disqualified.insert(dealer, DisqualificationReason::InQagg);
            continue;
        }
        // Step 2: too many independent complaints.
        let distinct: BTreeSet<usize> = complainers.iter().copied().collect();
        if distinct.len() > degree.saturating_sub(1) {
            disqualified.insert(dealer, DisqualificationReason::TooManyComplaints);
            continue;
        }
        // Step 3: disputation per complaint; a single lost disputation disqualifies.
        let dealer_commitments = commitments
            .get(&dealer)
            .ok_or(DKGError::PedersenMalformed("missing dealer commitments"))?;
        let dealer_openings = openings
            .get(&dealer)
            .ok_or(DKGError::PedersenMalformed("missing dealer openings"))?;
        for &complainer in distinct.iter() {
            let opening =
                dealer_openings
                    .get(complainer - 1)
                    .ok_or(DKGError::PedersenMalformed(
                        "missing opening for complainer",
                    ))?;
            let verdict = resolve_disputation(
                generators,
                dealer_commitments,
                complainer,
                opening,
                neutral_count,
                rng,
            );
            if verdict == Verdict::DealerDishonest {
                disqualified.insert(dealer, DisqualificationReason::LostDisputation);
                break;
            }
        }
    }

    let qual: BTreeSet<usize> = all_dealers
        .iter()
        .copied()
        .filter(|d| !disqualified.contains_key(d))
        .collect();

    Ok(ComplaintOutcome { qual, disqualified })
}

#[cfg(test)]
mod test {
    use super::{
        resolve_disputation, run_complaint_phase, Complaint, DisqualificationReason, Verdict,
    };
    use crate::dkg::pedersen::{PedersenDistribution, PedersenGenerators};
    use ark_bls12_381::Bls12_381;
    use ark_ff::UniformRand;
    use rand::thread_rng;
    use std::collections::{BTreeMap, BTreeSet};

    type Gens = PedersenGenerators<Bls12_381>;
    type Pedersen = PedersenDistribution<Bls12_381>;

    const DEGREE: usize = 3;
    const N: usize = 8;
    const NEUTRALS: usize = 5;

    // (i) A cheating dealer that opens an invalid share loses the disputation.
    #[test]
    fn test_cheating_dealer_caught() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (mut dist, _s) = Pedersen::deal(&gens, DEGREE, N, rng).unwrap();
        // Dealer's opening for receiver 3 does not match its commitments.
        dist.shares[2].sf += ark_bls12_381::Fr::rand(rng);
        let verdict =
            resolve_disputation(&gens, &dist.commitments, 3, &dist.shares[2], NEUTRALS, rng);
        assert_eq!(verdict, Verdict::DealerDishonest);
    }

    // (ii) A lying complainer is caught: the honest dealer opens a valid share.
    #[test]
    fn test_lying_complainer_caught() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (dist, _s) = Pedersen::deal(&gens, DEGREE, N, rng).unwrap();
        let verdict =
            resolve_disputation(&gens, &dist.commitments, 3, &dist.shares[2], NEUTRALS, rng);
        assert_eq!(verdict, Verdict::ComplainerDishonest);
    }

    // (iii) A Qagg member is auto-disqualified without any disputation.
    #[test]
    fn test_qagg_auto_disqualified() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (dist, _s) = Pedersen::deal(&gens, DEGREE, N, rng).unwrap();

        let dealers: BTreeSet<usize> = (0..4).collect();
        let mut qagg = BTreeSet::new();
        qagg.insert(2usize);

        let mut commitments = BTreeMap::new();
        let mut openings = BTreeMap::new();
        for d in dealers.iter() {
            commitments.insert(*d, dist.commitments.clone());
            openings.insert(*d, dist.shares.clone());
        }
        // Someone complains about the Qagg dealer (the share content is irrelevant).
        let complaints = vec![Complaint {
            dealer: 2,
            complainer: 1,
        }];

        let outcome = run_complaint_phase(
            &gens,
            DEGREE,
            &dealers,
            &qagg,
            &commitments,
            &openings,
            &complaints,
            NEUTRALS,
            rng,
        )
        .unwrap();

        assert_eq!(
            outcome.disqualified.get(&2),
            Some(&DisqualificationReason::InQagg)
        );
        assert!(!outcome.qual.contains(&2));
        for d in [0usize, 1, 3] {
            assert!(outcome.qual.contains(&d));
        }
    }

    // (iv) An honest dealer / honest pair: no complaint resolves against the dealer,
    // and with no complaints at all every dealer is qualified.
    #[test]
    fn test_honest_pair_cleared() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (dist, _s) = Pedersen::deal(&gens, DEGREE, N, rng).unwrap();

        let dealers: BTreeSet<usize> = (0..4).collect();
        let qagg = BTreeSet::new();
        let mut commitments = BTreeMap::new();
        let mut openings = BTreeMap::new();
        for d in dealers.iter() {
            commitments.insert(*d, dist.commitments.clone());
            openings.insert(*d, dist.shares.clone());
        }

        // A spurious complaint against an honest dealer 1 must NOT disqualify it.
        let complaints = vec![Complaint {
            dealer: 1,
            complainer: 3,
        }];
        let outcome = run_complaint_phase(
            &gens,
            DEGREE,
            &dealers,
            &qagg,
            &commitments,
            &openings,
            &complaints,
            NEUTRALS,
            rng,
        )
        .unwrap();
        assert!(outcome.qual.contains(&1));
        assert!(outcome.disqualified.is_empty());

        // No complaints at all ⇒ everyone qualifies.
        let outcome2 = run_complaint_phase(
            &gens,
            DEGREE,
            &dealers,
            &qagg,
            &commitments,
            &openings,
            &[],
            NEUTRALS,
            rng,
        )
        .unwrap();
        assert_eq!(outcome2.qual, dealers);
    }

    // The `#complaints > t-1` rule disqualifies a dealer with too many accusers,
    // even though each individual opening would have verified.
    #[test]
    fn test_too_many_complaints_disqualifies() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (dist, _s) = Pedersen::deal(&gens, DEGREE, N, rng).unwrap();

        let dealers: BTreeSet<usize> = (0..4).collect();
        let qagg = BTreeSet::new();
        let mut commitments = BTreeMap::new();
        let mut openings = BTreeMap::new();
        for d in dealers.iter() {
            commitments.insert(*d, dist.commitments.clone());
            openings.insert(*d, dist.shares.clone());
        }
        // t-1 = 2, so 3 distinct complainers exceed the threshold.
        let complaints = vec![
            Complaint {
                dealer: 0,
                complainer: 1,
            },
            Complaint {
                dealer: 0,
                complainer: 2,
            },
            Complaint {
                dealer: 0,
                complainer: 3,
            },
        ];
        let outcome = run_complaint_phase(
            &gens,
            DEGREE,
            &dealers,
            &qagg,
            &commitments,
            &openings,
            &complaints,
            NEUTRALS,
            rng,
        )
        .unwrap();
        assert_eq!(
            outcome.disqualified.get(&0),
            Some(&DisqualificationReason::TooManyComplaints)
        );
    }
}
