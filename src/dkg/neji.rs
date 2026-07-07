//! Wafa Neji's single-secret DKG with the *Disputation* complaint-management
//! strategy (Neji thesis, ch. 3 "Un protocole DKG basé sur une nouvelle stratégie
//! de gestion de plaintes").
//!
//! This is the **one-secret ancestor** of the multi-secret Pedersen DMKGs that the
//! rest of this crate implements (BTSOF 2020, Kalai 2022, the 2025
//! partially-aggregatable protocol). It establishes the public-channel +
//! encrypted-share + *Disputation* pattern those papers later generalise to a
//! five-component traceable key. Here there is a **single secret** `s_i ∈ Fr` per
//! dealer and the aggregate secret is `sk = Σ_{i∈QUAL} s_i`.
//!
//! ## What the paper specifies (and our faithful rendering)
//!
//! * **Feldman commitments, not Pedersen.** Each dealer commits its degree-`t`
//!   polynomial `f_i(x) = a_0 + … + a_t x^t` (with `f_i(0) = s_i`) by publishing
//!   `F_{k,i} = g^{a_k}` for `k ∈ [0,t]` — a **single generator** `g`. A receiver
//!   `P_j` checks its share with `g^{s_{ij}} = ∏_k F_{k,i}^{j^k}`.
//! * **A second generator `h` only for the public key**: `pk = h^{sk}`.
//! * **Share encryption** is option (B) lifted ElGamal (message `g^{s_{ij}}`).
//! * **Disputation** (no trusted party): neutrals blind the accused's opening with
//!   `r = Σ r_k`; the accused reveals `g^{r·s_{ij}}`; neutrals recover
//!   `g^{s_{ij}} = (g^{r·s_{ij}})^{1/r}` and check it against the Feldman
//!   commitments. No honest scalar share is ever revealed.
//!
//! The protocol is a **plain discrete-log** scheme (no pairing). Following the
//! paper's "generic prime-order group" model, the benchmark instantiates it on a
//! non-pairing curve (Jubjub); the module itself is generic over any
//! `C: ProjectiveCurve`.

use crate::dkg::encryption::{ElGamalBase, ElGamalCiphertext};
use crate::dkg::errors::VssError;
use crate::signature::utils::hash::hash_to_group;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};

/// Domain separator for the nothing-up-my-sleeve generator derivation.
const PERSONALIZATION: &[u8] = b"NEJIDKG_";

/// The two generators of Neji's DKG: `g` for the Feldman VSS / shares, `h` for the
/// public key `pk = h^{sk}`. Derived by hash-to-curve so their mutual discrete log
/// is unknown.
#[derive(Clone, Debug)]
pub struct NejiGenerators<C: ProjectiveCurve> {
    pub g: C::Affine,
    pub h: C::Affine,
}

impl<C: ProjectiveCurve> NejiGenerators<C> {
    pub fn setup() -> Result<Self, VssError> {
        let derive = |seed: &[u8]| -> Result<C::Affine, VssError> {
            Ok(hash_to_group::<C::Affine>(PERSONALIZATION, seed)
                .map_err(|_| VssError::Malformed("hash-to-curve failed"))?
                .into_affine())
        };
        Ok(Self {
            g: derive(b"neji-g")?,
            h: derive(b"neji-h")?,
        })
    }
}

/// A plain Shamir polynomial `f(x) = a_0 + a_1 x + … + a_t x^t` with the secret
/// pinned at the constant term `f(0) = a_0`. Pure scalar-field arithmetic.
#[derive(Clone, Debug)]
pub struct ShamirPolynomial<F: PrimeField> {
    /// `coeffs[k]` is the coefficient of `x^k`; `coeffs[0]` is the secret.
    pub coeffs: Vec<F>,
}

impl<F: PrimeField> ShamirPolynomial<F> {
    /// Sample a degree-`t` polynomial with `f(0) = secret` and random higher
    /// coefficients.
    pub fn sample<R: Rng>(degree: usize, secret: F, rng: &mut R) -> Result<Self, VssError> {
        if degree < 1 {
            return Err(VssError::InsufficientDegree(degree));
        }
        let mut coeffs = vec![secret];
        for _ in 1..=degree {
            coeffs.push(F::rand(rng));
        }
        Ok(Self { coeffs })
    }

    /// Evaluate at an integer point (Horner).
    pub fn evaluate(&self, x: F) -> F {
        let mut acc = F::zero();
        for c in self.coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }

    /// Shares `f(1), …, f(n)` for receivers `j ∈ [1,n]`.
    pub fn shares(&self, n: usize) -> Vec<F> {
        (1..=n).map(|j| self.evaluate(F::from(j as u64))).collect()
    }

    /// Lagrange coefficients `λ_j` that recover `f(0)` from values at `indices`:
    /// `f(0) = Σ_j λ_j · f(index_j)`.
    pub fn lambda_at_zero(indices: &[F]) -> Result<Vec<F>, VssError> {
        let target = F::zero();
        let mut coeffs = Vec::with_capacity(indices.len());
        for (i, xi) in indices.iter().enumerate() {
            let mut num = F::one();
            let mut den = F::one();
            for (k, xk) in indices.iter().enumerate() {
                if i == k {
                    continue;
                }
                num *= target - *xk;
                den *= *xi - *xk;
            }
            let den_inv = den.inverse().ok_or(VssError::BadIndices)?;
            coeffs.push(num * den_inv);
        }
        Ok(coeffs)
    }
}

/// One dealer's public Feldman output: the commitments `F_k = g^{a_k}` (`k∈[0,t]`)
/// and the per-receiver shares `s_j = f(j)` (index `i` ⇒ receiver `j = i+1`).
#[derive(Clone, Debug)]
pub struct FeldmanDistribution<C: ProjectiveCurve> {
    pub commitments: Vec<C::Affine>,
    pub shares: Vec<C::ScalarField>,
}

/// The dealer-local secret behind a [`FeldmanDistribution`].
#[derive(Clone, Debug)]
pub struct FeldmanSecrets<C: ProjectiveCurve> {
    pub secret: C::ScalarField,
    pub poly: ShamirPolynomial<C::ScalarField>,
}

impl<C: ProjectiveCurve> FeldmanDistribution<C> {
    /// Deal a freshly sampled random secret.
    pub fn deal<R: Rng>(
        generators: &NejiGenerators<C>,
        degree: usize,
        num_receivers: usize,
        rng: &mut R,
    ) -> Result<(Self, FeldmanSecrets<C>), VssError> {
        Self::deal_with_secret(
            generators,
            degree,
            num_receivers,
            C::ScalarField::rand(rng),
            rng,
        )
    }

    /// Deal a caller-chosen secret.
    pub fn deal_with_secret<R: Rng>(
        generators: &NejiGenerators<C>,
        degree: usize,
        num_receivers: usize,
        secret: C::ScalarField,
        rng: &mut R,
    ) -> Result<(Self, FeldmanSecrets<C>), VssError> {
        let poly = ShamirPolynomial::<C::ScalarField>::sample(degree, secret, rng)?;
        let commitments = poly
            .coeffs
            .iter()
            .map(|a| generators.g.mul(a.into_repr()).into_affine())
            .collect::<Vec<_>>();
        let shares = poly.shares(num_receivers);
        Ok((
            Self {
                commitments,
                shares,
            },
            FeldmanSecrets { secret, poly },
        ))
    }

    /// Check a receiver's recovered group-element share `m = g^{s_j}` against the
    /// Feldman commitments: `g^{s_j} == ∏_k F_k^{j^k}`.
    pub fn verify_in_exponent(commitments: &[C::Affine], j: usize, m: C::Affine) -> bool {
        commitment_at::<C>(commitments, j) == m.into_projective()
    }
}

/// `∏_k C_k^{j^k}` — the public commitment evaluated at receiver `j`.
fn commitment_at<C: ProjectiveCurve>(commitments: &[C::Affine], j: usize) -> C {
    let j_fr = C::ScalarField::from(j as u64);
    let mut acc = C::zero();
    let mut power = C::ScalarField::one();
    for c in commitments.iter() {
        acc += c.mul(power.into_repr());
        power *= j_fr;
    }
    acc
}

/// Encrypt the group-element message `g^{s_j}` to receiver `P_j` (option (B)).
pub fn encrypt_share<C: ProjectiveCurve, R: Rng>(
    generators: &NejiGenerators<C>,
    base: &ElGamalBase<C>,
    receiver_pk: &C::Affine,
    share: C::ScalarField,
    rng: &mut R,
) -> ElGamalCiphertext<C> {
    let m = generators.g.mul(share.into_repr()).into_affine();
    ElGamalCiphertext::encrypt(base, receiver_pk, m, rng)
}

/// The verdict of one disputation (mirrors the Pedersen complaint phase).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    DealerDishonest,
    ComplainerDishonest,
}

/// Why a dealer was disqualified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisqualificationReason {
    TooManyComplaints,
    LostDisputation,
}

/// A single complaint: receiver `complainer` (1-based) accuses `dealer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Complaint {
    pub dealer: usize,
    pub complainer: usize,
}

/// Run one Neji-style disputation (thesis Steps 1–10), modelled at the
/// commitment/opening level. Neutral parties contribute `r = Σ r_k ≠ 0`; the
/// accused reveals `g^{r·s}`; the neutrals recover `g^{s} = (g^{r·s})^{1/r}` and
/// check it against the Feldman commitments.
pub fn resolve_disputation<C: ProjectiveCurve, R: Rng>(
    generators: &NejiGenerators<C>,
    commitments: &[C::Affine],
    j: usize,
    dealer_opening: C::ScalarField,
    neutral_count: usize,
    rng: &mut R,
) -> Verdict {
    // Neutral blinds; resample if the sum is (negligibly) zero so 1/r exists.
    let r = loop {
        let mut acc = C::ScalarField::zero();
        for _ in 0..neutral_count.max(1) {
            acc += C::ScalarField::rand(rng);
        }
        if !acc.is_zero() {
            break acc;
        }
    };
    let r_inv = r.inverse().expect("r != 0");

    // Accused reveals the blinded opening g^{r·s}; neutrals unblind to g^{s}.
    let blinded = generators.g.mul((r * dealer_opening).into_repr());
    let recovered_gs = blinded.mul(r_inv.into_repr());

    if recovered_gs == commitment_at::<C>(commitments, j) {
        Verdict::ComplainerDishonest
    } else {
        Verdict::DealerDishonest
    }
}

/// The result of the complaint phase.
pub struct ComplaintOutcome {
    pub qual: BTreeSet<usize>,
    pub disqualified: BTreeMap<usize, DisqualificationReason>,
}

/// Run the disputation-based complaint phase over all dealers (thesis §3.3.2).
#[allow(clippy::too_many_arguments)]
pub fn run_complaint_phase<C: ProjectiveCurve, R: Rng>(
    generators: &NejiGenerators<C>,
    degree: usize,
    all_dealers: &BTreeSet<usize>,
    commitments: &BTreeMap<usize, Vec<C::Affine>>,
    openings: &BTreeMap<usize, Vec<C::ScalarField>>,
    complaints: &[Complaint],
    neutral_count: usize,
    rng: &mut R,
) -> Result<ComplaintOutcome, VssError> {
    let mut disqualified: BTreeMap<usize, DisqualificationReason> = BTreeMap::new();

    let mut by_dealer: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for c in complaints.iter() {
        by_dealer.entry(c.dealer).or_default().push(c.complainer);
    }

    for (&dealer, complainers) in by_dealer.iter() {
        let distinct: BTreeSet<usize> = complainers.iter().copied().collect();
        if distinct.len() > degree.saturating_sub(1) {
            disqualified.insert(dealer, DisqualificationReason::TooManyComplaints);
            continue;
        }
        let dealer_commitments = commitments
            .get(&dealer)
            .ok_or(VssError::Malformed("missing dealer commitments"))?;
        let dealer_openings = openings
            .get(&dealer)
            .ok_or(VssError::Malformed("missing dealer openings"))?;
        for &complainer in distinct.iter() {
            let opening = *dealer_openings
                .get(complainer - 1)
                .ok_or(VssError::Malformed("missing opening for complainer"))?;
            if resolve_disputation(
                generators,
                dealer_commitments,
                complainer,
                opening,
                neutral_count,
                rng,
            ) == Verdict::DealerDishonest
            {
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
    use super::*;
    use ark_bls12_381::{Fr, G1Projective};
    use rand::thread_rng;

    type Gens = NejiGenerators<G1Projective>;
    type Feldman = FeldmanDistribution<G1Projective>;
    type Shamir = ShamirPolynomial<Fr>;

    #[test]
    fn test_generators_distinct() {
        let g = Gens::setup().unwrap();
        assert_ne!(g.g, g.h);
        assert_eq!(g.g, Gens::setup().unwrap().g);
    }

    #[test]
    fn test_honest_shares_verify_in_exponent() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (dist, _s) = Feldman::deal(&gens, 3, 8, rng).unwrap();
        for (i, s) in dist.shares.iter().enumerate() {
            let m = gens.g.mul(s.into_repr()).into_affine();
            assert!(Feldman::verify_in_exponent(&dist.commitments, i + 1, m));
        }
    }

    #[test]
    fn test_tampered_share_fails() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (dist, _s) = Feldman::deal(&gens, 3, 8, rng).unwrap();
        let bad = gens
            .g
            .mul((dist.shares[2] + Fr::rand(rng)).into_repr())
            .into_affine();
        assert!(!Feldman::verify_in_exponent(&dist.commitments, 3, bad));
    }

    #[test]
    fn test_secret_reconstructs_at_zero() {
        // g^{f(0)} from t+1 shares-in-exponent equals the secret commitment g^s.
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let degree = 4;
        let n = 9;
        let (dist, secrets) = Feldman::deal(&gens, degree, n, rng).unwrap();

        let indices: Vec<Fr> = (0..=degree).map(|i| Fr::from((i + 1) as u64)).collect();
        let lambdas = Shamir::lambda_at_zero(&indices).unwrap();
        let mut acc = G1Projective::zero();
        for (i, lambda) in lambdas.iter().enumerate() {
            let m = gens.g.mul(dist.shares[i].into_repr());
            acc += m.mul(lambda.into_repr());
        }
        assert_eq!(
            acc.into_affine(),
            gens.g.mul(secrets.secret.into_repr()).into_affine()
        );
        // And that equals the published F_0 = g^{a_0}.
        assert_eq!(acc.into_affine(), dist.commitments[0]);
    }

    #[test]
    fn test_disputation_catches_cheating_dealer() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (dist, _s) = Feldman::deal(&gens, 3, 8, rng).unwrap();
        // The dealer opens an inconsistent share for receiver 3.
        let bad_opening = dist.shares[2] + Fr::rand(rng);
        assert_eq!(
            resolve_disputation(&gens, &dist.commitments, 3, bad_opening, 5, rng),
            Verdict::DealerDishonest
        );
        // An honest opening clears the dealer (the complainer lied).
        assert_eq!(
            resolve_disputation(&gens, &dist.commitments, 3, dist.shares[2], 5, rng),
            Verdict::ComplainerDishonest
        );
    }

    #[test]
    fn test_complaint_phase_disqualifies_cheater() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let degree = 2;
        let n = 5;
        let all: BTreeSet<usize> = (0..n).collect();
        let mut commitments = BTreeMap::new();
        let mut openings = BTreeMap::new();
        for d in 0..n {
            let (dist, _s) = Feldman::deal(&gens, degree, n, rng).unwrap();
            commitments.insert(d, dist.commitments.clone());
            // Dealer 1 opens a corrupted share to receiver 1.
            let mut shares = dist.shares.clone();
            if d == 1 {
                shares[0] += Fr::rand(rng);
            }
            openings.insert(d, shares);
        }
        let complaints = vec![Complaint {
            dealer: 1,
            complainer: 1,
        }];
        let outcome = run_complaint_phase(
            &gens,
            degree,
            &all,
            &commitments,
            &openings,
            &complaints,
            3,
            rng,
        )
        .unwrap();
        assert!(!outcome.qual.contains(&1));
        assert_eq!(
            outcome.disqualified.get(&1),
            Some(&DisqualificationReason::LostDisputation)
        );
        for h in [0usize, 2, 3, 4] {
            assert!(outcome.qual.contains(&h));
        }
    }
}
