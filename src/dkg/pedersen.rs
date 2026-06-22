//! Four-generator Pedersen commitments for the (x1,x2,y1,y2) layer.
//!
//! Each dealer encodes two secrets and two masks as four degree-`t` Franklin-Yung
//! polynomials: f and g pin the secrets (f(-1)=x1, f(-2)=y1; g(-1)=x2, g(-2)=y2),
//! while f' and g' pin the masks. For every coefficient k it publishes a combined
//! commitment over four NUMS generators with unknown mutual discrete logs:
//!
//! ```text
//! CM_k = g1^{a_k} · h1^{b_k} · g2^{a'_k} · h2^{b'_k}
//! ```
//!
//! Receiver j gets (sf, sf', sg, sg') = (f(j), f'(j), g(j), g'(j)) and checks
//!
//! ```text
//! g1^{sf} · h1^{sf'} · g2^{sg} · h2^{sg'} == prod_{k=0..t} CM_k^{j^k}
//! ```
//!
//! Shares are in the clear here; encryption to each receiver is layered on
//! separately.

use crate::dkg::{errors::DKGError, mss::MSSPolynomial};
use crate::signature::utils::hash::hash_to_group;
use ark_ec::{msm::VariableBaseMSM, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use rand::Rng;

/// Domain separator for the nothing-up-my-sleeve generator derivation
/// (blake2s personalization must be exactly 8 bytes).
const PERSONALIZATION: &[u8] = b"DMKGPEDR";

/// The four Pedersen generators `g1, g2, h1, h2` in G1 with unknown pairwise
/// discrete logs. `g1, g2` commit to the two secrets, `h1, h2` to their masks.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenGenerators<E: PairingEngine> {
    pub g1: E::G1Affine,
    pub g2: E::G1Affine,
    pub h1: E::G1Affine,
    pub h2: E::G1Affine,
}

impl<E: PairingEngine> PedersenGenerators<E> {
    /// Derive the four generators by hashing fixed nothing-up-my-sleeve seeds to
    /// the curve. Because each is produced by hash-to-curve, no party knows the
    /// discrete log of any generator with respect to another.
    pub fn setup() -> Result<Self, DKGError<E>> {
        let derive = |seed: &[u8]| -> Result<E::G1Affine, DKGError<E>> {
            Ok(hash_to_group::<E::G1Affine>(PERSONALIZATION, seed)?.into_affine())
        };
        Ok(Self {
            g1: derive(b"pedersen-g1")?,
            g2: derive(b"pedersen-g2")?,
            h1: derive(b"pedersen-h1")?,
            h2: derive(b"pedersen-h2")?,
        })
    }

    /// Compute a single combined Pedersen commitment
    /// `g1^a · h1^b · g2^{a'} · h2^{b'}`.
    fn commit(&self, a: E::Fr, b: E::Fr, a_prime: E::Fr, b_prime: E::Fr) -> E::G1Affine {
        let bases = [self.g1, self.h1, self.g2, self.h2];
        let scalars = [
            a.into_repr(),
            b.into_repr(),
            a_prime.into_repr(),
            b_prime.into_repr(),
        ];
        VariableBaseMSM::multi_scalar_mul(&bases, &scalars).into_affine()
    }
}

/// One receiver's share quadruple `(sf, sf', sg, sg') = (f(j),f'(j),g(j),g'(j))`,
/// in the clear here; encrypted to the receiver separately.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenShare<E: PairingEngine> {
    pub sf: E::Fr,
    pub sf_prime: E::Fr,
    pub sg: E::Fr,
    pub sg_prime: E::Fr,
}

/// A dealer's public Pedersen-layer output: the per-coefficient commitments `CM_k`
/// (`k in [0,t]`) and the per-receiver share quadruples (index `i` corresponds to
/// receiver `j = i + 1`).
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenDistribution<E: PairingEngine> {
    pub commitments: Vec<E::G1Affine>,
    pub shares: Vec<PedersenShare<E>>,
}

/// The dealer-local secrets behind a [`PedersenDistribution`]: the two pinned
/// secrets and the four polynomials. Kept private (no serialization).
#[derive(Clone, Debug)]
pub struct PedersenDealerSecrets<E: PairingEngine> {
    pub x1: E::Fr,
    pub x2: E::Fr,
    pub y1: E::Fr,
    pub y2: E::Fr,
    pub f: MSSPolynomial<E>,
    pub g: MSSPolynomial<E>,
    pub f_prime: MSSPolynomial<E>,
    pub g_prime: MSSPolynomial<E>,
}

impl<E: PairingEngine> PedersenDistribution<E> {
    /// Deal with caller-chosen secrets `x1,x2,y1,y2`. Blinds `β1..β4` and the
    /// free polynomial coefficients are sampled internally.
    ///
    /// (The paper also lists `β0`; it is not consumed by this commitment layer -
    /// only `β1..β4` pin the two mask polynomials - so it is not drawn here.)
    pub fn deal_with_secrets<R: Rng>(
        generators: &PedersenGenerators<E>,
        degree: usize,
        num_receivers: usize,
        secrets: (E::Fr, E::Fr, E::Fr, E::Fr),
        rng: &mut R,
    ) -> Result<(Self, PedersenDealerSecrets<E>), DKGError<E>> {
        let (x1, x2, y1, y2) = secrets;
        let beta1 = E::Fr::rand(rng);
        let beta2 = E::Fr::rand(rng);
        let beta3 = E::Fr::rand(rng);
        let beta4 = E::Fr::rand(rng);

        let f = MSSPolynomial::sample(degree, x1, y1, rng)?;
        let g = MSSPolynomial::sample(degree, x2, y2, rng)?;
        let f_prime = MSSPolynomial::sample(degree, beta1, beta2, rng)?;
        let g_prime = MSSPolynomial::sample(degree, beta3, beta4, rng)?;

        let commitments = (0..=degree)
            .map(|k| {
                generators.commit(
                    f.coeffs[k],
                    f_prime.coeffs[k],
                    g.coeffs[k],
                    g_prime.coeffs[k],
                )
            })
            .collect::<Vec<_>>();

        let sf = f.shares(num_receivers);
        let sf_prime = f_prime.shares(num_receivers);
        let sg = g.shares(num_receivers);
        let sg_prime = g_prime.shares(num_receivers);
        let shares = (0..num_receivers)
            .map(|i| PedersenShare {
                sf: sf[i],
                sf_prime: sf_prime[i],
                sg: sg[i],
                sg_prime: sg_prime[i],
            })
            .collect::<Vec<_>>();

        let distribution = Self {
            commitments,
            shares,
        };
        let secrets = PedersenDealerSecrets {
            x1,
            x2,
            y1,
            y2,
            f,
            g,
            f_prime,
            g_prime,
        };
        Ok((distribution, secrets))
    }

    /// Deal with freshly sampled random secrets `x1,x2,y1,y2`.
    pub fn deal<R: Rng>(
        generators: &PedersenGenerators<E>,
        degree: usize,
        num_receivers: usize,
        rng: &mut R,
    ) -> Result<(Self, PedersenDealerSecrets<E>), DKGError<E>> {
        let secrets = (
            E::Fr::rand(rng),
            E::Fr::rand(rng),
            E::Fr::rand(rng),
            E::Fr::rand(rng),
        );
        Self::deal_with_secrets(generators, degree, num_receivers, secrets, rng)
    }

    /// Receiver-side check of Eq. (1) for receiver `j` (1-based) against a
    /// share quadruple, rewritten as a single multi-scalar-mul that must vanish:
    ///
    /// ```text
    /// g1^{sf}·h1^{sf'}·g2^{sg}·h2^{sg'} · ∏_k CMₖ^{-jᵏ}  ==  1
    /// ```
    pub fn verify_share(
        generators: &PedersenGenerators<E>,
        commitments: &[E::G1Affine],
        j: usize,
        share: &PedersenShare<E>,
    ) -> Result<(), DKGError<E>> {
        let j_fr = E::Fr::from(j as u64);

        let mut bases = vec![generators.g1, generators.h1, generators.g2, generators.h2];
        bases.extend_from_slice(commitments);

        let mut scalars = vec![
            share.sf.into_repr(),
            share.sf_prime.into_repr(),
            share.sg.into_repr(),
            share.sg_prime.into_repr(),
        ];
        let mut power = E::Fr::one();
        for _ in 0..commitments.len() {
            scalars.push((-power).into_repr());
            power *= j_fr;
        }

        let product = VariableBaseMSM::multi_scalar_mul(&bases, &scalars);
        if !product.is_zero() {
            return Err(DKGError::PedersenShareCheckError(j));
        }
        Ok(())
    }

    /// Verify every receiver's share (`j = 1..=shares.len()`) against the
    /// commitments. Returns the first failing receiver, if any.
    pub fn verify_all(&self, generators: &PedersenGenerators<E>) -> Result<(), DKGError<E>> {
        for (i, share) in self.shares.iter().enumerate() {
            Self::verify_share(generators, &self.commitments, i + 1, share)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{PedersenDistribution, PedersenGenerators};
    use crate::dkg::mss::MSSPolynomial;
    use ark_bls12_381::{Bls12_381, Fr, G1Projective};
    use ark_ec::ProjectiveCurve;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    type Pedersen = PedersenDistribution<Bls12_381>;
    type Gens = PedersenGenerators<Bls12_381>;
    type MSS = MSSPolynomial<Bls12_381>;

    #[test]
    fn test_generators_distinct() {
        let gens = Gens::setup().unwrap();
        // NUMS generators must be distinct (and non-trivially related).
        assert_ne!(gens.g1, gens.g2);
        assert_ne!(gens.g1, gens.h1);
        assert_ne!(gens.g1, gens.h2);
        assert_ne!(gens.g2, gens.h1);
        assert_ne!(gens.g2, gens.h2);
        assert_ne!(gens.h1, gens.h2);
        // Deterministic derivation.
        let gens2 = Gens::setup().unwrap();
        assert_eq!(gens.g1, gens2.g1);
    }

    #[test]
    fn test_honest_shares_verify() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (dist, _secrets) = Pedersen::deal(&gens, 3, 8, rng).unwrap();
        dist.verify_all(&gens).unwrap();
    }

    #[test]
    fn test_recovered_secrets_match() {
        // The Pedersen layer should reconstruct (x1,x2,y1,y2) from t+1 shares.
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let degree = 4;
        let n = 9;
        let (dist, secrets) = Pedersen::deal(&gens, degree, n, rng).unwrap();

        let f_points = dist
            .shares
            .iter()
            .enumerate()
            .take(degree + 1)
            .map(|(i, s)| (MSS::point((i + 1) as i64), s.sf))
            .collect::<Vec<_>>();
        let g_points = dist
            .shares
            .iter()
            .enumerate()
            .take(degree + 1)
            .map(|(i, s)| (MSS::point((i + 1) as i64), s.sg))
            .collect::<Vec<_>>();

        assert_eq!(
            MSS::recover(MSS::point_minus1(), &f_points).unwrap(),
            secrets.x1
        );
        assert_eq!(
            MSS::recover(MSS::point_minus2(), &f_points).unwrap(),
            secrets.y1
        );
        assert_eq!(
            MSS::recover(MSS::point_minus1(), &g_points).unwrap(),
            secrets.x2
        );
        assert_eq!(
            MSS::recover(MSS::point_minus2(), &g_points).unwrap(),
            secrets.y2
        );
    }

    #[test]
    fn test_tampered_share_fails() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (mut dist, _secrets) = Pedersen::deal(&gens, 3, 8, rng).unwrap();

        // Corrupt one component of receiver 3's share (index 2).
        dist.shares[2].sf += Fr::rand(rng);
        assert!(dist.verify_all(&gens).is_err());
        // The other receivers still verify individually.
        Pedersen::verify_share(&gens, &dist.commitments, 1, &dist.shares[0]).unwrap();
    }

    #[test]
    fn test_tampered_commitment_fails() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let (mut dist, _secrets) = Pedersen::deal(&gens, 3, 8, rng).unwrap();

        dist.commitments[1] = G1Projective::rand(rng).into_affine();
        assert!(dist.verify_all(&gens).is_err());
    }
}
