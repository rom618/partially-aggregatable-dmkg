//! Phase 4 — verifiable share encryption for the `(x1,x2,y1,y2)` layer
//! (paper §4.3 Phases 1–2, encryption scheme §2.4).
//!
//! # Design note / deviation from the paper
//!
//! The paper's literal scheme `enc(s) = s · pkⱼ^{s}` is *multiplicative-group
//! (`Zp*`) native*. On a single elliptic curve we take **option (B): lifted /
//! exponential ElGamal**:
//!
//! ```text
//! enc_base(s) = (R, C) = ( g^r ,  base^{s} · pkⱼ^{r} ),   pkⱼ = g^{skⱼ}
//! dec         : base^{s} = C − skⱼ · R
//! ```
//!
//! where `g` is a dedicated nothing-up-my-sleeve ElGamal base and `base` is the
//! Pedersen generator the encrypted component is committed under. The receiver
//! recovers `base^{s}` as a *group element*; verification (Eq. 1) and
//! reconstruction happen **in the exponent**.
//!
//! Like the rest of the `(x1,x2,y1,y2)` layer this uses only plain group
//! operations, so it is generic over `C: ProjectiveCurve` (Jubjub for the
//! pairing-free DMKGs, BLS12-381 `G1` for the partially-aggregatable one).

use crate::dkg::{errors::VssError, pedersen::PedersenGenerators, pedersen::PedersenShare};
use crate::signature::utils::hash::hash_to_group;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use rand::Rng;

/// Domain separator for the ElGamal base derivation (8 bytes for blake2s).
const PERSONALIZATION: &[u8] = b"DMKGENCR";

/// The public ElGamal base `g` used to form `R = g^r` and receiver public keys
/// `pkⱼ = g^{skⱼ}`. Derived by hash-to-curve so it is independent of the four
/// Pedersen commitment generators.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ElGamalBase<C: ProjectiveCurve> {
    pub g: C::Affine,
}

impl<C: ProjectiveCurve> ElGamalBase<C> {
    pub fn setup() -> Result<Self, VssError> {
        Ok(Self {
            g: hash_to_group::<C::Affine>(PERSONALIZATION, b"elgamal-base")
                .map_err(|_| VssError::Malformed("hash-to-curve failed"))?
                .into_affine(),
        })
    }
}

/// A receiver's ElGamal keypair: `pk = g^{sk}`.
#[derive(Clone, Debug)]
pub struct ElGamalKeypair<C: ProjectiveCurve> {
    pub sk: C::ScalarField,
    pub pk: C::Affine,
}

impl<C: ProjectiveCurve> ElGamalKeypair<C> {
    pub fn generate<R: Rng>(base: &ElGamalBase<C>, rng: &mut R) -> Self {
        let sk = C::ScalarField::rand(rng);
        let pk = base.g.mul(sk.into_repr()).into_affine();
        Self { sk, pk }
    }
}

/// One ElGamal ciphertext `(R, C) = (g^r, base^{s}·pkⱼ^{r})`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ElGamalCiphertext<C: ProjectiveCurve> {
    pub r: C::Affine,
    pub c: C::Affine,
}

impl<C: ProjectiveCurve> ElGamalCiphertext<C> {
    /// Encrypt a group-element message `m = base^{s}` to receiver public key `pk`.
    pub fn encrypt<R: Rng>(
        base: &ElGamalBase<C>,
        pk: &C::Affine,
        m: C::Affine,
        rng: &mut R,
    ) -> Self {
        let r_scalar = C::ScalarField::rand(rng);
        let r = base.g.mul(r_scalar.into_repr()).into_affine();
        let c = (m.into_projective() + pk.mul(r_scalar.into_repr())).into_affine();
        Self { r, c }
    }

    /// Decrypt to recover the group-element message `base^{s} = C − sk·R`.
    pub fn decrypt(&self, sk: C::ScalarField) -> C::Affine {
        (self.c.into_projective() - self.r.mul(sk.into_repr())).into_affine()
    }
}

/// A receiver's four-component encrypted share. Each component encrypts the
/// matching Pedersen generator raised to the scalar share, i.e. the messages are
/// `g1^{sf}`, `h1^{sf'}`, `g2^{sg}`, `h2^{sg'}`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct EncryptedPedersenShare<C: ProjectiveCurve> {
    pub sf: ElGamalCiphertext<C>,
    pub sf_prime: ElGamalCiphertext<C>,
    pub sg: ElGamalCiphertext<C>,
    pub sg_prime: ElGamalCiphertext<C>,
}

/// The four group-element messages recovered from an [`EncryptedPedersenShare`]:
/// `(g1^{sf}, h1^{sf'}, g2^{sg}, h2^{sg'})`.
#[derive(Clone, Debug)]
pub struct RecoveredShareMessages<C: ProjectiveCurve> {
    pub m_sf: C::Affine,
    pub m_sf_prime: C::Affine,
    pub m_sg: C::Affine,
    pub m_sg_prime: C::Affine,
}

impl<C: ProjectiveCurve> EncryptedPedersenShare<C> {
    /// Encrypt a cleartext share quadruple to receiver `Pⱼ` (public key `pk`),
    /// committing each scalar under its matching Pedersen generator.
    pub fn encrypt<R: Rng>(
        generators: &PedersenGenerators<C>,
        base: &ElGamalBase<C>,
        pk: &C::Affine,
        share: &PedersenShare<C>,
        rng: &mut R,
    ) -> Self {
        let m_sf = generators.g1.mul(share.sf.into_repr()).into_affine();
        let m_sf_prime = generators.h1.mul(share.sf_prime.into_repr()).into_affine();
        let m_sg = generators.g2.mul(share.sg.into_repr()).into_affine();
        let m_sg_prime = generators.h2.mul(share.sg_prime.into_repr()).into_affine();
        Self {
            sf: ElGamalCiphertext::encrypt(base, pk, m_sf, rng),
            sf_prime: ElGamalCiphertext::encrypt(base, pk, m_sf_prime, rng),
            sg: ElGamalCiphertext::encrypt(base, pk, m_sg, rng),
            sg_prime: ElGamalCiphertext::encrypt(base, pk, m_sg_prime, rng),
        }
    }

    /// Decrypt all four components with receiver secret key `sk`.
    pub fn decrypt(&self, sk: C::ScalarField) -> RecoveredShareMessages<C> {
        RecoveredShareMessages {
            m_sf: self.sf.decrypt(sk),
            m_sf_prime: self.sf_prime.decrypt(sk),
            m_sg: self.sg.decrypt(sk),
            m_sg_prime: self.sg_prime.decrypt(sk),
        }
    }
}

impl<C: ProjectiveCurve> RecoveredShareMessages<C> {
    /// **Eq. (1) in the exponent.** Check that the recovered group-element share
    /// satisfies the Pedersen relation against the commitments at receiver `j`:
    ///
    /// ```text
    /// g1^{sf}·h1^{sf'}·g2^{sg}·h2^{sg'}  ==  ∏_{k} CMₖ^{ jᵏ }
    /// ```
    pub fn verify(&self, commitments: &[C::Affine], j: usize) -> Result<(), VssError> {
        let j_fr = C::ScalarField::from(j as u64);
        let lhs = self.m_sf.into_projective()
            + self.m_sf_prime.into_projective()
            + self.m_sg.into_projective()
            + self.m_sg_prime.into_projective();

        let mut rhs = C::zero();
        let mut power = C::ScalarField::one();
        for cm in commitments.iter() {
            rhs += cm.mul(power.into_repr());
            power *= j_fr;
        }

        if lhs == rhs {
            Ok(())
        } else {
            Err(VssError::ShareCheck(j))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{ElGamalBase, ElGamalCiphertext, ElGamalKeypair, EncryptedPedersenShare};
    use crate::dkg::mss::MSSPolynomial;
    use crate::dkg::pedersen::{PedersenDistribution, PedersenGenerators};
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{PrimeField, UniformRand};
    use rand::thread_rng;

    type Base = ElGamalBase<G1Projective>;
    type Keypair = ElGamalKeypair<G1Projective>;
    type Gens = PedersenGenerators<G1Projective>;
    type Pedersen = PedersenDistribution<G1Projective>;
    type MSS = MSSPolynomial<Fr>;

    #[test]
    fn test_ciphertext_roundtrip() {
        let rng = &mut thread_rng();
        let base = Base::setup().unwrap();
        let kp = Keypair::generate(&base, rng);
        let m = G1Projective::rand(rng).into_affine();
        let ct = ElGamalCiphertext::encrypt(&base, &kp.pk, m, rng);
        assert_eq!(ct.decrypt(kp.sk), m);
    }

    #[test]
    fn test_wrong_key_fails() {
        let rng = &mut thread_rng();
        let base = Base::setup().unwrap();
        let kp = Keypair::generate(&base, rng);
        let other = Keypair::generate(&base, rng);
        let m = G1Projective::rand(rng).into_affine();
        let ct = ElGamalCiphertext::encrypt(&base, &kp.pk, m, rng);
        assert_ne!(ct.decrypt(other.sk), m);
    }

    #[test]
    fn test_encrypted_share_verifies_against_cm() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let base = Base::setup().unwrap();
        let degree = 3;
        let n = 8;
        let (dist, _secrets) = Pedersen::deal(&gens, degree, n, rng).unwrap();

        // Each receiver has its own ElGamal keypair.
        let keys: Vec<Keypair> = (0..n).map(|_| Keypair::generate(&base, rng)).collect();

        for (i, share) in dist.shares.iter().enumerate() {
            let ct = EncryptedPedersenShare::encrypt(&gens, &base, &keys[i].pk, share, rng);
            let recovered = ct.decrypt(keys[i].sk);
            // Honest share verifies in the exponent.
            recovered.verify(&dist.commitments, i + 1).unwrap();
        }
    }

    #[test]
    fn test_tampered_ciphertext_fails_verification() {
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let base = Base::setup().unwrap();
        let (dist, _secrets) = Pedersen::deal(&gens, 3, 8, rng).unwrap();
        let kp = Keypair::generate(&base, rng);

        let mut ct = EncryptedPedersenShare::encrypt(&gens, &base, &kp.pk, &dist.shares[2], rng);
        // Corrupt the ciphertext body of one component.
        ct.sf.c = G1Projective::rand(rng).into_affine();
        let recovered = ct.decrypt(kp.sk);
        assert!(recovered.verify(&dist.commitments, 3).is_err());
    }

    #[test]
    fn test_reconstruction_in_exponent() {
        // Reconstruct g1^{x1} (= pk component) from t+1 recovered group-element
        // shares via Lagrange-in-exponent at the special point −1.
        let rng = &mut thread_rng();
        let gens = Gens::setup().unwrap();
        let base = Base::setup().unwrap();
        let degree = 4;
        let n = 9;
        let (dist, secrets) = Pedersen::deal(&gens, degree, n, rng).unwrap();
        let keys: Vec<Keypair> = (0..n).map(|_| Keypair::generate(&base, rng)).collect();

        // Decrypt the first t+1 receivers' `g1^{sf}` messages.
        let mut indices = vec![];
        let mut messages = vec![];
        for i in 0..=degree {
            let ct =
                EncryptedPedersenShare::encrypt(&gens, &base, &keys[i].pk, &dist.shares[i], rng);
            let recovered = ct.decrypt(keys[i].sk);
            indices.push(MSS::point((i + 1) as i64));
            messages.push(recovered.m_sf);
        }

        // λ at −1 recovers f(−1) = x1, in the exponent of g1.
        let lambdas = MSS::lambda1(&indices).unwrap();
        let mut acc = G1Projective::default();
        for (lambda, m) in lambdas.iter().zip(messages.iter()) {
            acc += m.mul(lambda.into_repr());
        }
        let expected = gens.g1.mul(secrets.x1.into_repr());
        assert_eq!(acc, expected);
    }
}
