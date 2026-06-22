//! Share encryption for the (x1,x2,y1,y2) layer.
//!
//! The paper's `enc(s) = s · pk^s` is native to a Zp* multiplicative group and
//! doesn't map onto an elliptic curve, so we use exponential ElGamal on G1
//! instead. Each scalar share is encrypted under its matching Pedersen generator
//! `base in {g1, h1, g2, h2}`:
//!
//! ```text
//! (R, C) = (g^r, base^s · pk^r),   pk = g^sk
//! dec:    base^s = C - sk·R
//! ```
//!
//! The receiver therefore recovers the group element `base^s`, not the scalar, so
//! verification and reconstruction are done in the exponent - matching the z layer
//! (whose recovered secret is also a group element) and pk = (c1,c2,c3).

use crate::dkg::{errors::DKGError, pedersen::PedersenGenerators, pedersen::PedersenShare};
use crate::signature::utils::hash::hash_to_group;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use rand::Rng;

/// Domain separator for the ElGamal base derivation (8 bytes for blake2s).
const PERSONALIZATION: &[u8] = b"DMKGENCR";

/// The public ElGamal base `g ∈ G1` used to form `R = g^r` and receiver public
/// keys `pkⱼ = g^{skⱼ}`. Derived by hash-to-curve so it is independent of the
/// four Pedersen commitment generators.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ElGamalBase<E: PairingEngine> {
    pub g: E::G1Affine,
}

impl<E: PairingEngine> ElGamalBase<E> {
    pub fn setup() -> Result<Self, DKGError<E>> {
        Ok(Self {
            g: hash_to_group::<E::G1Affine>(PERSONALIZATION, b"elgamal-base")?.into_affine(),
        })
    }
}

/// A receiver's ElGamal keypair on `G1`: `pk = g^{sk}`.
#[derive(Clone, Debug)]
pub struct ElGamalKeypair<E: PairingEngine> {
    pub sk: E::Fr,
    pub pk: E::G1Affine,
}

impl<E: PairingEngine> ElGamalKeypair<E> {
    pub fn generate<R: Rng>(base: &ElGamalBase<E>, rng: &mut R) -> Self {
        let sk = E::Fr::rand(rng);
        let pk = base.g.mul(sk.into_repr()).into_affine();
        Self { sk, pk }
    }
}

/// One ElGamal ciphertext `(R, C) = (g^r, base^{s}·pkⱼ^{r})`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ElGamalCiphertext<E: PairingEngine> {
    pub r: E::G1Affine,
    pub c: E::G1Affine,
}

impl<E: PairingEngine> ElGamalCiphertext<E> {
    /// Encrypt a group-element message `m = base^{s}` to receiver public key `pk`.
    pub fn encrypt<R: Rng>(
        base: &ElGamalBase<E>,
        pk: &E::G1Affine,
        m: E::G1Affine,
        rng: &mut R,
    ) -> Self {
        let r_scalar = E::Fr::rand(rng);
        let r = base.g.mul(r_scalar.into_repr()).into_affine();
        let c = (m.into_projective() + pk.mul(r_scalar.into_repr())).into_affine();
        Self { r, c }
    }

    /// Decrypt to recover the group-element message `base^{s} = C - sk·R`.
    pub fn decrypt(&self, sk: E::Fr) -> E::G1Affine {
        (self.c.into_projective() - self.r.mul(sk.into_repr())).into_affine()
    }
}

/// A receiver's four-component encrypted share. Each component encrypts the
/// matching Pedersen generator raised to the scalar share, i.e. the messages are
/// `g1^{sf}`, `h1^{sf'}`, `g2^{sg}`, `h2^{sg'}`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct EncryptedPedersenShare<E: PairingEngine> {
    pub sf: ElGamalCiphertext<E>,
    pub sf_prime: ElGamalCiphertext<E>,
    pub sg: ElGamalCiphertext<E>,
    pub sg_prime: ElGamalCiphertext<E>,
}

/// The four group-element messages recovered from an [`EncryptedPedersenShare`]:
/// `(g1^{sf}, h1^{sf'}, g2^{sg}, h2^{sg'})`.
#[derive(Clone, Debug)]
pub struct RecoveredShareMessages<E: PairingEngine> {
    pub m_sf: E::G1Affine,
    pub m_sf_prime: E::G1Affine,
    pub m_sg: E::G1Affine,
    pub m_sg_prime: E::G1Affine,
}

impl<E: PairingEngine> EncryptedPedersenShare<E> {
    /// Encrypt a cleartext share quadruple to receiver `Pⱼ` (public key `pk`),
    /// committing each scalar under its matching Pedersen generator.
    pub fn encrypt<R: Rng>(
        generators: &PedersenGenerators<E>,
        base: &ElGamalBase<E>,
        pk: &E::G1Affine,
        share: &PedersenShare<E>,
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
    pub fn decrypt(&self, sk: E::Fr) -> RecoveredShareMessages<E> {
        RecoveredShareMessages {
            m_sf: self.sf.decrypt(sk),
            m_sf_prime: self.sf_prime.decrypt(sk),
            m_sg: self.sg.decrypt(sk),
            m_sg_prime: self.sg_prime.decrypt(sk),
        }
    }
}

impl<E: PairingEngine> RecoveredShareMessages<E> {
    /// Eq. (1) in the exponent. Check that the recovered group-element share
    /// satisfies the Pedersen relation against the commitments at receiver `j`:
    ///
    /// ```text
    /// g1^{sf}·h1^{sf'}·g2^{sg}·h2^{sg'}  ==  ∏_{k} CMₖ^{ jᵏ }
    /// ```
    ///
    /// The left-hand side is exactly the product of the four recovered messages;
    /// no scalar is ever needed in the clear.
    pub fn verify(&self, commitments: &[E::G1Affine], j: usize) -> Result<(), DKGError<E>> {
        let j_fr = E::Fr::from(j as u64);
        let lhs = self.m_sf.into_projective()
            + self.m_sf_prime.into_projective()
            + self.m_sg.into_projective()
            + self.m_sg_prime.into_projective();

        let mut rhs = E::G1Projective::zero();
        let mut power = E::Fr::one();
        for cm in commitments.iter() {
            rhs += cm.mul(power.into_repr());
            power *= j_fr;
        }

        if lhs == rhs {
            Ok(())
        } else {
            Err(DKGError::PedersenShareCheckError(j))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{ElGamalBase, ElGamalCiphertext, ElGamalKeypair, EncryptedPedersenShare};
    use crate::dkg::mss::MSSPolynomial;
    use crate::dkg::pedersen::{PedersenDistribution, PedersenGenerators};
    use ark_bls12_381::{Bls12_381, G1Projective};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{PrimeField, UniformRand};
    use rand::thread_rng;

    type Base = ElGamalBase<Bls12_381>;
    type Keypair = ElGamalKeypair<Bls12_381>;
    type Gens = PedersenGenerators<Bls12_381>;
    type Pedersen = PedersenDistribution<Bls12_381>;
    type MSS = MSSPolynomial<Bls12_381>;

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
        // shares via Lagrange-in-exponent at the special point -1.
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

        // λ at -1 recovers f(-1) = x1, in the exponent of g1.
        let lambdas = MSS::lambda1(&indices).unwrap();
        let mut acc = G1Projective::default();
        for (lambda, m) in lambdas.iter().zip(messages.iter()) {
            acc += m.mul(lambda.into_repr());
        }
        let expected = gens.g1.mul(secrets.x1.into_repr());
        assert_eq!(acc, expected);
    }
}
