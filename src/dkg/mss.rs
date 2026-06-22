//! Franklin-Yung multi-secret sharing.
//!
//! A degree-`t` polynomial pins two secrets at the special points `f(-1) = s1`
//! and `f(-2) = s2`; the remaining `t-1` coefficients are random. Receivers
//! evaluate at integer points `j in [1,n]`, and any `t+1` shares Lagrange-recover
//! the values at `-1` and `-2`:
//!
//! ```text
//! lambda1_j = prod_{k != j} (-1-k)/(j-k)   recovers f(-1)
//! lambda2_j = prod_{k != j} (-2-k)/(j-k)   recovers f(-2)
//! ```
//!
//! This domain (integers plus -1, -2) is distinct from the roots-of-unity domain
//! used by the z/SCRAPE layer; the two must not be mixed.

use crate::dkg::errors::DKGError;
use ark_ec::PairingEngine;
use ark_ff::{Field, One, UniformRand, Zero};
use rand::Rng;
use std::marker::PhantomData;

/// A degree-`t` polynomial over `E::Fr`, pinned at the Franklin-Yung special
/// points `f(-1) = s₋₁`, `f(-2) = s₋₂`, with the remaining `t-1` coefficients
/// drawn at random.
///
/// `coeffs[k]` is the coefficient of `xᵏ`; `coeffs.len() == degree + 1`. This is
/// a dealer-local secret object (its shares and commitments go on the wire, not
/// the polynomial itself), so it deliberately does not derive serialization.
#[derive(Clone, Debug)]
pub struct MSSPolynomial<E: PairingEngine> {
    pub coeffs: Vec<E::Fr>,
    pairing_type: PhantomData<E>,
}

impl<E: PairingEngine> MSSPolynomial<E> {
    /// The special evaluation point `-1` (where `s₋₁`, i.e. `x1`/`x2`, lives).
    pub fn point_minus1() -> E::Fr {
        -E::Fr::one()
    }

    /// The special evaluation point `-2` (where `s₋₂`, i.e. `y1`/`y2`, lives).
    pub fn point_minus2() -> E::Fr {
        -(E::Fr::one() + E::Fr::one())
    }

    /// Field element for a (possibly negative) integer evaluation point.
    pub fn point(i: i64) -> E::Fr {
        if i >= 0 {
            E::Fr::from(i as u64)
        } else {
            -E::Fr::from((-i) as u64)
        }
    }

    /// Sample a degree-`t` polynomial with `f(-1) = s_minus1`, `f(-2) = s_minus2`
    /// and `t-1` random remaining coefficients.
    ///
    /// Coefficients `a₂..a_t` are drawn at random; `a₀, a₁` are then solved from
    /// the two linear constraints
    /// ```text
    ///   a₀ -   a₁ = s₋₁ - R₁,   R₁ = Σ_{k≥2} a_k·(-1)ᵏ
    ///   a₀ - 2 a₁ = s₋₂ - R₂,   R₂ = Σ_{k≥2} a_k·(-2)ᵏ
    /// ```
    pub fn sample<R: Rng>(
        degree: usize,
        s_minus1: E::Fr,
        s_minus2: E::Fr,
        rng: &mut R,
    ) -> Result<Self, DKGError<E>> {
        if degree < 1 {
            return Err(DKGError::MSSInsufficientDegree(degree));
        }

        let mut coeffs = vec![E::Fr::zero(); degree + 1];
        for c in coeffs.iter_mut().take(degree + 1).skip(2) {
            *c = E::Fr::rand(rng);
        }

        let m1 = Self::point_minus1();
        let m2 = Self::point_minus2();
        let mut r1 = E::Fr::zero();
        let mut r2 = E::Fr::zero();
        for (k, c) in coeffs.iter().enumerate().skip(2) {
            r1 += *c * m1.pow([k as u64]);
            r2 += *c * m2.pow([k as u64]);
        }

        let rhs1 = s_minus1 - r1; // a₀ -  a₁
        let rhs2 = s_minus2 - r2; // a₀ - 2a₁
        let a1 = rhs1 - rhs2; // (a₀-a₁) - (a₀-2a₁)
        let a0 = rhs1 + a1; // a₀ = (a₀-a₁) + a₁
        coeffs[0] = a0;
        coeffs[1] = a1;

        Ok(Self {
            coeffs,
            pairing_type: PhantomData,
        })
    }

    /// Evaluate the polynomial at an arbitrary field point (Horner's method).
    pub fn evaluate(&self, x: E::Fr) -> E::Fr {
        let mut acc = E::Fr::zero();
        for c in self.coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }

    /// Evaluate at an integer point (e.g. a receiver index `j`, or `-1`/`-2`).
    pub fn evaluate_at(&self, i: i64) -> E::Fr {
        self.evaluate(Self::point(i))
    }

    /// The pinned secret `s₋₁ = f(-1)` (i.e. `x1` for `f`, `x2` for `g`).
    pub fn secret_minus1(&self) -> E::Fr {
        self.evaluate(Self::point_minus1())
    }

    /// The pinned secret `s₋₂ = f(-2)` (i.e. `y1` for `f`, `y2` for `g`).
    pub fn secret_minus2(&self) -> E::Fr {
        self.evaluate(Self::point_minus2())
    }

    /// Shares `f(1), …, f(n)` for receivers `j ∈ [1,n]`.
    pub fn shares(&self, n: usize) -> Vec<E::Fr> {
        (1..=n)
            .map(|j| self.evaluate(E::Fr::from(j as u64)))
            .collect()
    }

    /// Lagrange coefficients `λⱼ` for evaluating a polynomial at `target` from
    /// its values at `indices`: `f(target) = Σⱼ λⱼ · f(indexⱼ)`.
    ///
    /// `indices` must be distinct (and number at least `t+1` for an exact
    /// recovery of a degree-`t` polynomial; with fewer the result is meaningless,
    /// but only distinctness can be checked here).
    pub fn lagrange_coefficients(
        target: E::Fr,
        indices: &[E::Fr],
    ) -> Result<Vec<E::Fr>, DKGError<E>> {
        let mut coeffs = Vec::with_capacity(indices.len());
        for (i, xi) in indices.iter().enumerate() {
            let mut num = E::Fr::one();
            let mut den = E::Fr::one();
            for (k, xk) in indices.iter().enumerate() {
                if i == k {
                    continue;
                }
                num *= target - *xk;
                den *= *xi - *xk;
            }
            let den_inv = den.inverse().ok_or(DKGError::MSSBadIndices)?;
            coeffs.push(num * den_inv);
        }
        Ok(coeffs)
    }

    /// `λ1ⱼ`: Lagrange coefficients that recover `f(-1)` (the `x1`/`x2` slot).
    pub fn lambda1(indices: &[E::Fr]) -> Result<Vec<E::Fr>, DKGError<E>> {
        Self::lagrange_coefficients(Self::point_minus1(), indices)
    }

    /// `λ2ⱼ`: Lagrange coefficients that recover `f(-2)` (the `y1`/`y2` slot).
    pub fn lambda2(indices: &[E::Fr]) -> Result<Vec<E::Fr>, DKGError<E>> {
        Self::lagrange_coefficients(Self::point_minus2(), indices)
    }

    /// Recover `f(target)` from `(index, value)` pairs via Lagrange interpolation.
    pub fn recover(target: E::Fr, points: &[(E::Fr, E::Fr)]) -> Result<E::Fr, DKGError<E>> {
        let indices = points.iter().map(|(x, _)| *x).collect::<Vec<_>>();
        let lambdas = Self::lagrange_coefficients(target, &indices)?;
        let mut acc = E::Fr::zero();
        for (lambda, (_, value)) in lambdas.iter().zip(points.iter()) {
            acc += *lambda * value;
        }
        Ok(acc)
    }
}

#[cfg(test)]
mod test {
    use super::MSSPolynomial;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::UniformRand;
    use rand::thread_rng;

    type MSS = MSSPolynomial<Bls12_381>;

    #[test]
    fn test_pinned_points_roundtrip() {
        let rng = &mut thread_rng();
        let degree = 3;

        // Two secrets per polynomial: f carries (x1, y1), g carries (x2, y2).
        let (x1, y1) = (Fr::rand(rng), Fr::rand(rng));
        let (x2, y2) = (Fr::rand(rng), Fr::rand(rng));

        let f = MSS::sample(degree, x1, y1, rng).unwrap();
        let g = MSS::sample(degree, x2, y2, rng).unwrap();

        assert_eq!(f.secret_minus1(), x1);
        assert_eq!(f.secret_minus2(), y1);
        assert_eq!(g.secret_minus1(), x2);
        assert_eq!(g.secret_minus2(), y2);
        assert_eq!(f.coeffs.len(), degree + 1);
    }

    #[test]
    fn test_lagrange_recovery_from_shares() {
        let rng = &mut thread_rng();
        let degree = 4;
        let n = 8;

        let (x1, y1) = (Fr::rand(rng), Fr::rand(rng));
        let f = MSS::sample(degree, x1, y1, rng).unwrap();

        // Recover from all n shares.
        let all_points = f
            .shares(n)
            .into_iter()
            .enumerate()
            .map(|(idx, value)| (MSS::point((idx + 1) as i64), value))
            .collect::<Vec<_>>();
        assert_eq!(MSS::recover(MSS::point_minus1(), &all_points).unwrap(), x1);
        assert_eq!(MSS::recover(MSS::point_minus2(), &all_points).unwrap(), y1);

        // Recover from an arbitrary subset of exactly t+1 shares.
        let subset = &all_points[..degree + 1];
        assert_eq!(MSS::recover(MSS::point_minus1(), subset).unwrap(), x1);
        assert_eq!(MSS::recover(MSS::point_minus2(), subset).unwrap(), y1);

        // The lambda helpers agree with `recover`.
        let indices = subset.iter().map(|(x, _)| *x).collect::<Vec<_>>();
        let lambda1 = MSS::lambda1(&indices).unwrap();
        let recovered_x1 = lambda1
            .iter()
            .zip(subset.iter())
            .fold(Fr::from(0u64), |acc, (l, (_, v))| acc + *l * v);
        assert_eq!(recovered_x1, x1);
    }

    #[test]
    fn test_degree_too_small_errors() {
        let rng = &mut thread_rng();
        assert!(MSS::sample(0, Fr::rand(rng), Fr::rand(rng), rng).is_err());
    }

    #[test]
    fn test_duplicate_indices_error() {
        let rng = &mut thread_rng();
        let degree = 2;
        let f = MSS::sample(degree, Fr::rand(rng), Fr::rand(rng), rng).unwrap();
        let v = f.evaluate_at(1);
        // Two identical indices -> zero denominator -> error, no panic.
        let points = [(MSS::point(1), v), (MSS::point(1), v)];
        assert!(MSS::recover(MSS::point_minus1(), &points).is_err());
    }
}
