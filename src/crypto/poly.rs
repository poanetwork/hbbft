//! Utilities for distributed key generation: uni- and bivariate polynomials and commitments.
//!
//! If `G` is a group of prime order `r` (written additively), and `g` is a generator, then
//! multiplication by integers factors through `r`, so the map `x -> x * g` (the sum of `x`
//! copies of `g`) is a homomorphism from the field `Fr` of integers modulo `r` to `G`. If the
//! _discrete logarithm_ is hard, i.e. it is infeasible to reverse this map, then `x * g` can be
//! considered a _commitment_ to `x`: By publishing it, you can guarantee to others that you won't
//! change your mind about the value `x`, without revealing it.
//!
//! This concept extends to polynomials: If you have a polynomial `f` over `Fr`, defined as
//! `a * X * X + b * X + c`, you can publish `a * g`, `b * g` and `c * g`. Then others will be able
//! to verify any single value `f(x)` of the polynomial without learning the original polynomial,
//! because `f(x) * g == x * x * (a * g) + x * (b * g) + (c * g)`. Only after learning three (in
//! general `degree + 1`) values, they can interpolate `f` itself.
//!
//! This module defines univariate polynomials (in one variable) and _symmetric_ bivariate
//! polynomials (in two variables) over a field `Fr`, as well as their _commitments_ in `G`.

use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem::{size_of, size_of_val};
use std::{cmp, iter, ops};

use memsec::{memzero, mlock, munlock};
use pairing::bls12_381::{Fr, G1, G1Affine};
use pairing::{CurveAffine, CurveProjective, Field};
use rand::Rng;

use super::{ContainsSecret, IntoFr};

/// A univariate polynomial in the prime field.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct Poly {
    /// The coefficients of a polynomial.
    #[serde(with = "super::serde_impl::field_vec")]
    pub(super) coeff: Vec<Fr>,
}

impl From<Vec<Fr>> for Poly {
    fn from(coeff: Vec<Fr>) -> Self {
        let poly = Poly { coeff };
        poly.mlock_secret_memory();
        poly
    }
}

impl Clone for Poly {
    fn clone(&self) -> Self {
        Poly::from(self.coeff.clone())
    }
}

/// A debug statement where the `coeff` vector of prime field elements has
/// been redacted.
impl fmt::Debug for Poly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Poly {{ coeff: ... }}")
    }
}

impl<B: Borrow<Poly>> ops::AddAssign<B> for Poly {
    fn add_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, Fr::zero());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.add_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly>> ops::Add<B> for &'a Poly {
    type Output = Poly;

    fn add(self, rhs: B) -> Poly {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Poly>> ops::Add<B> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: B) -> Poly {
        self += rhs;
        self
    }
}

impl<'a> ops::Add<Fr> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: Fr) -> Self::Output {
        if self.coeff.is_empty() {
            if !rhs.is_zero() {
                self.coeff.push(rhs);
            }
        } else {
            self.coeff[0].add_assign(&rhs);
            self.remove_zeros();
        }
        self
    }
}

impl<'a> ops::Add<u64> for Poly {
    type Output = Poly;

    fn add(self, rhs: u64) -> Self::Output {
        self + rhs.into_fr()
    }
}

impl<B: Borrow<Poly>> ops::SubAssign<B> for Poly {
    fn sub_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, Fr::zero());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.sub_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly>> ops::Sub<B> for &'a Poly {
    type Output = Poly;

    fn sub(self, rhs: B) -> Poly {
        (*self).clone() - rhs
    }
}

impl<B: Borrow<Poly>> ops::Sub<B> for Poly {
    type Output = Poly;

    fn sub(mut self, rhs: B) -> Poly {
        self -= rhs;
        self
    }
}

// Clippy thinks using `+` in a `Sub` implementation is suspicious.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl<'a> ops::Sub<Fr> for Poly {
    type Output = Poly;

    fn sub(self, mut rhs: Fr) -> Self::Output {
        rhs.negate();
        self + rhs
    }
}

impl<'a> ops::Sub<u64> for Poly {
    type Output = Poly;

    fn sub(self, rhs: u64) -> Self::Output {
        self - rhs.into_fr()
    }
}

// Clippy thinks using any `+` and `-` in a `Mul` implementation is suspicious.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl<'a, B: Borrow<Poly>> ops::Mul<B> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        let coeff: Vec<Fr> = (0..(self.coeff.len() + rhs.borrow().coeff.len() - 1))
            .map(|i| {
                // TODO: clear these secrets from the stack.
                let mut c = Fr::zero();
                for j in i.saturating_sub(rhs.borrow().degree())..(1 + cmp::min(i, self.degree())) {
                    let mut s = self.coeff[j];
                    s.mul_assign(&rhs.borrow().coeff[i - j]);
                    c.add_assign(&s);
                }
                c
            })
            .collect();
        Poly::from(coeff)
    }
}

impl<B: Borrow<Poly>> ops::Mul<B> for Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        &self * rhs
    }
}

impl<B: Borrow<Self>> ops::MulAssign<B> for Poly {
    fn mul_assign(&mut self, rhs: B) {
        *self = &*self * rhs;
    }
}

impl<'a> ops::Mul<Fr> for Poly {
    type Output = Poly;

    fn mul(mut self, rhs: Fr) -> Self::Output {
        if rhs.is_zero() {
            self.coeff.clear();
        } else {
            self.coeff.iter_mut().for_each(|c| c.mul_assign(&rhs));
        }
        self
    }
}

impl<'a> ops::Mul<u64> for Poly {
    type Output = Poly;

    fn mul(self, rhs: u64) -> Self::Output {
        self * rhs.into_fr()
    }
}

impl Drop for Poly {
    fn drop(&mut self) {
        self.zero_secret_memory();
        self.munlock_secret_memory();
    }
}

impl ContainsSecret for Poly {
    fn mlock_secret_memory(&self) {
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        unsafe {
            if !mlock(ptr, n_bytes) {
                println!("POLY MLOCK FAILED!");
            }
        }
    }

    fn munlock_secret_memory(&self) {
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        unsafe {
            if !munlock(ptr, n_bytes) {
                println!("POLY MUNLOCK FAILED!");
            }
        }
    }

    fn zero_secret_memory(&self) {
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        unsafe {
            memzero(ptr, n_bytes);
        }
    }
}

impl Poly {
    /// Creates a random polynomial.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Self {
        let coeff: Vec<Fr> = (0..=degree).map(|_| rng.gen()).collect();
        Poly::from(coeff)
    }

    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Poly::from(vec![])
    }

    /// Returns the polynomial with constant value `1`.
    pub fn one() -> Self {
        Self::monomial(0)
    }

    /// Returns the polynomial with constant value `c`.
    pub fn constant(c: Fr) -> Self {
        // TODO: clear secret `Fr` argument from stack frame.
        Poly::from(vec![c])
    }

    /// Returns the identity function, i.e. the polynomial "`x`".
    pub fn identity() -> Self {
        Self::monomial(1)
    }

    /// Returns the (monic) monomial "`x.pow(degree)`".
    pub fn monomial(degree: usize) -> Self {
        let coeff: Vec<Fr> = iter::repeat(Fr::zero())
            .take(degree)
            .chain(iter::once(Fr::one()))
            .collect();
        Poly::from(coeff)
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    pub fn interpolate<T, U, I>(samples_repr: I) -> Self
    where
        I: IntoIterator<Item = (T, U)>,
        T: IntoFr,
        U: IntoFr,
    {
        let convert = |(x, y): (T, U)| (x.into_fr(), y.into_fr());
        let samples: Vec<(Fr, Fr)> = samples_repr.into_iter().map(convert).collect();
        Self::compute_interpolation(&samples)
    }

    /// Returns the degree.
    pub fn degree(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the value at the point `i`.
    pub fn evaluate<T: IntoFr>(&self, i: T) -> Fr {
        let mut result = match self.coeff.last() {
            None => return Fr::zero(),
            Some(c) => *c,
        };
        let x = i.into_fr();
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(&x);
            result.add_assign(c);
        }
        result
    }

    /// Returns the corresponding commitment.
    pub fn commitment(&self) -> Commitment {
        let to_g1 = |c: &Fr| G1Affine::one().mul(*c);
        Commitment {
            coeff: self.coeff.iter().map(to_g1).collect(),
        }
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_zero()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len);
        self.munlock_truncated(zeros);
    }

    // Removes the `mlock` for zero prime field elements that have been
    // truncated from the `coeff` vector.
    fn munlock_truncated(&self, len: usize) {
        let n_bytes_truncated = len * size_of::<Fr>();
        unsafe {
            let ptr = self.coeff.as_ptr().offset(self.coeff.len() as isize) as *mut u8;
            if !munlock(ptr, n_bytes_truncated) {
                println!("POLY TRUNCATE MUNLOCK FAILED!");
            }
        }
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    fn compute_interpolation(samples: &[(Fr, Fr)]) -> Self {
        if samples.is_empty() {
            return Poly::zero();
        } else if samples.len() == 1 {
            return Poly::constant(samples[0].1);
        }
        // The degree is at least 1 now.
        let degree = samples.len() - 1;
        // Interpolate all but the last sample.
        let prev = Self::compute_interpolation(&samples[..degree]);
        let (x, mut y) = samples[degree]; // The last sample.
        y.sub_assign(&prev.evaluate(x));
        let step = Self::lagrange(x, &samples[..degree]);
        prev + step * Self::constant(y)
    }

    /// Returns the Lagrange base polynomial that is `1` in `p` and `0` in every `samples[i].0`.
    fn lagrange(p: Fr, samples: &[(Fr, Fr)]) -> Self {
        let mut result = Self::one();
        for &(sx, _) in samples {
            let mut denom = p;
            denom.sub_assign(&sx);
            denom = denom.inverse().expect("sample points must be distinct");
            result *= (Self::identity() - Self::constant(sx)) * Self::constant(denom);
        }
        result
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field elements.
    pub fn reveal(&self) -> String {
        format!("Poly {{ coeff: {:?} }}", self.coeff)
    }
}

/// A commitment to a univariate polynomial.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// The coefficients of the polynomial.
    #[serde(with = "super::serde_impl::projective_vec")]
    pub(super) coeff: Vec<G1>,
}

impl Hash for Commitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.coeff.len().hash(state);
        for c in &self.coeff {
            c.into_affine().into_compressed().as_ref().hash(state);
        }
    }
}

impl<B: Borrow<Commitment>> ops::AddAssign<B> for Commitment {
    fn add_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, G1::zero());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.add_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Commitment>> ops::Add<B> for &'a Commitment {
    type Output = Commitment;

    fn add(self, rhs: B) -> Commitment {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Commitment>> ops::Add<B> for Commitment {
    type Output = Commitment;

    fn add(mut self, rhs: B) -> Commitment {
        self += rhs;
        self
    }
}

impl Commitment {
    /// Returns the polynomial's degree.
    pub fn degree(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the `i`-th public key share.
    pub fn evaluate<T: IntoFr>(&self, i: T) -> G1 {
        let mut result = match self.coeff.last() {
            None => return G1::zero(),
            Some(c) => *c,
        };
        let x = i.into_fr();
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(x);
            result.add_assign(c);
        }
        result
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_zero()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len)
    }
}

/// A symmetric bivariate polynomial in the prime field.
///
/// This can be used for Verifiable Secret Sharing and Distributed Key Generation. See the module
/// documentation for details.
pub struct BivarPoly {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The coefficients of the polynomial. Coefficient `(i, j)` for `i <= j` is in position
    /// `j * (j + 1) / 2 + i`.
    coeff: Vec<Fr>,
}

impl Clone for BivarPoly {
    fn clone(&self) -> Self {
        let poly = BivarPoly {
            degree: self.degree,
            coeff: self.coeff.clone(),
        };
        poly.mlock_secret_memory();
        poly
    }
}

impl Drop for BivarPoly {
    fn drop(&mut self) {
        self.zero_secret_memory();
        self.munlock_secret_memory();
    }
}

/// A debug statement where the `coeff` vector of prime field elements has
/// been redacted.
impl fmt::Debug for BivarPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BivarPoly {{ degree: {}, coeff: ... }}", self.degree)
    }
}

impl ContainsSecret for BivarPoly {
    fn mlock_secret_memory(&self) {
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        unsafe {
            if !mlock(ptr, n_bytes) {
                println!("BivarPoly MLOCK FAILED!");
            }
        }
    }

    fn munlock_secret_memory(&self) {
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        unsafe {
            if !munlock(ptr, n_bytes) {
                println!("BivarPoly MUNLOCK FAILED!");
            }
        }
    }

    fn zero_secret_memory(&self) {
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        unsafe {
            memzero(ptr, n_bytes);
        }
    }
}

impl BivarPoly {
    /// Creates a random polynomial.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Self {
        let poly = BivarPoly {
            degree,
            coeff: (0..coeff_pos(degree + 1, 0)).map(|_| rng.gen()).collect(),
        };
        poly.mlock_secret_memory();
        poly
    }

    /// Returns the polynomial's degree: It is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the polynomial's value at the point `(x, y)`.
    pub fn evaluate<T: IntoFr>(&self, x: T, y: T) -> Fr {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = Fr::zero();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let mut summand = self.coeff[coeff_pos(i, j)];
                summand.mul_assign(&x_pow_i);
                summand.mul_assign(y_pow_j);
                result.add_assign(&summand);
            }
        }
        result
    }

    /// Returns the `x`-th row, as a univariate polynomial.
    pub fn row<T: IntoFr>(&self, x: T) -> Poly {
        let x_pow = self.powers(x);
        let coeff: Vec<Fr> = (0..=self.degree)
            .map(|i| {
                // TODO: clear these secrets from the stack.
                let mut result = Fr::zero();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let mut summand = self.coeff[coeff_pos(i, j)];
                    summand.mul_assign(x_pow_j);
                    result.add_assign(&summand);
                }
                result
            })
            .collect();
        Poly::from(coeff)
    }

    /// Returns the corresponding commitment. That information can be shared publicly.
    pub fn commitment(&self) -> BivarCommitment {
        let to_pub = |c: &Fr| G1Affine::one().mul(*c);
        BivarCommitment {
            degree: self.degree,
            coeff: self.coeff.iter().map(to_pub).collect(),
        }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: IntoFr>(&self, x: T) -> Vec<Fr> {
        powers(x, self.degree)
    }

    /// Generates a non-redacted debug string. This method differs from the
    /// `Debug` implementation in that it *does* leak the the struct's
    /// internal state.
    pub fn reveal(&self) -> String {
        format!(
            "BivarPoly {{ degree: {}, coeff: {:?} }}",
            self.degree, self.coeff
        )
    }
}

/// A commitment to a symmetric bivariate polynomial.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct BivarCommitment {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The commitments to the coefficients.
    #[serde(with = "super::serde_impl::projective_vec")]
    coeff: Vec<G1>,
}

impl Hash for BivarCommitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.degree.hash(state);
        for c in &self.coeff {
            c.into_affine().into_compressed().as_ref().hash(state);
        }
    }
}

impl BivarCommitment {
    /// Returns the polynomial's degree: It is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the commitment's value at the point `(x, y)`.
    pub fn evaluate<T: IntoFr>(&self, x: T, y: T) -> G1 {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = G1::zero();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let mut summand = self.coeff[coeff_pos(i, j)];
                summand.mul_assign(x_pow_i);
                summand.mul_assign(*y_pow_j);
                result.add_assign(&summand);
            }
        }
        result
    }

    /// Returns the `x`-th row, as a commitment to a univariate polynomial.
    pub fn row<T: IntoFr>(&self, x: T) -> Commitment {
        let x_pow = self.powers(x);
        let coeff: Vec<G1> = (0..=self.degree)
            .map(|i| {
                let mut result = G1::zero();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let mut summand = self.coeff[coeff_pos(i, j)];
                    summand.mul_assign(*x_pow_j);
                    result.add_assign(&summand);
                }
                result
            })
            .collect();
        Commitment { coeff }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: IntoFr>(&self, x: T) -> Vec<Fr> {
        powers(x, self.degree)
    }
}

/// Returns the `0`-th to `degree`-th power of `x`.
fn powers<T: IntoFr>(into_x: T, degree: usize) -> Vec<Fr> {
    let x = into_x.into_fr();
    let mut x_pow_i = Fr::one();
    iter::once(x_pow_i)
        .chain((0..degree).map(|_| {
            x_pow_i.mul_assign(&x);
            x_pow_i
        }))
        .collect()
}

/// Returns the position of coefficient `(i, j)` in the vector describing a symmetric bivariate
/// polynomial.
fn coeff_pos(i: usize, j: usize) -> usize {
    // Since the polynomial is symmetric, we can order such that `j >= i`.
    if j >= i {
        j * (j + 1) / 2 + i
    } else {
        i * (i + 1) / 2 + j
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{coeff_pos, BivarPoly, IntoFr, Poly};

    use pairing::bls12_381::{Fr, G1Affine};
    use pairing::{CurveAffine, Field};
    use rand;

    #[test]
    fn test_coeff_pos() {
        let mut i = 0;
        let mut j = 0;
        for n in 0..100 {
            assert_eq!(n, coeff_pos(i, j));
            if i >= j {
                j += 1;
                i = 0;
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn poly() {
        // The polynomial 5 X³ + X - 2.
        let poly = Poly::monomial(3) * 5 + Poly::monomial(1) - 2;
        let coeff: Vec<_> = [-2, 1, 0, 5].into_iter().map(IntoFr::into_fr).collect();
        assert_eq!(Poly { coeff }, poly);
        let samples = vec![(-1, -8), (2, 40), (3, 136), (5, 628)];
        for &(x, y) in &samples {
            assert_eq!(y.into_fr(), poly.evaluate(x));
        }
        assert_eq!(Poly::interpolate(samples), poly);
    }

    #[test]
    fn distributed_key_generation() {
        let mut rng = rand::thread_rng();
        let dealer_num = 3;
        let node_num = 5;
        let faulty_num = 2;

        // For distributed key generation, a number of dealers, only one of who needs to be honest,
        // generates random bivariate polynomials and publicly commits to them. In partice, the
        // dealers can e.g. be any `faulty_num + 1` nodes.
        let bi_polys: Vec<BivarPoly> = (0..dealer_num)
            .map(|_| BivarPoly::random(faulty_num, &mut rng))
            .collect();
        let pub_bi_commits: Vec<_> = bi_polys.iter().map(BivarPoly::commitment).collect();

        let mut sec_keys = vec![Fr::zero(); node_num];

        // Each dealer sends row `m` to node `m`, where the index starts at `1`. Don't send row `0`
        // to anyone! The nodes verify their rows, and send _value_ `s` on to node `s`. They again
        // verify the values they received, and collect them.
        for (bi_poly, bi_commit) in bi_polys.iter().zip(&pub_bi_commits) {
            for m in 1..=node_num {
                // Node `m` receives its row and verifies it.
                let row_poly = bi_poly.row(m);
                let row_commit = bi_commit.row(m);
                assert_eq!(row_poly.commitment(), row_commit);
                // Node `s` receives the `s`-th value and verifies it.
                for s in 1..=node_num {
                    let val = row_poly.evaluate(s);
                    let val_g1 = G1Affine::one().mul(val);
                    assert_eq!(bi_commit.evaluate(m, s), val_g1);
                    // The node can't verify this directly, but it should have the correct value:
                    assert_eq!(bi_poly.evaluate(m, s), val);
                }

                // A cheating dealer who modified the polynomial would be detected.
                let wrong_poly = row_poly.clone() + Poly::monomial(2) * Poly::constant(5.into_fr());
                assert_ne!(wrong_poly.commitment(), row_commit);

                // If `2 * faulty_num + 1` nodes confirm that they received a valid row, then at
                // least `faulty_num + 1` honest ones did, and sent the correct values on to node
                // `s`. So every node received at least `faulty_num + 1` correct entries of their
                // column/row (remember that the bivariate polynomial is symmetric). They can
                // reconstruct the full row and in particular value `0` (which no other node knows,
                // only the dealer). E.g. let's say nodes `1`, `2` and `4` are honest. Then node
                // `m` received three correct entries from that row:
                let received: BTreeMap<_, _> = [1, 2, 4]
                    .iter()
                    .map(|&i| (i, bi_poly.evaluate(m, i)))
                    .collect();
                let my_row = Poly::interpolate(received);
                assert_eq!(bi_poly.evaluate(m, 0), my_row.evaluate(0));
                assert_eq!(row_poly, my_row);

                // The node sums up all values number `0` it received from the different dealer. No
                // dealer and no other node knows the sum in the end.
                sec_keys[m - 1].add_assign(&my_row.evaluate(Fr::zero()));
            }
        }

        // Each node now adds up all the first values of the rows it received from the different
        // dealers (excluding the dealers where fewer than `2 * faulty_num + 1` nodes confirmed).
        // The whole first column never gets added up in practice, because nobody has all the
        // information. We do it anyway here; entry `0` is the secret key that is not known to
        // anyone, neither a dealer, nor a node:
        let mut sec_key_set = Poly::zero();
        for bi_poly in &bi_polys {
            sec_key_set += bi_poly.row(0);
        }
        for m in 1..=node_num {
            assert_eq!(sec_key_set.evaluate(m), sec_keys[m - 1]);
        }

        // The sum of the first rows of the public commitments is the commitment to the secret key
        // set.
        let mut sum_commit = Poly::zero().commitment();
        for bi_commit in &pub_bi_commits {
            sum_commit += bi_commit.row(0);
        }
        assert_eq!(sum_commit, sec_key_set.commitment());
    }
}
