//! Utilities for distributed key generation.
//!
//! A `BivarPoly` can be used for Verifiable Secret Sharing (VSS) and for key generation by a
//! trusted dealer. In a perfectly synchronous setting, e.g. on a blockchain or other agreed
//! transaction log, it works like this:
//!
//! The dealer generates a `BivarPoly` of degree `t` and publishes the `BivariateCommitment`,
//! with which the polynomial's values can be publicly verified. They then send _row_ `m > 0` to
//! node number `m`. Node `m`, in turn, sends _value_ `s` to node number `s`. Then if `2 * t + 1`
//! nodes confirm that they received a valid row, and there are at most `t` faulty nodes, then at
//! least `t + 1` honest nodes sent on an entry of every other node's column to that node. So we
//! know that every node can now reconstruct its column and the value at `0` of its column. These
//! values all lie on a univariate polynomial of degree `t`, so they can be used as secret keys.
//!
//! For Distributed Key Generation (DKG), every node proposes a polynomial via VSS. After a fixed
//! number (at least `N - 2 * t` if there are `N` nodes and up to `t` faulty ones) of them have
//! successfully been distributed, every node adds up the resulting secrets. Since the sum of
//! polynomials of degree `t` is itself a polynomial of degree `t`, these sums are still valid
//! secret keys, but now nobody knows the master key (number `0`).
// TODO: Expand this explanation and add examples, once the API is complete and stable.

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};
use std::{cmp, iter, ops};

use pairing::{CurveAffine, CurveProjective, Engine, Field, PrimeField};
use rand::Rng;

/// A univariate polynomial in the prime field.
#[derive(Clone, Debug)]
pub struct Poly<E: Engine> {
    /// The coefficients of a polynomial.
    coeff: Vec<E::Fr>,
}

impl<E: Engine> PartialEq for Poly<E> {
    fn eq(&self, other: &Self) -> bool {
        self.coeff == other.coeff
    }
}

impl<B: Borrow<Poly<E>>, E: Engine> ops::AddAssign<B> for Poly<E> {
    fn add_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, E::Fr::zero());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.add_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly<E>>, E: Engine> ops::Add<B> for &'a Poly<E> {
    type Output = Poly<E>;

    fn add(self, rhs: B) -> Poly<E> {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Poly<E>>, E: Engine> ops::Add<B> for Poly<E> {
    type Output = Poly<E>;

    fn add(mut self, rhs: B) -> Poly<E> {
        self += rhs;
        self
    }
}

impl<B: Borrow<Poly<E>>, E: Engine> ops::SubAssign<B> for Poly<E> {
    fn sub_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, E::Fr::zero());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.sub_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly<E>>, E: Engine> ops::Sub<B> for &'a Poly<E> {
    type Output = Poly<E>;

    fn sub(self, rhs: B) -> Poly<E> {
        (*self).clone() - rhs
    }
}

impl<B: Borrow<Poly<E>>, E: Engine> ops::Sub<B> for Poly<E> {
    type Output = Poly<E>;

    fn sub(mut self, rhs: B) -> Poly<E> {
        self -= rhs;
        self
    }
}

// Clippy thinks using any `+` and `-` in a `Mul` implementation is suspicious.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl<'a, B: Borrow<Poly<E>>, E: Engine> ops::Mul<B> for &'a Poly<E> {
    type Output = Poly<E>;

    fn mul(self, rhs: B) -> Self::Output {
        let coeff = (0..(self.coeff.len() + rhs.borrow().coeff.len() - 1))
            .map(|i| {
                let mut c = E::Fr::zero();
                for j in i.saturating_sub(rhs.borrow().degree())..(1 + cmp::min(i, self.degree())) {
                    let mut s = self.coeff[j];
                    s.mul_assign(&rhs.borrow().coeff[i - j]);
                    c.add_assign(&s);
                }
                c
            })
            .collect();
        Poly { coeff }
    }
}

impl<B: Borrow<Poly<E>>, E: Engine> ops::Mul<B> for Poly<E> {
    type Output = Poly<E>;

    fn mul(self, rhs: B) -> Self::Output {
        &self * rhs
    }
}

impl<B: Borrow<Self>, E: Engine> ops::MulAssign<B> for Poly<E> {
    fn mul_assign(&mut self, rhs: B) {
        *self = &*self * rhs;
    }
}

impl<E: Engine> Poly<E> {
    /// Creates a random polynomial.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Self {
        Poly {
            coeff: (0..(degree + 1)).map(|_| rng.gen()).collect(),
        }
    }

    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Poly { coeff: Vec::new() }
    }

    /// Returns the polynomial with constant value `1`.
    pub fn one() -> Self {
        Self::monomial(0)
    }

    /// Returns the polynomial with constant value `c`.
    pub fn constant(c: E::Fr) -> Self {
        Poly { coeff: vec![c] }
    }

    /// Returns the identity function, i.e. the polynomial "`x`".
    pub fn identity() -> Self {
        Self::monomial(1)
    }

    /// Returns the (monic) monomial "`x.pow(degree)`".
    pub fn monomial(degree: usize) -> Self {
        Poly {
            coeff: iter::repeat(E::Fr::zero())
                .take(degree)
                .chain(iter::once(E::Fr::one()))
                .collect(),
        }
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    pub fn interpolate<'a, T, I>(samples_repr: I) -> Self
    where
        I: IntoIterator<Item = (&'a T, &'a E::Fr)>,
        T: Into<<E::Fr as PrimeField>::Repr> + Clone + 'a,
    {
        let convert = |(x_repr, y): (&T, &E::Fr)| {
            let x = E::Fr::from_repr(x_repr.clone().into()).expect("invalid index");
            (x, *y)
        };
        let samples: Vec<(E::Fr, E::Fr)> = samples_repr.into_iter().map(convert).collect();
        Self::compute_interpolation(&samples)
    }

    /// Returns the degree.
    pub fn degree(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the value at the point `i`.
    pub fn evaluate<T: Into<<E::Fr as PrimeField>::Repr>>(&self, i: T) -> E::Fr {
        let mut result = match self.coeff.last() {
            None => return E::Fr::zero(),
            Some(c) => *c,
        };
        let x = E::Fr::from_repr(i.into()).expect("invalid index");
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(&x);
            result.add_assign(c);
        }
        result
    }

    /// Returns the corresponding commitment.
    pub fn commitment(&self) -> Commitment<E> {
        let to_g1 = |c: &E::Fr| E::G1Affine::one().mul(*c);
        Commitment {
            coeff: self.coeff.iter().map(to_g1).collect(),
        }
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_zero()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len)
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    fn compute_interpolation(samples: &[(E::Fr, E::Fr)]) -> Self {
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
    fn lagrange(p: E::Fr, samples: &[(E::Fr, E::Fr)]) -> Self {
        let mut result = Self::one();
        for &(sx, _) in samples {
            let mut denom = p;
            denom.sub_assign(&sx);
            denom = denom.inverse().expect("sample points must be distinct");
            result *= (Self::identity() - Self::constant(sx)) * Self::constant(denom);
        }
        result
    }
}

/// A commitment to a univariate polynomial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment<E: Engine> {
    /// The coefficients of the polynomial.
    #[serde(with = "super::serde_impl::projective_vec")]
    coeff: Vec<E::G1>,
}

impl<E: Engine> PartialEq for Commitment<E> {
    fn eq(&self, other: &Self) -> bool {
        self.coeff == other.coeff
    }
}

impl<E: Engine> Hash for Commitment<E> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.coeff.len().hash(state);
        for c in &self.coeff {
            c.into_affine().into_compressed().as_ref().hash(state);
        }
    }
}

impl<B: Borrow<Commitment<E>>, E: Engine> ops::AddAssign<B> for Commitment<E> {
    fn add_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, E::G1::zero());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.add_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Commitment<E>>, E: Engine> ops::Add<B> for &'a Commitment<E> {
    type Output = Commitment<E>;

    fn add(self, rhs: B) -> Commitment<E> {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Commitment<E>>, E: Engine> ops::Add<B> for Commitment<E> {
    type Output = Commitment<E>;

    fn add(mut self, rhs: B) -> Commitment<E> {
        self += rhs;
        self
    }
}

impl<E: Engine> Commitment<E> {
    /// Returns the polynomial's degree.
    pub fn degree(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the `i`-th public key share.
    pub fn evaluate<T: Into<<E::Fr as PrimeField>::Repr>>(&self, i: T) -> E::G1 {
        let mut result = match self.coeff.last() {
            None => return E::G1::zero(),
            Some(c) => *c,
        };
        let x = E::Fr::from_repr(i.into()).expect("invalid index");
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
#[derive(Debug, Clone)]
pub struct BivarPoly<E: Engine> {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The coefficients of the polynomial. Coefficient `(i, j)` for `i <= j` is in position
    /// `j * (j + 1) / 2 + i`.
    coeff: Vec<E::Fr>,
}

impl<E: Engine> BivarPoly<E> {
    /// Creates a random polynomial.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Self {
        BivarPoly {
            degree,
            coeff: (0..coeff_pos(degree + 1, 0)).map(|_| rng.gen()).collect(),
        }
    }

    /// Returns the polynomial's degree: It is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the polynomial's value at the point `(x, y)`.
    pub fn evaluate<T: Into<<E::Fr as PrimeField>::Repr>>(&self, x: T, y: T) -> E::Fr {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = E::Fr::zero();
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
    pub fn row<T: Into<<E::Fr as PrimeField>::Repr>>(&self, x: T) -> Poly<E> {
        let x_pow = self.powers(x);
        let coeff: Vec<E::Fr> = (0..=self.degree)
            .map(|i| {
                let mut result = E::Fr::zero();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let mut summand = self.coeff[coeff_pos(i, j)];
                    summand.mul_assign(x_pow_j);
                    result.add_assign(&summand);
                }
                result
            })
            .collect();
        Poly { coeff }
    }

    /// Returns the corresponding commitment. That information can be shared publicly.
    pub fn commitment(&self) -> BivarCommitment<E> {
        let to_pub = |c: &E::Fr| E::G1Affine::one().mul(*c);
        BivarCommitment {
            degree: self.degree,
            coeff: self.coeff.iter().map(to_pub).collect(),
        }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: Into<<E::Fr as PrimeField>::Repr>>(&self, x_repr: T) -> Vec<E::Fr> {
        powers(x_repr, self.degree)
    }
}

/// A commitment to a bivariate polynomial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BivarCommitment<E: Engine> {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The commitments to the coefficients.
    #[serde(with = "super::serde_impl::projective_vec")]
    coeff: Vec<E::G1>,
}

impl<E: Engine> Hash for BivarCommitment<E> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.degree.hash(state);
        for c in &self.coeff {
            c.into_affine().into_compressed().as_ref().hash(state);
        }
    }
}

impl<E: Engine> BivarCommitment<E> {
    /// Returns the polynomial's degree: It is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the commitment's value at the point `(x, y)`.
    pub fn evaluate<T: Into<<E::Fr as PrimeField>::Repr>>(&self, x: T, y: T) -> E::G1 {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = E::G1::zero();
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
    pub fn row<T: Into<<E::Fr as PrimeField>::Repr>>(&self, x: T) -> Commitment<E> {
        let x_pow = self.powers(x);
        let coeff: Vec<E::G1> = (0..=self.degree)
            .map(|i| {
                let mut result = E::G1::zero();
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
    fn powers<T: Into<<E::Fr as PrimeField>::Repr>>(&self, x_repr: T) -> Vec<E::Fr> {
        powers(x_repr, self.degree)
    }
}

/// Returns the `0`-th to `degree`-th power of `x`.
fn powers<P: PrimeField, T: Into<P::Repr>>(x_repr: T, degree: usize) -> Vec<P> {
    let x = &P::from_repr(x_repr.into()).expect("invalid index");
    let mut x_pow_i = P::one();
    iter::once(x_pow_i)
        .chain((0..degree).map(|_| {
            x_pow_i.mul_assign(x);
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

    use super::{coeff_pos, BivarPoly, Poly};

    use pairing::bls12_381::Bls12;
    use pairing::{CurveAffine, Engine, Field, PrimeField};
    use rand;

    type Fr = <Bls12 as Engine>::Fr;

    fn fr(x: i64) -> Fr {
        let mut result = Fr::from_repr((x.abs() as u64).into()).unwrap();
        if x < 0 {
            result.negate();
        }
        result
    }

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
        // The polynomial "`5 * x.pow(3) + x.pow(1) - 2`".
        let poly: Poly<Bls12> =
            Poly::monomial(3) * Poly::constant(fr(5)) + Poly::monomial(1) - Poly::constant(fr(2));
        let coeff = vec![fr(-2), fr(1), fr(0), fr(5)];
        assert_eq!(Poly { coeff }, poly);
        let samples = vec![
            (fr(-1), fr(-8)),
            (fr(2), fr(40)),
            (fr(3), fr(136)),
            (fr(5), fr(628)),
        ];
        for &(x, y) in &samples {
            assert_eq!(y, poly.evaluate(x));
        }
        let sample_iter = samples.iter().map(|&(ref x, ref y)| (x, y));
        assert_eq!(Poly::interpolate(sample_iter), poly);
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
        let bi_polys: Vec<BivarPoly<Bls12>> = (0..dealer_num)
            .map(|_| BivarPoly::random(faulty_num, &mut rng))
            .collect();
        let pub_bi_commits: Vec<_> = bi_polys.iter().map(BivarPoly::commitment).collect();

        let mut sec_keys = vec![fr(0); node_num];

        // Each dealer sends row `m` to node `m`, where the index starts at `1`. Don't send row `0`
        // to anyone! The nodes verify their rows, and send _value_ `s` on to node `s`. They again
        // verify the values they received, and collect them.
        for (bi_poly, bi_commit) in bi_polys.iter().zip(&pub_bi_commits) {
            for m in 1..=node_num {
                // Node `m` receives its row and verifies it.
                let row_poly = bi_poly.row(m as u64);
                let row_commit = bi_commit.row(m as u64);
                assert_eq!(row_poly.commitment(), row_commit);
                // Node `s` receives the `s`-th value and verifies it.
                for s in 1..=node_num {
                    let val = row_poly.evaluate(s as u64);
                    let val_g1 = <Bls12 as Engine>::G1Affine::one().mul(val);
                    assert_eq!(bi_commit.evaluate(m as u64, s as u64), val_g1);
                    // The node can't verify this directly, but it should have the correct value:
                    assert_eq!(bi_poly.evaluate(m as u64, s as u64), val);
                }

                // A cheating dealer who modified the polynomial would be detected.
                let wrong_poly = row_poly.clone() + Poly::monomial(2) * Poly::constant(fr(5));
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
                    .map(|&i| (i, bi_poly.evaluate(m as u64, i as u64)))
                    .collect();
                let my_row = Poly::interpolate(&received);
                assert_eq!(bi_poly.evaluate(m as u64, 0), my_row.evaluate(0));
                assert_eq!(row_poly, my_row);

                // The node sums up all values number `0` it received from the different dealer. No
                // dealer and no other node knows the sum in the end.
                sec_keys[m - 1].add_assign(&my_row.evaluate(0));
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
            assert_eq!(sec_key_set.evaluate(m as u64), sec_keys[m - 1]);
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
