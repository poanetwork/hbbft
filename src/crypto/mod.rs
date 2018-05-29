mod error;

use byteorder::{BigEndian, ByteOrder};
use init_with::InitWith;

use pairing::{CurveAffine, CurveProjective, Engine, Field, PrimeField};
use rand::{ChaChaRng, Rand, Rng, SeedableRng};
use ring::digest;

use self::error::{ErrorKind, Result};

/// The number of words (`u32`) in a ChaCha RNG seed.
const CHACHA_RNG_SEED_SIZE: usize = 8;

/// Returns a hash of the given message in `G2`.
pub fn hash_g2<E, M>(msg: M) -> E::G2
where
    E: Engine,
    <E as Engine>::G2: Rand,
    M: AsRef<[u8]>,
{
    let digest = digest::digest(&digest::SHA256, msg.as_ref());
    let seed = <[u32; CHACHA_RNG_SEED_SIZE]>::init_with_indices(|i| {
        BigEndian::read_u32(&digest.as_ref()[(4 * i)..(4 * i + 4)])
    });
    let mut rng = ChaChaRng::from_seed(&seed);
    rng.gen()
}

/// A public key, or a public key share.
#[derive(Debug)]
pub struct PublicKey<E: Engine>(E::G1);

impl<E: Engine> PartialEq for PublicKey<E>
where
    E::G2: PartialEq,
{
    fn eq(&self, other: &PublicKey<E>) -> bool {
        self.0 == other.0
    }
}

impl<E: Engine> PublicKey<E> {
    /// Returns `true` if the signature matches the element of `E::G2`.
    pub fn verify_g2<H: Into<E::G2Affine>>(&self, sig: &Signature<E>, hash: H) -> bool {
        E::pairing(self.0, hash) == E::pairing(E::G1::one(), sig.0)
    }

    /// Returns `true` if the signature matches the message.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature<E>, msg: M) -> bool {
        self.verify_g2(sig, hash_g2::<E, M>(msg))
    }
}

/// A signature, or a signature share.
#[derive(Debug)]
pub struct Signature<E: Engine>(E::G2);

impl<E: Engine> PartialEq for Signature<E>
where
    E::G2: PartialEq,
{
    fn eq(&self, other: &Signature<E>) -> bool {
        self.0 == other.0
    }
}

/// A secret key, or a secret key share.
#[derive(Debug)]
pub struct SecretKey<E: Engine>(E::Fr);

impl<E: Engine> PartialEq for SecretKey<E>
where
    E::G2: PartialEq,
{
    fn eq(&self, other: &SecretKey<E>) -> bool {
        self.0 == other.0
    }
}

impl<E: Engine> SecretKey<E> {
    /// Creates a new secret key.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        SecretKey(rng.gen())
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey<E> {
        PublicKey(E::G1Affine::one().mul(self.0))
    }

    /// Signs the given element of `E::G2`.
    pub fn sign_g2<H: Into<E::G2Affine>>(&self, hash: H) -> Signature<E> {
        Signature(hash.into().mul(self.0))
    }

    /// Signs the given message.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> Signature<E> {
        self.sign_g2(hash_g2::<E, M>(msg))
    }
}

/// A public key and an associated set of public key shares.
pub struct PublicKeySet<E: Engine> {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    coeff: Vec<E::G1>,
}

impl<E: Engine> PublicKeySet<E> {
    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PublicKey<E> {
        PublicKey(self.coeff[0])
    }

    /// Returns the `i`-th public key share.
    pub fn public_key_share<T>(&self, i: T) -> PublicKey<E>
    where
        T: Into<<E::Fr as PrimeField>::Repr>,
    {
        let mut x = E::Fr::one();
        x.add_assign(&E::Fr::from_repr(i.into()).expect("invalid index"));
        let mut pk = *self.coeff.last().expect("at least one coefficient");
        for c in self.coeff.iter().rev().skip(1) {
            pk.mul_assign(x);
            pk.add_assign(c);
        }
        PublicKey(pk)
    }

    /// Verifies that the given signatures are correct and combines them into a signature that can
    /// be verified with the main public key.
    pub fn combine_signatures<'a, ITR, IND>(&self, items: ITR) -> Result<Signature<E>>
    where
        ITR: IntoIterator<Item = (&'a IND, &'a Signature<E>)>,
        IND: Into<<E::Fr as PrimeField>::Repr> + Clone + 'a,
    {
        let sigs: Vec<_> = items
            .into_iter()
            .map(|(i, sig)| {
                let mut x = E::Fr::one();
                x.add_assign(&E::Fr::from_repr(i.clone().into()).expect("invalid index"));
                (x, sig)
            })
            .collect();
        if sigs.len() < self.coeff.len() {
            return Err(ErrorKind::NotEnoughShares.into());
        }
        let mut result = E::G2::zero();
        let mut indexes = Vec::new();
        for (x, sig) in sigs.iter().take(self.coeff.len()) {
            if indexes.contains(x) {
                return Err(ErrorKind::DuplicateEntry.into());
            }
            indexes.push(x.clone());
            // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
            // points but `1` at `x`.
            let mut l0 = E::Fr::one();
            for (x0, _) in sigs.iter().take(self.coeff.len()).filter(|(x0, _)| x0 != x) {
                let mut denom = *x0;
                denom.sub_assign(x);
                l0.mul_assign(x0);
                l0.mul_assign(&denom.inverse().expect("indices are different"));
            }
            let mut summand = sig.0;
            summand.mul_assign(l0);
            result.add_assign(&summand);
        }
        Ok(Signature(result))
    }
}

/// A secret key and an associated set of secret key shares.
pub struct SecretKeySet<E: Engine> {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    coeff: Vec<E::Fr>,
}

impl<E: Engine> SecretKeySet<E> {
    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt.
    pub fn new<R: Rng>(threshold: usize, rng: &mut R) -> Self {
        SecretKeySet {
            coeff: (0..(threshold + 1)).map(|_| rng.gen()).collect(),
        }
    }

    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the `i`-th secret key share.
    pub fn secret_key_share<T>(&self, i: T) -> SecretKey<E>
    where
        T: Into<<E::Fr as PrimeField>::Repr>,
    {
        let mut x = E::Fr::one();
        x.add_assign(&E::Fr::from_repr(i.into()).expect("invalid index"));
        let mut pk = *self.coeff.last().expect("at least one coefficient");
        for c in self.coeff.iter().rev().skip(1) {
            pk.mul_assign(&x);
            pk.add_assign(c);
        }
        SecretKey(pk)
    }

    /// Returns the corresponding public key set. That information can be shared publicly.
    pub fn public_keys(&self) -> PublicKeySet<E> {
        let to_pub = |c: &E::Fr| E::G1Affine::one().mul(*c);
        PublicKeySet {
            coeff: self.coeff.iter().map(to_pub).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use pairing::bls12_381::Bls12;
    use rand;

    #[test]
    fn test_simple_sig() {
        let mut rng = rand::thread_rng();
        let sk0 = SecretKey::<Bls12>::new(&mut rng);
        let sk1 = SecretKey::<Bls12>::new(&mut rng);
        let pk0 = sk0.public_key();
        let msg0 = b"Real news";
        let msg1 = b"Fake news";
        assert!(pk0.verify(&sk0.sign(msg0), msg0));
        assert!(!pk0.verify(&sk1.sign(msg0), msg0)); // Wrong key.
        assert!(!pk0.verify(&sk0.sign(msg1), msg0)); // Wrong message.
    }

    #[test]
    fn test_threshold_sig() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::<Bls12>::new(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let msg = "Totally real news";

        // The threshold is 3, so 4 signature shares will suffice to recreate the share.
        let sigs: BTreeMap<_, _> = [5, 8, 7, 10]
            .into_iter()
            .map(|i| (*i, sk_set.secret_key_share(*i).sign(msg)))
            .collect();

        // Each of the shares is a valid signature matching its public key share.
        for (i, sig) in &sigs {
            pk_set.public_key_share(*i).verify(sig, msg);
        }

        // Combined, they produce a signature matching the main public key.
        let sig = pk_set.combine_signatures(&sigs).expect("signatures match");
        assert!(pk_set.public_key().verify(&sig, msg));

        // A different set of signatories produces the same signature.
        let sigs2: BTreeMap<_, _> = [42, 43, 44, 45]
            .into_iter()
            .map(|i| (*i, sk_set.secret_key_share(*i).sign(msg)))
            .collect();
        let sig2 = pk_set.combine_signatures(&sigs2).expect("signatures match");
        assert_eq!(sig, sig2);
    }

    /// Some basic sanity checks for the hash function.
    #[test]
    fn test_hash_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..1000).map(|_| rng.gen()).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();

        let hash = hash_g2::<Bls12, _>;
        assert_eq!(hash(&msg), hash(&msg));
        assert_ne!(hash(&msg), hash(&msg_end0));
        assert_ne!(hash(&msg_end0), hash(&msg_end1));
    }
}
