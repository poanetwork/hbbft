// Clippy warns that it's dangerous to derive `PartialEq` and explicitly implement `Hash`, but the
// `pairing::bls12_381` types don't implement `Hash`, so we can't derive it.
#![cfg_attr(feature = "cargo-clippy", allow(derive_hash_xor_eq))]

pub mod error;
pub mod poly;
#[cfg(feature = "serialization-protobuf")]
pub mod protobuf_impl;
pub mod serde_impl;

use std::fmt;
use std::hash::{Hash, Hasher};

use byteorder::{BigEndian, ByteOrder};
use clear_on_drop::ClearOnDrop;
use init_with::InitWith;
use pairing::bls12_381::{Bls12, Fr, FrRepr, G1, G1Affine, G2, G2Affine};
use pairing::{CurveAffine, CurveProjective, Engine, Field, PrimeField};
use rand::{ChaChaRng, OsRng, Rng, SeedableRng};
use ring::digest;

use self::error::{ErrorKind, Result};
use self::poly::{Commitment, Poly};
use fmt::HexBytes;

/// The number of words (`u32`) in a ChaCha RNG seed.
const CHACHA_RNG_SEED_SIZE: usize = 8;

const ERR_OS_RNG: &str = "could not initialize the OS random number generator";

/// A public key, or a public key share.
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct PublicKey(#[serde(with = "serde_impl::projective")] G1);

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let uncomp = self.0.into_affine().into_uncompressed();
        let bytes = uncomp.as_ref();
        write!(f, "PublicKey({:?})", HexBytes(bytes))
    }
}

impl PublicKey {
    /// Returns `true` if the signature matches the element of `G2`.
    pub fn verify_g2<H: Into<G2Affine>>(&self, sig: &Signature, hash: H) -> bool {
        Bls12::pairing(self.0, hash) == Bls12::pairing(G1Affine::one(), sig.0)
    }

    /// Returns `true` if the signature matches the message.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature, msg: M) -> bool {
        self.verify_g2(sig, hash_g2(msg))
    }

    /// Returns `true` if the decryption share matches the ciphertext.
    pub fn verify_decryption_share(&self, share: &DecryptionShare, ct: &Ciphertext) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *ct;
        let hash = hash_g1_g2(*u, v);
        Bls12::pairing(share.0, hash) == Bls12::pairing(self.0, *w)
    }

    /// Encrypts the message.
    pub fn encrypt<M: AsRef<[u8]>>(&self, msg: M) -> Ciphertext {
        let r: Fr = OsRng::new().expect(ERR_OS_RNG).gen();
        let u = G1Affine::one().mul(r);
        let v: Vec<u8> = {
            let g = self.0.into_affine().mul(r);
            xor_vec(&hash_bytes(g, msg.as_ref().len()), msg.as_ref())
        };
        let w = hash_g1_g2(u, &v).into_affine().mul(r);
        Ciphertext(u, v, w)
    }

    /// Returns a byte string representation of the public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.into_affine().into_compressed().as_ref().to_vec()
    }
}

/// A signature, or a signature share.
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Signature(#[serde(with = "serde_impl::projective")] G2);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let uncomp = self.0.into_affine().into_uncompressed();
        let bytes = uncomp.as_ref();
        write!(f, "Signature({:?})", HexBytes(bytes))
    }
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl Signature {
    pub fn parity(&self) -> bool {
        let uncomp = self.0.into_affine().into_uncompressed();
        let bytes = uncomp.as_ref();
        let xor_bytes: u8 = bytes.iter().fold(0, |result, byte| result ^ byte);
        let parity = 0 != xor_bytes % 2;
        debug!("Signature: {:?}, output: {}", HexBytes(bytes), parity);
        parity
    }
}

/// A secret key, or a secret key share.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(Fr);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let uncomp = self.public_key().0.into_affine().into_uncompressed();
        let bytes = uncomp.as_ref();
        write!(f, "SecretKey({:?})", HexBytes(bytes))
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        SecretKey(Fr::zero())
    }
}

impl SecretKey {
    /// Creates a new secret key.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        SecretKey(rng.gen())
    }

    pub fn from_value(f: Fr) -> Self {
        SecretKey(f)
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(G1Affine::one().mul(self.0))
    }

    /// Signs the given element of `G2`.
    pub fn sign_g2<H: Into<G2Affine>>(&self, hash: H) -> Signature {
        Signature(hash.into().mul(self.0))
    }

    /// Signs the given message.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> Signature {
        self.sign_g2(hash_g2(msg))
    }

    /// Returns the decrypted text, or `None`, if the ciphertext isn't valid.
    pub fn decrypt(&self, ct: &Ciphertext) -> Option<Vec<u8>> {
        if !ct.verify() {
            return None;
        }
        let Ciphertext(ref u, ref v, _) = *ct;
        let g = u.into_affine().mul(self.0);
        Some(xor_vec(&hash_bytes(g, v.len()), v))
    }

    /// Returns a decryption share, or `None`, if the ciphertext isn't valid.
    pub fn decrypt_share(&self, ct: &Ciphertext) -> Option<DecryptionShare> {
        if !ct.verify() {
            return None;
        }
        Some(DecryptionShare(ct.0.into_affine().mul(self.0)))
    }
}

/// An encrypted message.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(
    #[serde(with = "serde_impl::projective")] G1,
    Vec<u8>,
    #[serde(with = "serde_impl::projective")] G2,
);

impl Hash for Ciphertext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let Ciphertext(ref u, ref v, ref w) = *self;
        u.into_affine().into_compressed().as_ref().hash(state);
        v.hash(state);
        w.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl Ciphertext {
    /// Returns `true` if this is a valid ciphertext. This check is necessary to prevent
    /// chosen-ciphertext attacks.
    pub fn verify(&self) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *self;
        let hash = hash_g1_g2(*u, v);
        Bls12::pairing(G1Affine::one(), *w) == Bls12::pairing(*u, hash)
    }
}

/// A decryption share. A threshold of decryption shares can be used to decrypt a message.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct DecryptionShare(#[serde(with = "serde_impl::projective")] G1);

impl Hash for DecryptionShare {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

/// A public key and an associated set of public key shares.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    commit: Commitment,
}

impl Hash for PublicKeySet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.commit.hash(state);
    }
}

impl From<Commitment> for PublicKeySet {
    fn from(commit: Commitment) -> PublicKeySet {
        PublicKeySet { commit }
    }
}

impl PublicKeySet {
    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.commit.degree()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.commit.coeff[0])
    }

    /// Returns the `i`-th public key share.
    pub fn public_key_share<T: Into<FrRepr>>(&self, i: T) -> PublicKey {
        PublicKey(self.commit.evaluate(from_repr_plus_1::<Fr>(i.into())))
    }

    /// Combines the shares into a signature that can be verified with the main public key.
    pub fn combine_signatures<'a, ITR, IND>(&self, shares: ITR) -> Result<Signature>
    where
        ITR: IntoIterator<Item = (&'a IND, &'a Signature)>,
        IND: Into<FrRepr> + Clone + 'a,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
        Ok(Signature(interpolate(self.commit.degree() + 1, samples)?))
    }

    /// Combines the shares to decrypt the ciphertext.
    pub fn decrypt<'a, ITR, IND>(&self, shares: ITR, ct: &Ciphertext) -> Result<Vec<u8>>
    where
        ITR: IntoIterator<Item = (&'a IND, &'a DecryptionShare)>,
        IND: Into<FrRepr> + Clone + 'a,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
        let g = interpolate(self.commit.degree() + 1, samples)?;
        Ok(xor_vec(&hash_bytes(g, ct.1.len()), &ct.1))
    }
}

/// A secret key and an associated set of secret key shares.
pub struct SecretKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    poly: Poly,
}

impl From<Poly> for SecretKeySet {
    fn from(poly: Poly) -> SecretKeySet {
        SecretKeySet { poly }
    }
}

impl SecretKeySet {
    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt.
    pub fn random<R: Rng>(threshold: usize, rng: &mut R) -> Self {
        SecretKeySet {
            poly: Poly::random(threshold, rng),
        }
    }

    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.poly.degree()
    }

    /// Returns the `i`-th secret key share.
    pub fn secret_key_share<T: Into<FrRepr>>(&self, i: T) -> ClearOnDrop<Box<SecretKey>> {
        ClearOnDrop::new(Box::new(SecretKey(
            self.poly.evaluate(from_repr_plus_1::<Fr>(i.into())),
        )))
    }

    /// Returns the corresponding public key set. That information can be shared publicly.
    pub fn public_keys(&self) -> PublicKeySet {
        PublicKeySet {
            commit: self.poly.commitment(),
        }
    }

    /// Returns the secret master key.
    #[cfg(test)]
    fn secret_key(&self) -> SecretKey {
        SecretKey(self.poly.evaluate(0))
    }
}

/// Returns a hash of the given message in `G2`.
fn hash_g2<M: AsRef<[u8]>>(msg: M) -> G2 {
    let digest = digest::digest(&digest::SHA256, msg.as_ref());
    let seed = <[u32; CHACHA_RNG_SEED_SIZE]>::init_with_indices(|i| {
        BigEndian::read_u32(&digest.as_ref()[(4 * i)..(4 * i + 4)])
    });
    let mut rng = ChaChaRng::from_seed(&seed);
    rng.gen()
}

/// Returns a hash of the group element and message, in the second group.
fn hash_g1_g2<M: AsRef<[u8]>>(g1: G1, msg: M) -> G2 {
    // If the message is large, hash it, otherwise copy it.
    // TODO: Benchmark and optimize the threshold.
    let mut msg = if msg.as_ref().len() > 64 {
        let digest = digest::digest(&digest::SHA256, msg.as_ref());
        digest.as_ref().to_vec()
    } else {
        msg.as_ref().to_vec()
    };
    msg.extend(g1.into_affine().into_compressed().as_ref());
    hash_g2(&msg)
}

/// Returns a hash of the group element with the specified length in bytes.
fn hash_bytes(g1: G1, len: usize) -> Vec<u8> {
    let digest = digest::digest(&digest::SHA256, g1.into_affine().into_compressed().as_ref());
    let seed = <[u32; CHACHA_RNG_SEED_SIZE]>::init_with_indices(|i| {
        BigEndian::read_u32(&digest.as_ref()[(4 * i)..(4 * i + 4)])
    });
    let mut rng = ChaChaRng::from_seed(&seed);
    rng.gen_iter().take(len).collect()
}

/// Returns the bitwise xor.
fn xor_vec(x: &[u8], y: &[u8]) -> Vec<u8> {
    x.iter().zip(y).map(|(a, b)| a ^ b).collect()
}

/// Given a list of `t` samples `(i - 1, f(i) * g)` for a polynomial `f` of degree `t - 1`, and a
/// group generator `g`, returns `f(0) * g`.
fn interpolate<'a, C, ITR, IND>(t: usize, items: ITR) -> Result<C>
where
    C: CurveProjective,
    ITR: IntoIterator<Item = (&'a IND, &'a C)>,
    IND: Into<<C::Scalar as PrimeField>::Repr> + Clone + 'a,
{
    let samples: Vec<_> = items
        .into_iter()
        .map(|(i, sample)| (from_repr_plus_1::<C::Scalar>(i.clone().into()), sample))
        .collect();
    if samples.len() < t {
        return Err(ErrorKind::NotEnoughShares.into());
    }
    let mut result = C::zero();
    let mut indexes = Vec::new();
    for (x, sample) in samples.iter().take(t) {
        if indexes.contains(x) {
            return Err(ErrorKind::DuplicateEntry.into());
        }
        indexes.push(x.clone());
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
        // points but `1` at `x`.
        let mut l0 = C::Scalar::one();
        for (x0, _) in samples.iter().take(t).filter(|(x0, _)| x0 != x) {
            let mut denom = *x0;
            denom.sub_assign(x);
            l0.mul_assign(x0);
            l0.mul_assign(&denom.inverse().expect("indices are different"));
        }
        result.add_assign(&sample.into_affine().mul(l0));
    }
    Ok(result)
}

fn from_repr_plus_1<F: PrimeField>(repr: F::Repr) -> F {
    let mut x = F::one();
    x.add_assign(&F::from_repr(repr).expect("invalid index"));
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use rand;

    #[test]
    fn test_simple_sig() {
        let mut rng = rand::thread_rng();
        let sk0 = SecretKey::new(&mut rng);
        let sk1 = SecretKey::new(&mut rng);
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
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();

        // Make sure the keys are different, and the first coefficient is the main key.
        assert_ne!(pk_set.public_key(), pk_set.public_key_share(0));
        assert_ne!(pk_set.public_key(), pk_set.public_key_share(1));
        assert_ne!(pk_set.public_key(), pk_set.public_key_share(2));

        // Make sure we don't hand out the main secret key to anyone.
        assert_ne!(sk_set.secret_key(), *sk_set.secret_key_share(0));
        assert_ne!(sk_set.secret_key(), *sk_set.secret_key_share(1));
        assert_ne!(sk_set.secret_key(), *sk_set.secret_key_share(2));

        let msg = "Totally real news";

        // The threshold is 3, so 4 signature shares will suffice to recreate the share.
        let sigs: BTreeMap<_, _> = [5, 8, 7, 10]
            .into_iter()
            .map(|i| (*i, sk_set.secret_key_share(*i).sign(msg)))
            .collect();

        // Each of the shares is a valid signature matching its public key share.
        for (i, sig) in &sigs {
            assert!(pk_set.public_key_share(*i).verify(sig, msg));
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

    #[test]
    fn test_simple_enc() {
        let mut rng = rand::thread_rng();
        let sk_bob = SecretKey::new(&mut rng);
        let sk_eve = SecretKey::new(&mut rng);
        let pk_bob = sk_bob.public_key();
        let msg = b"Muffins in the canteen today! Don't tell Eve!";
        let ciphertext = pk_bob.encrypt(&msg[..]);
        assert!(ciphertext.verify());

        // Bob can decrypt the message.
        let decrypted = sk_bob.decrypt(&ciphertext).expect("valid ciphertext");
        assert_eq!(msg[..], decrypted[..]);

        // Eve can't.
        let decrypted_eve = sk_eve.decrypt(&ciphertext).expect("valid ciphertext");
        assert_ne!(msg[..], decrypted_eve[..]);

        // Eve tries to trick Bob into decrypting `msg` xor `v`, but it doesn't validate.
        let Ciphertext(u, v, w) = ciphertext;
        let fake_ciphertext = Ciphertext(u, vec![0; v.len()], w);
        assert!(!fake_ciphertext.verify());
        assert_eq!(None, sk_bob.decrypt(&fake_ciphertext));
    }

    #[test]
    fn test_threshold_enc() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let msg = b"Totally real news";
        let ciphertext = pk_set.public_key().encrypt(&msg[..]);

        // The threshold is 3, so 4 signature shares will suffice to decrypt.
        let shares: BTreeMap<_, _> = [5, 8, 7, 10]
            .into_iter()
            .map(|i| {
                let ski = sk_set.secret_key_share(*i);
                let share = ski.decrypt_share(&ciphertext).expect("ciphertext is valid");
                (*i, share)
            })
            .collect();

        // Each of the shares is valid matching its public key share.
        for (i, share) in &shares {
            pk_set
                .public_key_share(*i)
                .verify_decryption_share(share, &ciphertext);
        }

        // Combined, they can decrypt the message.
        let decrypted = pk_set
            .decrypt(&shares, &ciphertext)
            .expect("decryption shares match");
        assert_eq!(msg[..], decrypted[..]);
    }

    /// Some basic sanity checks for the `hash_g2` function.
    #[test]
    fn test_hash_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..1000).map(|_| rng.gen()).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();

        assert_eq!(hash_g2(&msg), hash_g2(&msg));
        assert_ne!(hash_g2(&msg), hash_g2(&msg_end0));
        assert_ne!(hash_g2(&msg_end0), hash_g2(&msg_end1));
    }

    /// Some basic sanity checks for the `hash_g1_g2` function.
    #[test]
    fn test_hash_g1_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..1000).map(|_| rng.gen()).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();
        let g0 = rng.gen();
        let g1 = rng.gen();

        assert_eq!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg_end0));
        assert_ne!(hash_g1_g2(g0, &msg_end0), hash_g1_g2(g0, &msg_end1));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g1, &msg));
    }

    /// Some basic sanity checks for the `hash_bytes` function.
    #[test]
    fn test_hash_bytes() {
        let mut rng = rand::thread_rng();
        let g0 = rng.gen();
        let g1 = rng.gen();
        let hash = hash_bytes;
        assert_eq!(hash(g0, 5), hash(g0, 5));
        assert_ne!(hash(g0, 5), hash(g1, 5));
        assert_eq!(5, hash(g0, 5).len());
        assert_eq!(6, hash(g0, 6).len());
        assert_eq!(20, hash(g0, 20).len());
    }

    #[test]
    fn test_serde() {
        use bincode;

        let mut rng = rand::thread_rng();
        let sk = SecretKey::new(&mut rng);
        let sig = sk.sign("Please sign here: ______");
        let pk = sk.public_key();
        let ser_pk = bincode::serialize(&pk).expect("serialize public key");
        let deser_pk = bincode::deserialize(&ser_pk).expect("deserialize public key");
        assert_eq!(pk, deser_pk);
        let ser_sig = bincode::serialize(&sig).expect("serialize signature");
        let deser_sig = bincode::deserialize(&ser_sig).expect("deserialize signature");
        assert_eq!(sig, deser_sig);
    }
}
