use std::borrow::Borrow;
use std::marker::PhantomData;

use pairing::{CurveAffine, CurveProjective, EncodedPoint, Engine};

use super::{DecryptionShare, PublicKey, Signature};
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const ERR_LEN: &str = "wrong length of deserialized group element";
const ERR_CODE: &str = "deserialized bytes don't encode a group element";

/// A wrapper type to facilitate serialization and deserialization of group elements.
struct CurveWrap<C, B>(B, PhantomData<C>);

impl<C, B> CurveWrap<C, B> {
    fn new(c: B) -> Self {
        CurveWrap(c, PhantomData)
    }
}

impl<C: CurveProjective, B: Borrow<C>> Serialize for CurveWrap<C, B> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_projective(self.0.borrow(), s)
    }
}

impl<'de, C: CurveProjective> Deserialize<'de> for CurveWrap<C, C> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(CurveWrap::new(deserialize_projective(d)?))
    }
}

impl<E: Engine> Serialize for PublicKey<E> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_projective(&self.0, s)
    }
}

impl<'de, E: Engine> Deserialize<'de> for PublicKey<E> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(PublicKey(deserialize_projective(d)?))
    }
}

impl<E: Engine> Serialize for Signature<E> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_projective(&self.0, s)
    }
}

impl<'de, E: Engine> Deserialize<'de> for Signature<E> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Signature(deserialize_projective(d)?))
    }
}

impl<E: Engine> Serialize for DecryptionShare<E> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_projective(&self.0, s)
    }
}

impl<'de, E: Engine> Deserialize<'de> for DecryptionShare<E> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(DecryptionShare(deserialize_projective(d)?))
    }
}

/// Serializes the compressed representation of a group element.
fn serialize_projective<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    C: CurveProjective,
{
    c.into_affine().into_compressed().as_ref().serialize(s)
}

/// Deserializes the compressed representation of a group element.
fn deserialize_projective<'de, D, C>(d: D) -> Result<C, D::Error>
where
    D: Deserializer<'de>,
    C: CurveProjective,
{
    let bytes = <Vec<u8>>::deserialize(d)?;
    if bytes.len() != <C::Affine as CurveAffine>::Compressed::size() {
        return Err(D::Error::custom(ERR_LEN));
    }
    let mut compressed = <C::Affine as CurveAffine>::Compressed::empty();
    compressed.as_mut().copy_from_slice(&bytes);
    let to_err = |_| D::Error::custom(ERR_CODE);
    Ok(compressed.into_affine().map_err(to_err)?.into_projective())
}

/// Serialization and deserialization of vectors of projective curve elements.
pub mod projective_vec {
    use super::CurveWrap;

    use pairing::CurveProjective;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, C>(vec: &[C], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: CurveProjective,
    {
        let wrap_vec: Vec<CurveWrap<C, &C>> = vec.iter().map(CurveWrap::new).collect();
        wrap_vec.serialize(s)
    }

    pub fn deserialize<'de, D, C>(d: D) -> Result<Vec<C>, D::Error>
    where
        D: Deserializer<'de>,
        C: CurveProjective,
    {
        let wrap_vec = <Vec<CurveWrap<C, C>>>::deserialize(d)?;
        Ok(wrap_vec.into_iter().map(|CurveWrap(c, _)| c).collect())
    }
}
