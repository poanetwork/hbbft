use super::Signature;
use pairing::{CurveAffine, CurveProjective, EncodedPoint, Engine};

impl<E: Engine> Signature<E> {
    pub fn to_vec(&self) -> Vec<u8> {
        let comp = self.0.into_affine().into_compressed();
        comp.as_ref().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut comp = <E::G2Affine as CurveAffine>::Compressed::empty();
        comp.as_mut().copy_from_slice(bytes);
        if let Ok(affine) = comp.into_affine() {
            Some(Signature(affine.into_projective()))
        } else {
            None
        }
    }
}
