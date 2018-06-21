use super::Signature;
use pairing::bls12_381::G2Compressed;
use pairing::{CurveAffine, CurveProjective, EncodedPoint};

impl Signature {
    pub fn to_vec(&self) -> Vec<u8> {
        let comp = self.0.into_affine().into_compressed();
        comp.as_ref().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut comp = G2Compressed::empty();
        comp.as_mut().copy_from_slice(bytes);
        if let Ok(affine) = comp.into_affine() {
            Some(Signature(affine.into_projective()))
        } else {
            None
        }
    }
}
