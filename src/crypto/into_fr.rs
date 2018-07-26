use pairing::bls12_381::Fr;
use pairing::{Field, PrimeField};

/// A conversion into an element of the field `Fr`.
pub trait IntoFr: Copy {
    fn into_fr(self) -> Fr;
}

impl IntoFr for Fr {
    fn into_fr(self) -> Fr {
        self
    }
}

impl IntoFr for u64 {
    fn into_fr(self) -> Fr {
        Fr::from_repr(self.into()).expect("modulus is greater than u64::MAX")
    }
}

impl IntoFr for usize {
    fn into_fr(self) -> Fr {
        (self as u64).into_fr()
    }
}

impl IntoFr for i32 {
    fn into_fr(self) -> Fr {
        if self >= 0 {
            (self as u64).into_fr()
        } else {
            let mut result = ((-self) as u64).into_fr();
            result.negate();
            result
        }
    }
}

impl IntoFr for i64 {
    fn into_fr(self) -> Fr {
        if self >= 0 {
            (self as u64).into_fr()
        } else {
            let mut result = ((-self) as u64).into_fr();
            result.negate();
            result
        }
    }
}

impl<'a, T: IntoFr> IntoFr for &'a T {
    fn into_fr(self) -> Fr {
        (*self).into_fr()
    }
}
