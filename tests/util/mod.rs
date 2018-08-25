use std::ops;

use rand;

pub trait SubSlice
where
    Self: ops::Index<ops::Range<usize>>,
{
    #[inline]
    fn subslice(
        &self,
        range: ops::Range<usize>,
    ) -> &<Self as ops::Index<ops::Range<usize>>>::Output;
}

impl<T> SubSlice for [T] {
    #[inline]
    fn subslice(
        &self,
        mut range: ops::Range<usize>,
    ) -> &<Self as ops::Index<ops::Range<usize>>>::Output {
        if range.end > self.len() {
            range.end = self.len();
        }

        &self[range]
    }
}

fn choose_approx<R: ?Sized + rand::Rng, T: Clone>(
    rng: &mut R,
    mut slice: &[T],
    mut n: usize,
    out_of_first: usize,
) {
    slice = &slice[..(out_of_first.min(slice.len()))];
}
