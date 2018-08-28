//! Utility functions
//!
//! A collection miscellaneous functions that are used in the tests, but are generic enough to be
//! factored out.

use std::ops;

/// Subslicing.
pub trait SubSlice
where
    Self: ops::Index<ops::Range<usize>>,
{
    /// Create new subslice of given size or smaller.
    ///
    /// Functions similar to `&sl[a..b]`, but while regular slicing will panic if `b` is out of
    /// range, `subslice` will return the longest possible slice.
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

#[cfg(test)]
mod tests {
    use super::SubSlice;

    #[test]
    fn subslice_regular() {
        let vals = vec![
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
        ];

        assert_eq!(&['a', 'b', 'c'], vals.subslice(0..3));
        assert_eq!(&['d', 'e', 'f', 'g'], vals.subslice(3..7));
    }

    #[test]
    fn subslice_out_of_bounds() {
        let vals = vec![
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
        ];

        assert_eq!(&['m', 'n', 'o'], vals.subslice(12..17));
        assert_eq!(vals.as_slice(), vals.subslice(0..1000));
    }

}

/// Try-return a result, wrapped in `Some`.
///
/// Like `try!`, but wraps into an `Option::Some` as well. Useful for iterators
/// that return `Option<Result<_, _>>`.
#[macro_export]
macro_rules! try_some {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Some(Err(From::from(e))),
        }
    };
}
