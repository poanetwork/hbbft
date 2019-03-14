//! Utility functions
//!
//! A collection of miscellaneous functions that are used in the tests, but are generic enough to be
//! factored out.

use rand::Rng;

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

/// Return true with a certain `probability` ([0 .. 1.0]).
pub fn randomly<R: Rng>(probability: f32, rng: &mut R) -> bool {
    assert!(probability <= 1.0);
    assert!(probability >= 0.0);
    rng.gen_range(0.0, 1.0) <= probability
}
