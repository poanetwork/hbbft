//! Utility functions
//!
//! Functions not large enough to warrant their own crate or module, but flexible enough to be used
//! in multiple disjunct places in the library. May also contain backports, workarounds.

use rand;

/// Workaround trait for creating new random number generators
pub trait SubRng {
    fn sub_rng(&mut self) -> Box<dyn rand::Rng + Send>;
}

impl<R> SubRng for R
where
    R: rand::Rng,
{
    fn sub_rng(&mut self) -> Box<dyn rand::Rng + Send> {
        // Currently hard-coded to be an `Isaac64Rng`, until better options emerge. This is either
        // dependant on `rand` 0.5 support or an API re-design of parts of `threshold_crypto` and
        // `hbbft`.
        let rng = self.gen::<rand::isaac::Isaac64Rng>();
        Box::new(rng)
    }
}
