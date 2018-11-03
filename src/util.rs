//! Utility functions
//!
//! Functions not large enough to warrant their own crate or module, but flexible enough to be used
//! in multiple disjunct places in the library. May also contain backports, workarounds.

use std::fmt;

use hex_fmt::HexFmt;
use rand;

/// Workaround trait for creating new random number generators
pub trait SubRng {
    fn sub_rng(&mut self) -> Box<dyn rand::Rng + Send + Sync>;
}

impl<R> SubRng for R
where
    R: rand::Rng,
{
    fn sub_rng(&mut self) -> Box<dyn rand::Rng + Send + Sync> {
        // Currently hard-coded to be an `Isaac64Rng`, until better options emerge. This is either
        // dependant on `rand` 0.5 support or an API re-design of parts of `threshold_crypto` and
        // `hbbft`.
        let rng = self.gen::<rand::isaac::Isaac64Rng>();
        Box::new(rng)
    }
}

/// Prints "`<RNG>`" as a placeholder for a random number generator in debug output.
pub fn fmt_rng<T>(_: T, f: &mut fmt::Formatter) -> fmt::Result {
    f.write_str("<RNG>")
}

/// Prints a byte slice as shortened hexadecimal in debug output.
pub fn fmt_hex<T: AsRef<[u8]>>(bytes: T, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{:10}", HexFmt(bytes))
}
