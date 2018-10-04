//! Proptest helpers and strategies.
//!
//! This module houses strategies to generate (and reduce/expand) various `hbbft` and `net` related
//! structures.

use integer_sqrt::IntegerSquareRoot;
use proptest::arbitrary::any;
use proptest::prelude::Rng;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Reason, TestRunner};
use rand::{self, SeedableRng};

/// Random number generator type used in testing.
pub type TestRng = rand::XorShiftRng;

/// Seed type of the random number generator used in testing.
// Note: In `rand` 0.5, this is an associated type of the `SeedableRng` trait, but for 0.4 and below
//       we still need to alias this type.
pub type TestRngSeed = [u32; 4];

/// Generates a random instance of a random number generator.
pub fn gen_rng() -> impl Strategy<Value = TestRng> {
    gen_seed().prop_map(TestRng::from_seed)
}

/// Generates a random seed to instantiate a `TestRng`.
///
/// The random seed is non-shrinkable, to avoid meaningless shrinking in case of failed tests.
pub fn gen_seed() -> impl Strategy<Value = TestRngSeed> {
    any::<TestRngSeed>().no_shrink()
}

/// Node network dimension.
///
/// A `NetworkDimension` describes the number of correct and faulty nodes in a network. It can also
/// be checked, "averaged" (using the `average_higher` function) and generated using
/// `NetworkDimensionTree`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NetworkDimension {
    /// Total number of nodes in network.
    size: u16,
    /// Number of faulty nodes in a network.
    faulty: u16,
}

impl NetworkDimension {
    /// Creates a new `NetworkDimension` with the supplied parameters.
    ///
    /// # Panics
    ///

    #[inline]
    pub fn new(size: u16, faulty: u16) -> Self {
        let dim = NetworkDimension { size, faulty };
        assert!(
            dim.is_bft(),
            "Tried to create network dimension that violates BFT-property."
        );
        dim
    }

    #[inline]
    pub fn faulty(self) -> usize {
        self.faulty.into()
    }

    #[inline]
    pub fn size(self) -> usize {
        self.size.into()
    }

    /// Checks whether the network dimension satisfies the `3 * faulty + 1 <= size` condition.
    #[inline]
    fn is_bft(self) -> bool {
        self.faulty * 3 < self.size
    }

    /// Creates a proptest strategy to create network dimensions within a certain range.
    #[inline]
    pub fn range(min_size: u16, max_size: u16) -> NetworkDimensionStrategy {
        NetworkDimensionStrategy { min_size, max_size }
    }

    /// Returns next-larger network dimension.
    ///
    /// The order on `NetworkDimension` is canonically defined by `(size, faulty)`. The `succ`
    /// function returns the next-higher valid instance by first trying to increase `faulty`, then
    /// `size`.
    #[inline]
    pub fn succ(self) -> NetworkDimension {
        let mut n = self.size;
        let mut f = self.faulty + 1;

        if 3 * f >= n {
            f = 0;
            n += 1;
        }

        NetworkDimension::new(n, f)
    }
}

/// Network dimension tree for proptest generation.
///
/// See `proptest::strategy::ValueTree` for a more thorough description.
#[derive(Copy, Clone, Debug)]
pub struct NetworkDimensionTree {
    /// The upper bound for any generated dimension.
    high: u32,
    /// The currently generated network dimension.
    current: u32,
    /// The lower bound for any generated dimension value (changes during generation or shrinking).
    low: u32,
}

impl NetworkDimensionTree {
    /// Generate a random network dimension tree.
    ///
    /// The resulting initial `NetworkDimension` will have a number of nodes within
    /// [`min_size`, `max_size`] and a valid number of faulty nodes.
    ///
    /// # Panics
    ///
    /// The minimum `min_size` is 1 and `min_size` must be less than or equal `max_size`.
    pub fn gen<R: Rng>(mut rng: R, min_size: u16, max_size: u16) -> Self {
        // A common mistake, add an extra assert for a more helpful error message.
        assert!(min_size > 0, "minimum network size is 1");

        let total = rng.gen_range(min_size, max_size + 1);
        let max_faulty = (total - 1) / 3;
        let faulty = rng.gen_range(0, max_faulty + 1);

        let high = NetworkDimension::new(total, faulty);

        NetworkDimensionTree {
            high: high.into(),
            current: high.into(),
            low: 0,
        }
    }
}

impl ValueTree for NetworkDimensionTree {
    type Value = NetworkDimension;

    fn current(&self) -> Self::Value {
        self.current.into()
    }

    fn simplify(&mut self) -> bool {
        let prev = *self;

        self.high = self.current;
        self.current = self.low + (self.high - self.low) / 2;

        (prev.high != self.high || prev.current != self.current)
    }

    fn complicate(&mut self) -> bool {
        let prev = *self;

        if self.high == self.current {
            return false;
        }

        self.low = self.current + 1;
        self.current = self.low + (self.high - self.low) / 2;

        (prev.current != self.current || prev.low != self.low)
    }
}

impl From<NetworkDimension> for u32 {
    fn from(dim: NetworkDimension) -> u32 {
        // `b` is the "Block index" here. Counting through `NetworkDimensions` a pattern shows:
        //
        //  n   f
        //  1   0  \
        //  2   0   |- Block 0
        //  3   0  /
        //  4   0 \
        //  4   1  \
        //  5   0   >  Block 1
        //  5   1   |
        //  6   0  /
        //  6   1 /
        //  7   0 ...
        //
        // We observe that each block starts at index `3 * (b(b+1)/2)`. Along with the offset,
        // we can calculate a mapping onto the natural numbers using this:

        let b = (u32::from(dim.size) - 1) / 3;
        let start = 3 * b * (b + 1) / 2;
        let offset = (u32::from(dim.size) - 3 * b - 1) * (b + 1) + u32::from(dim.faulty);

        start + offset
    }
}

impl From<u32> for NetworkDimension {
    fn from(n: u32) -> NetworkDimension {
        // Inverse of `u32 as From<NetworkDimension>`:

        // Find the block number first:
        let b = max_sum(n / 3);

        // Calculate the block start and the resulting offset of `n`:
        let start = 3 * b * (b + 1) / 2;
        let offset = n - start;

        let faulty = offset % (b + 1);
        let size = 3 * b + 1 + offset / (b + 1);

        NetworkDimension::new(size as u16, faulty as u16)
    }
}

/// Finds the largest consecutive summand less or equal than `n`.
///
/// The return value `k` will satisfy `SUM 1..k <= n`.
pub fn max_sum(n: u32) -> u32 {
    // Derived by quadratically solving `n(n+1)/2`; we only want the "positive" result.
    // `integer_sqrt` functions as a `floor` function here.
    ((1 + 8 * n).integer_sqrt() - 1) / 2
}

/// Network dimension strategy for proptest.
#[derive(Debug)]
pub struct NetworkDimensionStrategy {
    /// Minimum number of nodes for newly generated networks dimensions.
    pub min_size: u16,
    /// Maximum number of nodes for newly generated networks dimensions.
    pub max_size: u16,
}

impl Strategy for NetworkDimensionStrategy {
    type Value = NetworkDimension;
    type Tree = NetworkDimensionTree;

    fn new_tree(&self, runner: &mut TestRunner) -> Result<Self::Tree, Reason> {
        Ok(NetworkDimensionTree::gen(
            runner.rng(),
            self.min_size,
            self.max_size,
        ))
    }
}
