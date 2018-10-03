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
    pub size: u16,
    /// Number of faulty nodes in a network.
    pub faulty: u16,
}

impl NetworkDimension {
    /// Creates a new `NetworkDimension` with the supplied parameters.
    ///
    /// Dimensions that do not satisfy BFT conditions (see `is_bft`) can be created using this
    /// function.
    #[inline]
    pub fn new(size: u16, faulty: u16) -> Self {
        NetworkDimension { size, faulty }
    }

    /// Checks whether the network dimension satisfies the `3 * faulty + 1 <= size` condition.
    #[inline]
    pub fn is_bft(&self) -> bool {
        self.faulty * 3 < self.size
    }

    /// Creates a new dimension of average complexity.
    ///
    /// The new dimension is approximately half way in the interval of `[self, high]` and will
    /// conform to the constraint checked by `is_bft()`.
    ///
    /// # Panics
    ///
    /// `high` must be have a higher or equal size and faulty node count.
    pub fn average_higher(&self, high: NetworkDimension) -> NetworkDimension {
        assert!(high.size >= self.size);
        assert!(high.faulty >= self.faulty);

        // We try halving both values, rounding down. If `size` is at the minimum, `faulty` will
        // shrink afterwards.
        let mut half = NetworkDimension {
            size: self.size + (high.size - self.size) / 2,
            faulty: self.faulty + (high.faulty - self.faulty) / 2,
        };

        // Reduce the number of faulty nodes, if we are outside our limits.
        if !half.is_bft() {
            half.faulty -= 1;
        }

        // Perform invariant checking.
        assert!(half.is_bft());
        assert!(half.size >= self.size);
        assert!(half.faulty >= self.faulty);
        assert!(half.size <= high.size);
        assert!(half.faulty <= high.faulty);

        half
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
    pub fn succ(&self) -> NetworkDimension {
        let mut n = self.size;
        let mut f = self.faulty + 1;

        if 3 * f >= n {
            f = 0;
            n += 1;
        }

        NetworkDimension { size: n, faulty: f }
    }
}

/// Network dimension tree for proptest generation.
///
/// See `proptest::strategy::ValueTree` for a more thorough description.
#[derive(Copy, Clone, Debug)]
pub struct NetworkDimensionTree {
    /// The upper bound for any generated dimension.
    high: NetworkDimension,
    /// The currently generated network dimension.
    current: NetworkDimension,
    /// The lower bound for any generated dimension value (changes during generation or shrinking).
    low: NetworkDimension,
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

        let high = NetworkDimension {
            size: total,
            faulty,
        };
        assert!(high.is_bft());

        let low = NetworkDimension {
            size: min_size,
            faulty: 0,
        };
        assert!(low.is_bft());

        NetworkDimensionTree {
            high,
            current: high,
            low,
        }
    }
}

impl ValueTree for NetworkDimensionTree {
    type Value = NetworkDimension;

    fn current(&self) -> Self::Value {
        self.current
    }

    fn simplify(&mut self) -> bool {
        // Shrinking is simply done through `average_higher`.
        let prev = *self;

        self.high = prev.current;
        self.current = self.low.average_higher(prev.high);

        (prev.high != self.high || prev.current != self.current)
    }

    fn complicate(&mut self) -> bool {
        let prev = *self;

        // Minimally increase the faulty-node ratio by adjusting the number of faulty nodes and the
        // size slightly less. If we are at the maximum number of faulty nodes, we would end up
        // increasing the network size instead (see branch below though).
        let mut new_low = self.current;
        new_low.faulty += 1;
        new_low.size = (new_low.size + 2).max(new_low.faulty * 3 + 1);
        assert!(new_low.is_bft());

        // Instead of growing the network, return unchanged if the new network would be larger than
        // the current high.
        if new_low.size > self.high.size {
            return false;
        }

        self.current = new_low.average_higher(self.high);
        self.low = new_low;

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

        let b = (dim.size as u32 - 1) / 3;
        let start = 3 * b * (b + 1) / 2;
        let offset = (dim.size as u32 - 3 * b - 1) * (b + 1) + dim.faulty as u32;

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

        NetworkDimension {
            size: size as u16,
            faulty: faulty as u16,
        }
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
