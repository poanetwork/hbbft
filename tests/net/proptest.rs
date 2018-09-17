//! Proptest helpers and strategies.
//!
//! This module houses strategies to generate (and reduce/expand) various `hbbft` and `net` related
//! structures.

use proptest::prelude::Rng;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Reason, TestRunner};

/// Node network dimension.
///
/// A `NetworkDimension` describes the number of correct and faulty nodes in a network. It can also
/// be checked, "averaged" (using the `average_higher` function) and generated using
/// `NetworkDimensionTree`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NetworkDimension {
    /// Total number of nodes in network.
    pub size: usize,
    /// Number of faulty nodes in a network.
    pub faulty: usize,
}

impl NetworkDimension {
    /// Creates a new `NetworkDimension` with the supplied parameters.
    ///
    /// Dimensions that do not satisfy BFT conditions (see `is_bft`) can be created using this
    /// function.
    pub fn new(size: usize, faulty: usize) -> Self {
        NetworkDimension { size, faulty }
    }

    /// Checks whether the network dimension satisfies the `3 * faulty + 1 <= size` condition.
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
        if half.faulty * 3 > half.size {
            half.faulty -= 1;
        }

        // This assert just checks for bugs.
        assert!(half.is_bft());

        half
    }

    /// Creates a proptest strategy to create network dimensions within a certain range.
    pub fn range(min_size: usize, max_size: usize) -> NetworkDimensionStrategy {
        NetworkDimensionStrategy { min_size, max_size }
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
    pub fn gen<R: Rng>(mut rng: R, min_size: usize, max_size: usize) -> Self {
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

/// Network dimension strategy for proptest.
#[derive(Debug)]
pub struct NetworkDimensionStrategy {
    /// Minimum number of nodes for newly generated networks dimensions.
    pub min_size: usize,
    /// Maximum number of nodes for newly generated networks dimensions.
    pub max_size: usize,
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
