//! Proptest helpers and strategies
//!
//! This module houses strategies to generate (and reduce/expand) various `hbbft` and `net` related
//! structures.

use proptest::prelude::Rng;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Reason, TestRunner};

/// Node network topology.
///
/// A `NetworkTopology` describes the number of correct and faulty nodes in a network. It can also
/// be checked, "averaged" (using the `halfway` function) and generated using `NetworkTopologyTree`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NetworkTopology {
    /// Total number of nodes in network.
    pub size: usize,
    /// Number of faulty nodes in a network.
    pub faulty: usize,
}

impl NetworkTopology {
    /// Creates a new `NetworkTopology` with the supplied parameters.
    ///
    /// # Panics
    ///
    /// `size` and `faulty` must not satisfy the conditions imposed by `is_sane`.
    pub fn new(size: usize, faulty: usize) -> Self {
        let nt = NetworkTopology { size, faulty };
        assert!(nt.is_sane());
        nt
    }

    /// Checks whether the network topology satisfies the `3 * faulty + 1 <= size`
    pub fn is_sane(&self) -> bool {
        self.faulty * 3 + 1 <= self.size
    }

    /// Creates a new topology of average complexity.
    ///
    /// The new topology is approximately half way in the interval of `[self, high]` and will
    /// conform to the constraint checked by `is_sane()`.
    ///
    /// # Panics
    ///
    /// `high` must be have a higher or equal size and faulty node count.
    pub fn halfway(&self, high: NetworkTopology) -> NetworkTopology {
        assert!(high.size >= self.size);
        assert!(high.faulty >= self.faulty);

        // We try halving both values, rounding down. If `size` is at the minimum, `faulty` will
        // shrink afterwards.
        let mut half = NetworkTopology {
            size: self.size + (high.size - self.size) / 2,
            faulty: self.faulty + (high.faulty - self.faulty) / 2,
        };

        // Reduce the number of faulty nodes, if we are outside our limits.
        if !half.faulty * 3 <= half.size {
            half.faulty -= 1;
        }

        // This assert just checks for bugs.
        assert!(half.is_sane());

        half
    }

    /// Creates a proptest strategy to create network topologies within a certain range.
    pub fn range(min_size: usize, max_size: usize) -> NetworkTopologyStrategy {
        NetworkTopologyStrategy { min_size, max_size }
    }
}

/// Network topology tree for proptest generation.
#[derive(Copy, Clone, Debug)]
pub struct NetworkTopologyTree {
    high: NetworkTopology,
    current: NetworkTopology,
    low: NetworkTopology,
}

impl NetworkTopologyTree {
    /// Generate a random network topology tree
    ///
    /// The resulting initial `NetworkTopology` will have a number of nodes within
    /// [`min_size`, `max_size`] and a valid number of faulty nodes.
    ///
    /// # Panics
    ///
    /// The minimum `min_size` is 1 and `min_size` must be less or equal `max_size`.
    pub fn gen<R: Rng>(mut rng: R, min_size: usize, max_size: usize) -> Self {
        // A common mistake, add an extra assert for a more helpful error message.
        assert!(min_size > 0, "minimum network size is 1");

        let total = rng.gen_range(min_size, max_size + 1);
        let max_faulty = (total - 1) / 3;
        let faulty = rng.gen_range(0, max_faulty + 1);

        let high = NetworkTopology {
            size: total,
            faulty,
        };
        assert!(high.is_sane());

        let low = NetworkTopology {
            size: min_size,
            faulty: 0,
        };
        assert!(low.is_sane());

        NetworkTopologyTree {
            high,
            current: high,
            low,
        }
    }
}

impl ValueTree for NetworkTopologyTree {
    type Value = NetworkTopology;

    fn current(&self) -> Self::Value {
        self.current.clone()
    }

    fn simplify(&mut self) -> bool {
        // Shrinking is simply done through `halfway`.
        let prev = *self;

        self.high = prev.current;
        self.current = self.low.halfway(prev.high);

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
        assert!(new_low.is_sane());

        // Instead of growing the network, return unchanged if the new network would be larger than
        // the current high.
        if new_low.size > self.high.size {
            return false;
        }

        self.current = new_low.halfway(self.high);
        self.low = new_low;

        (prev.current != self.current || prev.low != self.low)
    }
}

/// Network topology strategy for proptest.
#[derive(Debug)]
pub struct NetworkTopologyStrategy {
    /// Minimum number of nodes for newly generated networks topologies.
    pub min_size: usize,
    /// Maximum number of nodes for newly generated networks topologies.
    pub max_size: usize,
}

impl Strategy for NetworkTopologyStrategy {
    type Value = NetworkTopology;
    type Tree = NetworkTopologyTree;

    fn new_tree(&self, runner: &mut TestRunner) -> Result<Self::Tree, Reason> {
        Ok(NetworkTopologyTree::gen(
            runner.rng(),
            self.min_size,
            self.max_size,
        ))
    }
}
