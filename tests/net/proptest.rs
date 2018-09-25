//! Proptest helpers and strategies.
//!
//! This module houses strategies to generate (and reduce/expand) various `hbbft` and `net` related
//! structures.

use std::{cell, fmt};

use hbbft::messaging::DistAlgorithm;
use net::adversary::{self, Adversary};
use proptest::prelude::{any, Rng};
use proptest::strategy::{BoxedStrategy, LazyJust, Strategy, ValueTree};
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

/// Adversary configuration.
///
/// Describes a generic adversary and can be used to instantiate it. All configurations are ordered
/// in terms of approximate complexity.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum AdversaryConfiguration {
    /// A `NullAdversary`.
    Null,
    /// A `NodeOrderAdversary`.
    NodeOrder,
    /// A `SilentAdversary`.
    Silent,
    /// A `ReorderingAdversary`.
    ///
    /// Includes an opaque complexity value that specifies how active the adversary acts.
    Reordering(u8), // random complexity value
    /// A `RandomAdversary`.
    ///
    /// Includes an opaque complexity value that specifies how active the adversary acts.
    Random(u8), // random complexity value, not a seed!
}

impl AdversaryConfiguration {
    pub fn average_higher(&self, high: AdversaryConfiguration) -> Self {
        assert!(*self <= high);

        let l: u8 = (*self).into();
        let h: u8 = high.into();

        AdversaryConfiguration::from(l + (h - l) / 2)
    }

    pub fn create_adversary<D>(&self) -> Box<dyn Adversary<D>>
    where
        D: DistAlgorithm,
        D::Message: Clone,
        D::Output: Clone,
    {
        match self {
            AdversaryConfiguration::Null => Box::new(adversary::NullAdversary::new()),
            _ => unimplemented!(),
        }
    }
}

impl From<u8> for AdversaryConfiguration {
    fn from(raw: u8) -> AdversaryConfiguration {
        match raw.min(34) {
            0 => AdversaryConfiguration::Null,
            1 => AdversaryConfiguration::NodeOrder,
            2 => AdversaryConfiguration::Silent,
            // `Reordering` and `Random` adversary each know 16 different complexities.
            n if n <= 18 => AdversaryConfiguration::Reordering(n - 2),
            n if n <= 34 => AdversaryConfiguration::Random(n - 18),
            // The `.min` above ensure no values exceeds the tested ones.
            _ => unreachable!(),
        }
    }
}

impl From<AdversaryConfiguration> for u8 {
    fn from(at: AdversaryConfiguration) -> u8 {
        match at {
            AdversaryConfiguration::Null => 0,
            AdversaryConfiguration::NodeOrder => 1,
            AdversaryConfiguration::Silent => 2,
            AdversaryConfiguration::Reordering(n) => n + 2,
            AdversaryConfiguration::Random(n) => n + 18,
        }
    }
}

struct AdversaryTree<D> {
    high: AdversaryConfiguration,
    current: AdversaryConfiguration,
    low: AdversaryConfiguration,
    current_instance: cell::RefCell<Option<Box<dyn Adversary<D>>>>,
}

impl<D> ValueTree for AdversaryTree<D>
where
    Adversary<D>: fmt::Debug + Clone,
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
{
    type Value = Box<Adversary<D> + 'static>;

    fn current(&self) -> Self::Value {
        // Through `current_instance` we only instantiate the adversary once its requested. This
        // is not done for performance but code structuring purposes (actual gains would likely
        // be very small). If this causes any issues due to the resulting `?Sync`, the  cell can be
        // removed and an instance created inside `simplify` and `complicate` each time the state
        // changes.
        self.current_instance
            .borrow_mut()
            .get_or_insert_with(|| self.current.create_adversary())
            .clone()
    }

    fn simplify(&mut self) -> bool {
        let prev_high = self.high;
        let prev_current = self.current;

        self.high = self.current;
        self.current = self.low.average_higher(prev_high);

        (prev_high != self.high || prev_current != self.current)
    }

    fn complicate(&mut self) -> bool {
        let new_low: AdversaryConfiguration = (u8::from(self.low) + 1).into();
        let prev_low = self.low;
        let prev_current = self.current;

        if new_low > self.high {
            // We already hit the max.
            return false;
        }

        self.current = new_low.average_higher(self.high);
        self.low = new_low;

        (prev_current != self.current || prev_low != self.low)
    }
}

fn boxed_null_adversary<D>() -> Box<dyn Adversary<D>>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
{
    adversary::NullAdversary::new().boxed()
}

fn boxed_node_order_adversary<D>() -> Box<dyn Adversary<D>>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
{
    adversary::NodeOrderAdversary::new().boxed()
}

fn generic_adversary<D>()
// -> impl Strategy
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
{
    // let b1 = || boxed_adversary(adversary::NullAdversary::new);
    // prop_oneof![
    // boxed_null_adversary::<D>,
    // boxed_node_order_adversary::<D>(),
    //     // LazyJust::new(|| Box::new(adversary::NodeOrderAdversary::new()))
    // ]
    // unimplemented!()
}
