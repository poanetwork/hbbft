use proptest::prelude::Rng;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Reason, TestRunner};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NetworkTopology {
    pub size: usize,
    pub faulty: usize,
}

impl NetworkTopology {
    pub fn new(size: usize, faulty: usize) -> Self {
        NetworkTopology { size, faulty }
    }

    pub fn is_sane(&self) -> bool {
        self.faulty * 3 + 1 <= self.size
    }

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

        assert!(half.is_sane());

        half
    }

    pub fn range(min_size: usize, max_size: usize) -> NetworkTopologyStrategy {
        NetworkTopologyStrategy { min_size, max_size }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct NetworkTopologyTree {
    high: NetworkTopology,
    current: NetworkTopology,
    low: NetworkTopology,
}

impl NetworkTopologyTree {
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
        let prev = *self;

        // println!("Before shrinking: {:?}", self);
        self.high = prev.current;
        self.current = self.low.halfway(prev.high);
        // println!("After shrinking: {:?}", self);

        (prev.high != self.high || prev.current != self.current)
    }

    fn complicate(&mut self) -> bool {
        let prev = *self;

        // Minimal increase in faulty-node ratio by adjusting the number of faulty nodes and the
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

#[derive(Debug)]
pub struct NetworkTopologyStrategy {
    pub min_size: usize,
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
