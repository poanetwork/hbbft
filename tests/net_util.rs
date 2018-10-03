extern crate failure;
extern crate hbbft;
#[macro_use]
extern crate proptest;
extern crate rand;
extern crate rand_core;
extern crate threshold_crypto;

pub mod net;

use proptest::arbitrary::any;
use proptest::prelude::RngCore;
use proptest::strategy::{Strategy, ValueTree};
use rand::{Rng as Rng4, SeedableRng as SeedableRng4};

use net::proptest::{NetworkDimension, NetworkDimensionTree};

struct RngAdapter4To5<T>(pub T);

impl<T> Rng4 for RngAdapter4To5<T>
where
    T: Rng4,
{
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
}

impl<T> RngCore for RngAdapter4To5<T>
where
    T: Rng4,
{
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes);
    }

    #[inline]
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill_bytes(bytes);
        Ok(())
    }
}

/// Checks the `check_sanity` function with various inputs.
#[test]
fn check_sanity_works() {
    assert!(NetworkDimension::new(3, 0).is_bft());
    assert!(NetworkDimension::new(4, 0).is_bft());
    assert!(NetworkDimension::new(5, 0).is_bft());
    assert!(NetworkDimension::new(6, 0).is_bft());
    assert!(!NetworkDimension::new(3, 1).is_bft());
    assert!(NetworkDimension::new(4, 1).is_bft());
    assert!(NetworkDimension::new(5, 1).is_bft());
    assert!(NetworkDimension::new(6, 1).is_bft());
    assert!(NetworkDimension::new(16, 3).is_bft());
    assert!(NetworkDimension::new(17, 3).is_bft());
    assert!(NetworkDimension::new(18, 3).is_bft());
    assert!(NetworkDimension::new(19, 3).is_bft());
    assert!(NetworkDimension::new(16, 5).is_bft());
    assert!(NetworkDimension::new(17, 5).is_bft());
    assert!(NetworkDimension::new(18, 5).is_bft());
    assert!(NetworkDimension::new(19, 5).is_bft());
    assert!(!NetworkDimension::new(16, 6).is_bft());
    assert!(!NetworkDimension::new(17, 6).is_bft());
    assert!(!NetworkDimension::new(18, 6).is_bft());
    assert!(NetworkDimension::new(19, 6).is_bft());
    assert!(!NetworkDimension::new(19, 19).is_bft());
    assert!(!NetworkDimension::new(19, 21).is_bft());

    // Edge cases:
    assert!(NetworkDimension::new(1, 0).is_bft());
    assert!(!NetworkDimension::new(0, 0).is_bft());
    assert!(!NetworkDimension::new(1, 1).is_bft());
}

proptest!{
    /// Ensure that `.average_higher()` produces valid new dimensions.
    #[test]
    fn average_higher_is_bft(size in 4..40usize) {
        let mut faulty: usize = size/3;
        if faulty > 0 {
            faulty -= 1;
        }

        let high = NetworkDimension::new(size, faulty);
        let low = NetworkDimension::new(size/4, faulty/12);

        println!("high: {:?}, low: {:?}", high, low);
        assert!(high.is_bft());
        assert!(low.is_bft());

        let average_higher = low.average_higher(high);
        println!("average_higher: {:?}", average_higher);
        assert!(average_higher.is_bft());
    }
}

/// Ensure `.average_higher()` works for edge cases.
#[test]
fn average_higher_handles_edge_cases() {
    let high = NetworkDimension::new(1, 0);
    let low = NetworkDimension::new(1, 0);
    let average_higher = low.average_higher(high);
    assert!(average_higher.is_bft());

    let high = NetworkDimension::new(10, 0);
    let low = NetworkDimension::new(10, 0);
    let average_higher = low.average_higher(high);
    assert!(average_higher.is_bft());

    let high = NetworkDimension::new(10, 3);
    let low = NetworkDimension::new(10, 3);
    let average_higher = low.average_higher(high);
    assert!(average_higher.is_bft());

    let high = NetworkDimension::new(11, 3);
    let low = NetworkDimension::new(10, 3);
    let average_higher = low.average_higher(high);
    assert!(average_higher.is_bft());
}

proptest!{
    /// Ensures all generated network dimensions are actually sane.
    #[test]
    fn generated_network_dimensions_are_sane(nt in NetworkDimension::range(1, 400)) {
        assert!(nt.is_bft());
    }
}

#[derive(Debug)]
enum Op {
    Simplify,
    Complicate,
}

fn any_op() -> impl Strategy<Value = Op> {
    any::<bool>().prop_map(|v| if v { Op::Simplify } else { Op::Complicate })
}

proptest!{
    /// Verifies generated network dimensions can be grown and shrunk multiple times.
    #[test]
    fn network_dimensions_shrink_and_grow(
        // dim in NetworkDimension::range(1, 400).no_shrink(),
        seed in any::<[u32; 4]>().no_shrink(),
        // num_ops in 10..10000,
        ops in proptest::collection::vec(any_op(), 1..100)
    ) {
        let mut rng5 = RngAdapter4To5(rand::XorShiftRng::from_seed(seed));

        let mut tree = NetworkDimensionTree::gen(&mut rng5, 1, 40);
        assert!(tree.current().is_bft());
        println!("Current: {:?}", tree);

        for op in ops.iter() {
            match op {
                Op::Simplify => tree.simplify(),
                Op::Complicate => tree.complicate(),
            };

            assert!(tree.current().is_bft());
        }
    }
}
