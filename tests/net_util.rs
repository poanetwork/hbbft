extern crate failure;
extern crate hbbft;
#[macro_use]
extern crate proptest;
extern crate integer_sqrt;
extern crate rand;
extern crate rand_core;
extern crate threshold_crypto;

pub mod net;

use proptest::arbitrary::any;
use proptest::prelude::RngCore;
use proptest::strategy::{Strategy, ValueTree};
use rand::{Rng as Rng4, SeedableRng as SeedableRng4};

use net::proptest::{max_sum, NetworkDimension, NetworkDimensionTree};

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

proptest!{
    /// Ensures all generated network dimensions are actually sane.
    #[test]
    fn generated_network_dimensions_are_sane(_nt in NetworkDimension::range(1, 400)) {
        // Nothing to do here, assert already in `NetworkDimension::new`.
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
        println!("Start: {:?}", tree);

        for op in ops {
            println!("Op: {:?}", op);
            match op {
                Op::Simplify => tree.simplify(),
                Op::Complicate => tree.complicate(),
            };
            println!("Result: {:?}", tree);
        }
    }
}

#[test]
fn network_succ_works() {
    let expected = (&[
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 0),
        (4, 1),
        (5, 0),
        (5, 1),
        (6, 0),
        (6, 1),
        (7, 0),
        (7, 1),
        (7, 2),
        (8, 0),
        (8, 1),
        (8, 2),
        (9, 0),
        (9, 1),
        (9, 2),
        (10, 0),
        (10, 1),
        (10, 2),
        (10, 3),
    ])
        .iter()
        .map(|&(n, f)| NetworkDimension::new(n, f));

    let mut dim = NetworkDimension::new(1, 0);

    for exp in expected {
        assert_eq!(dim, exp);
        dim = dim.succ();
    }
}

#[test]
fn test_max_sum() {
    assert_eq!(max_sum(0), 0);
    assert_eq!(max_sum(1), 1);
    assert_eq!(max_sum(2), 1);
    assert_eq!(max_sum(3), 2);
    assert_eq!(max_sum(4), 2);
    assert_eq!(max_sum(5), 2);
    assert_eq!(max_sum(6), 3);
    assert_eq!(max_sum(7), 3);
    assert_eq!(max_sum(8), 3);
    assert_eq!(max_sum(9), 3);
    assert_eq!(max_sum(10), 4);
    assert_eq!(max_sum(5049), 99);
    assert_eq!(max_sum(5050), 100);
    assert_eq!(max_sum(5051), 100);
    assert_eq!(max_sum(5150), 100);
    assert_eq!(max_sum(5151), 101);
}

#[test]
fn network_to_u32_is_correct() {
    assert_eq!(u32::from(NetworkDimension::new(1, 0)), 0u32);
    assert_eq!(u32::from(NetworkDimension::new(2, 0)), 1u32);
    assert_eq!(u32::from(NetworkDimension::new(3, 0)), 2u32);
    assert_eq!(u32::from(NetworkDimension::new(4, 0)), 3u32);
    assert_eq!(u32::from(NetworkDimension::new(4, 1)), 4u32);
    assert_eq!(u32::from(NetworkDimension::new(5, 0)), 5u32);
    assert_eq!(u32::from(NetworkDimension::new(5, 1)), 6u32);
    assert_eq!(u32::from(NetworkDimension::new(6, 0)), 7u32);
    assert_eq!(u32::from(NetworkDimension::new(6, 1)), 8u32);
    assert_eq!(u32::from(NetworkDimension::new(7, 0)), 9u32);
    assert_eq!(u32::from(NetworkDimension::new(7, 1)), 10u32);
    assert_eq!(u32::from(NetworkDimension::new(7, 2)), 11u32);
    assert_eq!(u32::from(NetworkDimension::new(8, 0)), 12u32);
    assert_eq!(u32::from(NetworkDimension::new(8, 1)), 13u32);
    assert_eq!(u32::from(NetworkDimension::new(8, 2)), 14u32);
    assert_eq!(u32::from(NetworkDimension::new(9, 0)), 15u32);
    assert_eq!(u32::from(NetworkDimension::new(9, 1)), 16u32);
    assert_eq!(u32::from(NetworkDimension::new(9, 2)), 17u32);
    assert_eq!(u32::from(NetworkDimension::new(10, 0)), 18u32);
    assert_eq!(u32::from(NetworkDimension::new(10, 1)), 19u32);
    assert_eq!(u32::from(NetworkDimension::new(10, 2)), 20u32);
    assert_eq!(u32::from(NetworkDimension::new(10, 3)), 21u32);
}

#[test]
fn network_from_u32_is_correct() {
    assert_eq!(NetworkDimension::new(1, 0), NetworkDimension::from(0u32));
    assert_eq!(NetworkDimension::new(2, 0), NetworkDimension::from(1u32));
    assert_eq!(NetworkDimension::new(3, 0), NetworkDimension::from(2u32));
    assert_eq!(NetworkDimension::new(4, 0), NetworkDimension::from(3u32));
    assert_eq!(NetworkDimension::new(4, 1), NetworkDimension::from(4u32));
    assert_eq!(NetworkDimension::new(5, 0), NetworkDimension::from(5u32));
    assert_eq!(NetworkDimension::new(5, 1), NetworkDimension::from(6u32));
    assert_eq!(NetworkDimension::new(6, 0), NetworkDimension::from(7u32));
    assert_eq!(NetworkDimension::new(6, 1), NetworkDimension::from(8u32));
    assert_eq!(NetworkDimension::new(7, 0), NetworkDimension::from(9u32));
    assert_eq!(NetworkDimension::new(7, 1), NetworkDimension::from(10u32));
    assert_eq!(NetworkDimension::new(7, 2), NetworkDimension::from(11u32));
    assert_eq!(NetworkDimension::new(8, 0), NetworkDimension::from(12u32));
    assert_eq!(NetworkDimension::new(8, 1), NetworkDimension::from(13u32));
    assert_eq!(NetworkDimension::new(8, 2), NetworkDimension::from(14u32));
    assert_eq!(NetworkDimension::new(9, 0), NetworkDimension::from(15u32));
    assert_eq!(NetworkDimension::new(9, 1), NetworkDimension::from(16u32));
    assert_eq!(NetworkDimension::new(9, 2), NetworkDimension::from(17u32));
    assert_eq!(NetworkDimension::new(10, 0), NetworkDimension::from(18u32));
    assert_eq!(NetworkDimension::new(10, 1), NetworkDimension::from(19u32));
    assert_eq!(NetworkDimension::new(10, 2), NetworkDimension::from(20u32));
    assert_eq!(NetworkDimension::new(10, 3), NetworkDimension::from(21u32));
    assert_eq!(NetworkDimension::new(11, 0), NetworkDimension::from(22u32));
    assert_eq!(NetworkDimension::new(11, 1), NetworkDimension::from(23u32));
    assert_eq!(NetworkDimension::new(11, 2), NetworkDimension::from(24u32));
    assert_eq!(NetworkDimension::new(11, 3), NetworkDimension::from(25u32));
    assert_eq!(NetworkDimension::new(12, 0), NetworkDimension::from(26u32));
    assert_eq!(NetworkDimension::new(12, 1), NetworkDimension::from(27u32));
    assert_eq!(NetworkDimension::new(12, 2), NetworkDimension::from(28u32));
    assert_eq!(NetworkDimension::new(12, 3), NetworkDimension::from(29u32));
    assert_eq!(NetworkDimension::new(13, 0), NetworkDimension::from(30u32));
    assert_eq!(NetworkDimension::new(13, 1), NetworkDimension::from(31u32));
    assert_eq!(NetworkDimension::new(13, 2), NetworkDimension::from(32u32));
    assert_eq!(NetworkDimension::new(13, 3), NetworkDimension::from(33u32));
    assert_eq!(NetworkDimension::new(13, 4), NetworkDimension::from(34u32));
}
