extern crate failure;
extern crate hbbft;
#[macro_use]
extern crate proptest;
extern crate rand;
extern crate threshold_crypto;

pub mod net;

use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

use net::proptest::{NetworkDimension, NetworkDimensionTree};

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

/// Verifies generated network dimensions can be grown and shrunk multiple times.
#[test]
fn network_dimensions_shrink_and_grow() {
    let mut runner = TestRunner::new(Default::default());

    let mut tree = NetworkDimensionTree::gen(runner.rng(), 1, 40);
    assert!(tree.current().is_bft());

    // We complicate and simplify a few times.
    for _ in 0..10 {
        tree.complicate();
        assert!(tree.current().is_bft());
    }

    for _ in 0..20 {
        tree.simplify();
        assert!(tree.current().is_bft());
    }

    for _ in 0..10 {
        tree.complicate();
        assert!(tree.current().is_bft());
    }

    for _ in 0..10 {
        tree.simplify();
        assert!(tree.current().is_bft());
    }
}
