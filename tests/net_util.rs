extern crate failure;
extern crate hbbft;
#[macro_use]
extern crate proptest;
extern crate rand;
extern crate threshold_crypto;

pub mod net;

use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

use net::proptest::{NetworkTopology, NetworkTopologyTree};

/// Checks the `check_sanity` function with various inputs.
#[test]
fn check_sanity_works() {
    assert!(NetworkTopology::new(3, 0).is_sane());
    assert!(NetworkTopology::new(4, 0).is_sane());
    assert!(NetworkTopology::new(5, 0).is_sane());
    assert!(NetworkTopology::new(6, 0).is_sane());
    assert!(!NetworkTopology::new(3, 1).is_sane());
    assert!(NetworkTopology::new(4, 1).is_sane());
    assert!(NetworkTopology::new(5, 1).is_sane());
    assert!(NetworkTopology::new(6, 1).is_sane());
    assert!(NetworkTopology::new(16, 3).is_sane());
    assert!(NetworkTopology::new(17, 3).is_sane());
    assert!(NetworkTopology::new(18, 3).is_sane());
    assert!(NetworkTopology::new(19, 3).is_sane());
    assert!(NetworkTopology::new(16, 5).is_sane());
    assert!(NetworkTopology::new(17, 5).is_sane());
    assert!(NetworkTopology::new(18, 5).is_sane());
    assert!(NetworkTopology::new(19, 5).is_sane());
    assert!(!NetworkTopology::new(16, 6).is_sane());
    assert!(!NetworkTopology::new(17, 6).is_sane());
    assert!(!NetworkTopology::new(18, 6).is_sane());
    assert!(NetworkTopology::new(19, 6).is_sane());
    assert!(!NetworkTopology::new(19, 19).is_sane());
    assert!(!NetworkTopology::new(19, 21).is_sane());

    // Edge cases:
    assert!(NetworkTopology::new(1, 0).is_sane());
    assert!(!NetworkTopology::new(0, 0).is_sane());
    assert!(!NetworkTopology::new(1, 1).is_sane());
}

proptest!{
    /// Ensure that `.halfway()` produces valid new topologies.
    #[test]
    fn halfway_is_sane(size in 4..40usize) {
        let mut faulty: usize = size/3;
        if faulty > 0 {
            faulty -= 1;
        }

        let high = NetworkTopology::new(size, faulty);
        let low = NetworkTopology::new(size/4, faulty/12);

        println!("high: {:?}, low: {:?}", high, low);
        assert!(high.is_sane());
        assert!(low.is_sane());

        let halfway = low.halfway(high);
        println!("halfway: {:?}", halfway);
        assert!(halfway.is_sane());
    }
}

/// Ensure `.halfway()` works for edge cases.
#[test]
fn halfway_handles_edge_cases() {
    let high = NetworkTopology::new(1, 0);
    let low = NetworkTopology::new(1, 0);
    let halfway = low.halfway(high);
    assert!(halfway.is_sane());

    let high = NetworkTopology::new(10, 0);
    let low = NetworkTopology::new(10, 0);
    let halfway = low.halfway(high);
    assert!(halfway.is_sane());

    let high = NetworkTopology::new(10, 3);
    let low = NetworkTopology::new(10, 3);
    let halfway = low.halfway(high);
    assert!(halfway.is_sane());

    let high = NetworkTopology::new(11, 3);
    let low = NetworkTopology::new(10, 3);
    let halfway = low.halfway(high);
    assert!(halfway.is_sane());
}

proptest!{
    /// Ensures all generated network topologies are actually sane.
    #[test]
    fn generated_network_topologies_are_sane(nt in NetworkTopology::range(1, 400)) {
        assert!(nt.is_sane());
    }
}

/// Verifies generated network topologies can be grown and shrunk multiple times.
#[test]
fn network_topologies_shrink_and_grow() {
    let mut runner = TestRunner::new(Default::default());

    let mut tree = NetworkTopologyTree::gen(runner.rng(), 1, 40);
    assert!(tree.current().is_sane());

    // We complicate and simplify a few times.
    for _ in 0..10 {
        tree.complicate();
        assert!(tree.current().is_sane());
    }

    for _ in 0..20 {
        tree.simplify();
        assert!(tree.current().is_sane());
    }

    for _ in 0..10 {
        tree.complicate();
        assert!(tree.current().is_sane());
    }

    for _ in 0..10 {
        tree.simplify();
        assert!(tree.current().is_sane());
    }
}
