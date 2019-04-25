#![deny(unused_must_use)]
//! Tests of the Binary Agreement protocol
//!
//! Each of the nodes in the simulated network runs one instance of Binary Agreement. This suffices
//! to test correctness of the protocol.
//!
//! There are three properties that are tested:
//!
//! - Agreement: If any correct node outputs the bit `b`, then every correct node outputs `b`.
//!
//! - Termination: If all correct nodes receive input, then every correct node outputs a bit.
//!
//! - Validity: If any correct node outputs `b`, then at least one correct node received `b` as
//! input.

use std::iter::once;
use std::sync::Arc;
use std::time;

use hbbft::binary_agreement::BinaryAgreement;
use hbbft::ConsensusProtocol;
use hbbft_testing::adversary::{Adversary, ReorderingAdversary};
use hbbft_testing::proptest::{gen_seed, NetworkDimension, TestRng, TestRngSeed};
use hbbft_testing::{NetBuilder, NewNodeInfo, VirtualNet};
use proptest::arbitrary::any;
use proptest::{prelude::ProptestConfig, prop_compose, proptest};
use rand::{Rng, SeedableRng};

/// Test configuration for Binary Agreement tests.
#[derive(Debug)]
struct TestConfig {
    /// The desired network dimension.
    dimension: NetworkDimension,
    /// Random number generator to be passed to subsystems.
    seed: TestRngSeed,
    /// Input to Binary Agreement instances that has the following meaning:
    ///
    /// - `Some(b)`: all instances receive `b` as input.
    ///
    /// - `None`: each instance receives a random `bool` as input.
    input: Option<bool>,
}

prop_compose! {
    /// Strategy to generate a test configuration.
    fn arb_config()
        (
            dimension in NetworkDimension::range(1, 50),
            seed in gen_seed(),
            input in any::<Option<bool>>(),
        ) -> TestConfig
    {
        TestConfig { dimension, seed, input }
    }
}

/// Proptest wrapper for `binary_agreement` that runs the test function on generated configurations.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1, .. ProptestConfig::default()
    })]
    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn run_binary_agreement(cfg in arb_config()) {
        binary_agreement(cfg)
    }
}

type NodeId = u16;

fn test_binary_agreement<A, R>(
    net: &mut VirtualNet<BinaryAgreement<NodeId, u8>, A>,
    input: Option<bool>,
    mut rng: R,
) where
    R: Rng + 'static,
    A: Adversary<BinaryAgreement<NodeId, u8>>,
{
    let ids: Vec<NodeId> = net.nodes().map(|n| *n.id()).collect();
    for id in ids {
        let _ = net.send_input(id, input.unwrap_or_else(|| rng.gen::<bool>()), &mut rng);
    }

    // Handle messages in random order until all nodes have output the proposed value.
    while !net.nodes().all(|node| node.algorithm().terminated()) {
        let _ = net.crank_expect(&mut rng);
    }
    // Verify that all instances output the same value.
    let mut expected = input;
    for node in net.nodes() {
        if let Some(b) = expected {
            assert!(once(&b).eq(node.outputs()));
        } else {
            assert_eq!(1, node.outputs().len());
            expected = Some(node.outputs()[0]);
        }
    }
    // TODO: As soon as observers are added to the test framework, compare the expected output
    // against the output of observers.
}

/// Tests Binary Agreement on a given configuration.
#[allow(clippy::needless_pass_by_value)]
fn binary_agreement(cfg: TestConfig) {
    let mut rng: TestRng = TestRng::from_seed(cfg.seed);
    let size = cfg.dimension.size();
    let num_faulty_nodes = cfg.dimension.faulty();
    let num_good_nodes = size - num_faulty_nodes;
    println!(
        "Test start: {} good nodes and {} faulty nodes, input: {:?}",
        num_good_nodes, num_faulty_nodes, cfg.input
    );
    // Create a network with `size` validators and one observer.
    let (mut net, _) = NetBuilder::new(0..size as u16)
        .num_faulty(num_faulty_nodes as usize)
        .message_limit(10_000 * size as usize)
        .time_limit(time::Duration::from_secs(30 * size as u64))
        .adversary(ReorderingAdversary::new())
        .using(move |node_info: NewNodeInfo<_>| {
            BinaryAgreement::new(Arc::new(node_info.netinfo), 0)
                .expect("Failed to create a BinaryAgreement instance.")
        })
        .build(&mut rng)
        .expect("Could not construct test network.");
    test_binary_agreement(
        &mut net,
        cfg.input,
        TestRng::from_seed(rng.gen::<TestRngSeed>()),
    );
    println!(
        "Test success: {} good nodes and {} faulty nodes, input: {:?}",
        num_good_nodes, num_faulty_nodes, cfg.input
    );
}
