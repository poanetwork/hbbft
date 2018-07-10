//! Tests of the Binary Byzantine Agreement protocol. Only one proposer instance
//! is tested. Each of the nodes in the simulated network run only one instance
//! of Agreement. This way we only test correctness of the protocol and not
//! message dispatch between multiple proposers.
//!
//! There are three properties that are tested:
//!
//! - Agreement: If any correct node outputs the bit b, then every correct node outputs b.
//!
//! - Termination: If all correct nodes receive input, then every correct node outputs a bit.
//!
//! - Validity: If any correct node outputs b, then at least one correct node received b as input.
//!
//! TODO: Implement adversaries and send BVAL messages at different times.

extern crate env_logger;
extern crate hbbft;
#[macro_use]
extern crate log;
extern crate pairing;
extern crate rand;
#[macro_use]
extern crate serde_derive;

mod network;

use std::iter::once;
use std::sync::Arc;

use rand::Rng;

use hbbft::agreement::Agreement;
use hbbft::messaging::NetworkInfo;

use network::{Adversary, MessageScheduler, NodeUid, SilentAdversary, TestNetwork, TestNode};

fn test_agreement<A: Adversary<Agreement<NodeUid>>>(
    mut network: TestNetwork<A, Agreement<NodeUid>>,
    input: Option<bool>,
) {
    let ids: Vec<NodeUid> = network.nodes.keys().cloned().collect();
    for id in ids {
        network.input(id, input.unwrap_or_else(rand::random));
    }

    // Handle messages in random order until all nodes have output the proposed value.
    while !network.nodes.values().all(TestNode::terminated) {
        network.step();
    }
    // Verify that all instances output the same value.
    let mut expected = input;
    for node in network.nodes.values() {
        if let Some(b) = expected {
            assert!(once(&b).eq(node.outputs()));
        } else {
            assert_eq!(1, node.outputs().len());
            expected = Some(node.outputs()[0]);
        }
    }
    assert!(expected.iter().eq(network.observer.outputs()));
}

fn test_agreement_different_sizes<A, F>(new_adversary: F)
where
    A: Adversary<Agreement<NodeUid>>,
    F: Fn(usize, usize) -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();
    let sizes = (1..6)
        .chain(once(rng.gen_range(6, 20)))
        .chain(once(rng.gen_range(30, 50)));
    for size in sizes {
        let num_faulty_nodes = (size - 1) / 3;
        let num_good_nodes = size - num_faulty_nodes;
        for &input in &[None, Some(false), Some(true)] {
            info!(
                "Test start: {} good nodes and {} faulty nodes, input: {:?}",
                num_good_nodes, num_faulty_nodes, input
            );
            let adversary = |_| new_adversary(num_good_nodes, num_faulty_nodes);
            let new_agreement = |netinfo: Arc<NetworkInfo<NodeUid>>| {
                Agreement::new(netinfo, 0, NodeUid(0)).expect("agreement instance")
            };
            let network =
                TestNetwork::new(num_good_nodes, num_faulty_nodes, adversary, new_agreement);
            test_agreement(network, input);
            info!(
                "Test success: {} good nodes and {} faulty nodes, input: {:?}",
                num_good_nodes, num_faulty_nodes, input
            );
        }
    }
}

#[test]
fn test_agreement_random_silent() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::Random);
    test_agreement_different_sizes(new_adversary);
}

#[test]
fn test_agreement_first_silent() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::First);
    test_agreement_different_sizes(new_adversary);
}
