#![deny(unused_must_use)]
//! Tests of the Binary Agreement protocol. Only one proposer instance
//! is tested. Each of the nodes in the simulated network run only one instance
//! of Binary Agreement. This way we only test correctness of the protocol and not
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
extern crate log;
extern crate rand;
extern crate rand_derive;
extern crate serde_derive;
extern crate threshold_crypto as crypto;

mod network;

use std::iter::once;
use std::sync::Arc;

use log::info;
use rand::Rng;

use hbbft::binary_agreement::BinaryAgreement;
use hbbft::NetworkInfo;

use network::{Adversary, MessageScheduler, NodeId, SilentAdversary, TestNetwork, TestNode};

fn test_binary_agreement<A: Adversary<BinaryAgreement<NodeId, u8>>>(
    mut network: TestNetwork<A, BinaryAgreement<NodeId, u8>>,
    input: Option<bool>,
) {
    let ids: Vec<NodeId> = network.nodes.keys().cloned().collect();
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

fn test_binary_agreement_different_sizes<A, F>(new_adversary: F)
where
    A: Adversary<BinaryAgreement<NodeId, u8>>,
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
            let new_ba = |netinfo: Arc<NetworkInfo<NodeId>>| {
                BinaryAgreement::new(netinfo, 0, false).expect("Binary Agreement instance")
            };
            let network = TestNetwork::new(num_good_nodes, num_faulty_nodes, adversary, new_ba);
            test_binary_agreement(network, input);
            info!(
                "Test success: {} good nodes and {} faulty nodes, input: {:?}",
                num_good_nodes, num_faulty_nodes, input
            );
        }
    }
}

#[test]
fn test_binary_agreement_random_silent() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::Random);
    test_binary_agreement_different_sizes(new_adversary);
}

#[test]
fn test_binary_agreement_first_silent() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::First);
    test_binary_agreement_different_sizes(new_adversary);
}
