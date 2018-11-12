#![deny(unused_must_use)]
//! Tests of the Binary Agreement protocol
//!
//! Only one proposer instance is tested. Each of the nodes in the simulated network run only one
//! instance of Binary Agreement. This way we only test correctness of the protocol and not message
//! dispatch between multiple proposers.
//!
//! There are three properties that are tested:
//!
//! - Agreement: If any correct node outputs the bit `b`, then every correct node outputs `b`.
//!
//! - Termination: If all correct nodes receive input, then every correct node outputs a bit.
//!
//! - Validity: If any correct node outputs `b`, then at least one correct node received `b` as
//! input.

extern crate env_logger;
extern crate failure;
extern crate hbbft;
extern crate integer_sqrt;
extern crate log;
extern crate proptest;
extern crate rand;
extern crate threshold_crypto;

mod net;

use std::iter::once;
use std::sync::Arc;
use std::time;

use log::info;
use rand::Rng;

use hbbft::binary_agreement::BinaryAgreement;
use hbbft::DistAlgorithm;

use net::adversary::ReorderingAdversary;
use net::proptest::TestRng;
use net::{NetBuilder, NewNodeInfo, VirtualNet};

type NodeId = usize;
type SessionId = u8;
type Algo = BinaryAgreement<NodeId, SessionId>;

impl VirtualNet<Algo> {
    fn test_binary_agreement<R>(&mut self, input: Option<bool>, mut rng: R)
    where
        R: Rng + 'static,
    {
        let ids: Vec<NodeId> = self.nodes().map(|n| n.id().clone()).collect();
        for id in ids {
            let _ = self.send_input(id, input.unwrap_or_else(|| rng.gen::<bool>()));
        }

        // Handle messages in random order until all nodes have output the proposed value.
        while !self.nodes().all(|node| node.algorithm().terminated()) {
            let _ = self.crank_expect();
        }
        // Verify that all instances output the same value.
        let mut expected = input;
        for node in self.nodes() {
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
}

fn test_binary_agreement_different_sizes() {
    // FIXME: Seed the Rng.
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
            let mut net: VirtualNet<_> = NetBuilder::new(0..size)
                .num_faulty(num_faulty_nodes)
                .message_limit(10_000 * size as usize)
                .time_limit(time::Duration::from_secs(30 * size as u64))
                .rng(rng.gen::<TestRng>())
                .adversary(ReorderingAdversary::new(rng.gen::<TestRng>()))
                .using(move |node_info: NewNodeInfo<_>| {
                    BinaryAgreement::new(Arc::new(node_info.netinfo), 0)
                        .expect("Failed to create a BinaryAgreement instance.")
                }).build()
                .expect("Could not construct test network.");
            net.test_binary_agreement(input, rng.gen::<TestRng>());
            info!(
                "Test success: {} good nodes and {} faulty nodes, input: {:?}",
                num_good_nodes, num_faulty_nodes, input
            );
        }
    }
}

/// Tests Binary Agreement with random inputs, all `false` inputs and all `true` inputs.
#[test]
fn binary_agreement() {
    let _ = env_logger::try_init();
    test_binary_agreement_different_sizes();
}
