#![deny(unused_must_use)]
//! Non-deterministic tests for the ThresholdSign protocol

pub mod net;

use log::info;
use rand::Rng;
use std::sync::Arc;

use hbbft::{crypto::Signature, threshold_sign::ThresholdSign, util, ConsensusProtocol};

use crate::net::adversary::{Adversary, NodeOrderAdversary, ReorderingAdversary};
use crate::net::{NetBuilder, NewNodeInfo, VirtualNet};

type NodeId = u16;

impl<A> VirtualNet<ThresholdSign<NodeId>, A>
where
    A: Adversary<ThresholdSign<NodeId>>,
{
    /// Tests a network of threshold signing instances with an optional expected value. Outputs the
    /// computed signature if the test is successful.
    fn test_threshold_sign(&mut self) -> Signature {
        let mut rng = rand::thread_rng();
        self.broadcast_input(&(), &mut rng)
            .expect("broadcast input failed");

        // Handle messages until all good nodes have terminated.
        while !self.nodes().all(|node| node.algorithm().terminated()) {
            let _ = self.crank_expect(&mut rng);
        }

        // Verify that all instances output the same value.
        let first = self.correct_nodes().nth(0).unwrap().outputs();
        assert!(!first.is_empty());
        assert!(self.nodes().all(|node| node.outputs() == first));

        first[0].clone()
    }
}

const GOOD_SAMPLE_SET: f64 = 400.0;

/// The count of throws of each side of the coin should be approaching 50% with a sufficiently large
/// sample set. This check assumes logarithmic growth of the expected number of throws of one coin
/// size.
fn check_coin_distribution(num_samples: usize, count_true: usize, count_false: usize) {
    // Maximum 40% expectation in case of 400 samples or more.
    const EXPECTED_SHARE: f64 = 0.4;
    let max_gain = GOOD_SAMPLE_SET.log2();
    let num_samples_f64 = num_samples as f64;
    let gain = num_samples_f64.log2().min(max_gain);
    let step = EXPECTED_SHARE / max_gain;
    let min_throws = (num_samples_f64 * gain * step) as usize;
    info!(
        "Expecting a minimum of {} throws for each coin side. Throws of true: {}. Throws of false: {}.",
        min_throws, count_true, count_false
    );
    assert!(count_true > min_throws);
    assert!(count_false > min_throws);
}

fn test_threshold_sign_different_sizes<A, F>(new_adversary: F, num_samples: usize)
where
    A: Adversary<ThresholdSign<NodeId>>,
    F: Fn() -> A,
{
    assert!(num_samples > 0);

    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();

    let mut last_size = 1;
    let mut sizes = vec![last_size];
    let num_sizes = (GOOD_SAMPLE_SET.log2() - (num_samples as f64).log2()) as usize;
    for _ in 0..num_sizes {
        last_size += rng.gen_range(3, 7);
        sizes.push(last_size);
    }

    for size in sizes {
        let num_faulty_nodes = util::max_faulty(size);
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            size - num_faulty_nodes,
            num_faulty_nodes
        );
        let unique_id: u64 = rng.gen();
        let mut count_true = 0;
        let mut count_false = 0;
        for i in 0..num_samples {
            let nonce = format!("My very unique nonce {:x}:{}", unique_id, i);
            info!("Nonce: {}", nonce);
            let (mut net, _) = NetBuilder::new(0..size as u16)
                .num_faulty(num_faulty_nodes as usize)
                .message_limit(size * (size - 1))
                .no_time_limit()
                .adversary(new_adversary())
                .using(move |node_info: NewNodeInfo<_>| {
                    ThresholdSign::new_with_document(Arc::new(node_info.netinfo), nonce.clone())
                        .expect("Failed to create a ThresholdSign instance.")
                })
                .build(&mut rng)
                .expect("Could not construct test network.");
            let coin = net.test_threshold_sign().parity();
            if coin {
                count_true += 1;
            } else {
                count_false += 1;
            }
        }
        check_coin_distribution(num_samples, count_true, count_false);
    }
}

#[test]
fn test_threshold_sign_random_silent_200_samples() {
    let new_adversary = || ReorderingAdversary::new();
    test_threshold_sign_different_sizes(new_adversary, 200);
}

#[test]
fn test_threshold_sign_first_silent_50_samples() {
    let new_adversary = || NodeOrderAdversary::new();
    test_threshold_sign_different_sizes(new_adversary, 50);
}
