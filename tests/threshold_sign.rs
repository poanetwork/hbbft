#![deny(unused_must_use)]
//! Threshold signing tests

extern crate env_logger;
extern crate hbbft;
extern crate log;
extern crate rand;
extern crate rand_derive;
extern crate serde_derive;
extern crate threshold_crypto as crypto;

mod network;

use std::iter::once;

use log::info;
use rand::Rng;
use rand_derive::Rand;
use serde_derive::{Deserialize, Serialize};

use crypto::Signature;
use hbbft::{threshold_sign::ThresholdSign, util};

use network::{Adversary, MessageScheduler, NodeId, SilentAdversary, TestNetwork, TestNode};

/// Tests a network of threshold signing instances with an optional expected value. Outputs the
/// computed signature if the test is successful.
fn test_threshold_sign<A>(mut network: TestNetwork<A, ThresholdSign<NodeId>>) -> Signature
where
    A: Adversary<ThresholdSign<NodeId>>,
{
    network.input_all(());
    network.observer.handle_input(()); // Observer will only return after `input` was called.

    // Handle messages until all good nodes have terminated.
    while !network.nodes.values().all(TestNode::terminated) {
        network.step();
    }
    let mut expected = None;
    // Verify that all instances output the same value.
    for node in network.nodes.values() {
        if let Some(ref b) = expected {
            assert!(once(b).eq(node.outputs()));
        } else {
            assert_eq!(1, node.outputs().len());
            expected = Some(node.outputs()[0].clone());
        }
    }
    // Now `expected` is the unique output of all good nodes.
    assert!(expected.iter().eq(network.observer.outputs()));
    expected.unwrap()
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
    F: Fn(usize, usize) -> A,
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
        let num_good_nodes = size - num_faulty_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_faulty_nodes
        );
        let unique_id: u64 = rng.gen();
        let mut count_true = 0;
        let mut count_false = 0;
        for i in 0..num_samples {
            let adversary = |_| new_adversary(num_good_nodes, num_faulty_nodes);
            let nonce = format!("My very unique nonce {:x}:{}", unique_id, i);
            info!("Nonce: {}", nonce);
            let new_coin = |netinfo: _| {
                ThresholdSign::new_with_document(netinfo, nonce.clone())
                    .expect("Failed to set the new coin's ID")
            };
            let network = TestNetwork::new(num_good_nodes, num_faulty_nodes, adversary, new_coin);
            let coin = test_threshold_sign(network).parity();
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
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::Random);
    test_threshold_sign_different_sizes(new_adversary, 200);
}

#[test]
fn test_threshold_sign_first_silent_50_samples() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::First);
    test_threshold_sign_different_sizes(new_adversary, 50);
}
