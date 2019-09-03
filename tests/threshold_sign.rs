#![deny(unused_must_use)]
//! Non-deterministic tests for the ThresholdSign protocol

use std::sync::Arc;

use hbbft::{threshold_sign::ThresholdSign, util, ConsensusProtocol};
use hbbft_testing::adversary::{Adversary, NodeOrderAdversary, ReorderingAdversary};
use hbbft_testing::proptest::{gen_seed, TestRng, TestRngSeed};
use hbbft_testing::{NetBuilder, NewNodeInfo, VirtualNet};
use log::info;
use proptest::{prelude::ProptestConfig, proptest};
use rand::{Rng, SeedableRng};

type NodeId = u16;

/// Creates a new test network.
fn new_net<A, M, R>(
    size: usize,
    num_faulty: usize,
    adv: A,
    msg: M,
    rng: &mut R,
) -> VirtualNet<ThresholdSign<NodeId>, A>
where
    M: AsRef<[u8]> + 'static,
    A: Adversary<ThresholdSign<NodeId>>,
    R: Rng,
{
    NetBuilder::new(0..size as u16)
        .num_faulty(num_faulty as usize)
        .message_limit(size * (size - 1))
        .no_time_limit()
        .adversary(adv)
        .using(move |node_info: NewNodeInfo<_>| {
            ThresholdSign::new_with_document(Arc::new(node_info.netinfo), &msg)
                .expect("Failed to create a ThresholdSign instance.")
        })
        .build(rng)
        .expect("Could not construct test network.")
        .0
}

/// Tests a network of threshold signing instances.
fn test_threshold_sign_different_sizes<A, F>(new_adversary: F, seed: TestRngSeed)
where
    A: Adversary<ThresholdSign<NodeId>>,
    F: Fn() -> A,
{
    const MSG: &str = "message";
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng: TestRng = TestRng::from_seed(seed);

    for &size in &[1, 2, 3, 4, 8, 15, 31] {
        let num_faulty_nodes = util::max_faulty(size);
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            size - num_faulty_nodes,
            num_faulty_nodes
        );
        let mut net = new_net(size, num_faulty_nodes, new_adversary(), MSG, &mut rng);
        net.broadcast_input(&(), &mut rng)
            .expect("threshold sign input failed");
        // Handle messages until all good nodes have terminated.
        while !net.nodes().all(|node| node.algorithm().terminated()) {
            let _ = net.crank_expect(&mut rng);
        }
        let node0 = net.correct_nodes().nth(0).unwrap();
        // Verify that all instances output the same value.
        assert_eq!(1, node0.outputs().len());
        assert!(net.nodes().all(|node| node.outputs() == node0.outputs()));
        let pk = node0.algorithm().netinfo().public_key_set().public_key();
        assert!(pk.verify(&node0.outputs()[0], MSG));
    }
}

const GOOD_SAMPLE_SET: f64 = 400.0;

/// The count of throws of each side of the coin should be approaching 50% with a sufficiently large
/// sample set. This check assumes logarithmic growth of the expected number of throws of one coin
/// size.
fn check_coin_distribution(num_samples: usize, count_true: usize, count_false: usize) {
    // Maximum 40% expectation in case of 400 samples or more.
    const EXPECTED_SHARE: f64 = 0.33;
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

fn test_coin_different_sizes<A, F>(new_adversary: F, num_samples: usize, seed: TestRngSeed)
where
    A: Adversary<ThresholdSign<NodeId>>,
    F: Fn() -> A,
{
    assert!(num_samples > 0);

    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng: TestRng = TestRng::from_seed(seed);

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
            let mut net = new_net(size, num_faulty_nodes, new_adversary(), nonce, &mut rng);
            net.broadcast_input(&(), &mut rng)
                .expect("threshold sign input failed");
            // Handle messages until all good nodes have terminated.
            while !net.nodes().all(|node| node.algorithm().terminated()) {
                let _ = net.crank_expect(&mut rng);
            }
            let node0 = net.correct_nodes().nth(0).unwrap();
            // Verify that all instances output the same value.
            assert_eq!(1, node0.outputs().len());
            assert!(net.nodes().all(|node| node.outputs() == node0.outputs()));
            let coin = node0.outputs()[0].parity();
            if coin {
                count_true += 1;
            } else {
                count_false += 1;
            }
        }
        check_coin_distribution(num_samples, count_true, count_false);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1, .. ProptestConfig::default()
    })]

    #[test]
    fn test_coin_random_silent_200_samples(seed in gen_seed()) {
        let new_adversary = || ReorderingAdversary::new();
        test_coin_different_sizes(new_adversary, 200, seed);
    }

    #[test]
    fn test_coin_first_silent_50_samples(seed in gen_seed()) {
        let new_adversary = || NodeOrderAdversary::new();
        test_coin_different_sizes(new_adversary, 50, seed);
    }

    #[test]
    fn test_threshold_sign(seed in gen_seed()) {
        let new_adversary = || ReorderingAdversary::new();
        test_threshold_sign_different_sizes(new_adversary, seed);
    }
}
