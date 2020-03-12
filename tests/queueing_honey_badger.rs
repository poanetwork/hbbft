#![deny(unused_must_use)]
//! Network tests for Queueing Honey Badger.

use std::collections::BTreeSet;
use std::sync::Arc;

use hbbft::dynamic_honey_badger::{DynamicHoneyBadger, JoinPlan};
use hbbft::queueing_honey_badger::{Change, ChangeState, Input, QueueingHoneyBadger};
use hbbft::sender_queue::{Message, SenderQueue, Step};
use hbbft::util;
use hbbft_testing::adversary::{Adversary, NodeOrderAdversary, ReorderingAdversary};
use hbbft_testing::proptest::{gen_seed, TestRng, TestRngSeed};
use hbbft_testing::{NetBuilder, NewNodeInfo, Node, VirtualNet};
use log::info;
use proptest::{prelude::ProptestConfig, proptest};
use rand::{Rng, SeedableRng};

type NodeId = u16;
type QHB = QueueingHoneyBadger<usize, NodeId, Vec<usize>>;
type SQ = SenderQueue<QHB>;

// Send the second half of the transactions to the specified node.
fn input_second_half<A>(
    net: &mut VirtualNet<SQ, A>,
    id: NodeId,
    num_txs: usize,
    mut rng: &mut TestRng,
) where
    A: Adversary<SQ>,
{
    for tx in (num_txs / 2)..num_txs {
        let _ = net.send_input(id, Input::User(tx), &mut rng);
    }
}

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_queueing_honey_badger<A>(mut net: VirtualNet<SQ, A>, num_txs: usize, mut rng: &mut TestRng)
where
    A: Adversary<SQ>,
{
    // Make two copies of all public keys.
    let pub_keys_add = net
        .correct_nodes()
        .next()
        .expect("At least one correct node needs to exist")
        .algorithm()
        .algo()
        .dyn_hb()
        .public_keys()
        .clone();

    let mut pub_keys_rm = pub_keys_add.clone();

    // Get the first correct node id as candidate for removal/re-adding.
    let first_correct_node = *net.correct_nodes().next().unwrap().id();

    // Remove the first correct node, which is to be removed.
    Arc::make_mut(&mut pub_keys_rm).remove(&first_correct_node);

    // Broadcast public keys of all nodes except for the node to be removed.
    let _ = net.broadcast_input(
        &Input::Change(Change::NodeChange(pub_keys_rm.clone())),
        &mut rng,
    );

    // Broadcast the first half of the transactions.
    for tx in 0..(num_txs / 2) {
        let _ = net.broadcast_input(&Input::User(tx), &mut rng);
    }

    // Closure for checking the output of a node for ChangeSet completion containing
    // all nodes but the removed node.
    let has_remove = |node: &Node<SQ>| {
        node.outputs().iter().any(|batch| match batch.change() {
            ChangeState::Complete(Change::NodeChange(pub_keys)) => pub_keys == &pub_keys_rm,
            _ => false,
        })
    };

    // Closure for checking the output of a node for ChangeSet completion containing
    // all nodes, including the previously removed node.
    let has_add = |node: &Node<SQ>| {
        node.outputs().iter().any(|batch| match batch.change() {
            ChangeState::Complete(Change::NodeChange(pub_keys)) => pub_keys == &pub_keys_add,
            _ => false,
        })
    };

    // Returns `true` if the node has not output all changes or transactions yet.
    let node_busy = |node: &Node<SQ>| {
        !has_remove(node) || !has_add(node) || !node.algorithm().algo().queue().is_empty()
    };

    // All nodes await removal.
    let mut awaiting_removal: BTreeSet<_> = net.correct_nodes().map(|node| *node.id()).collect();

    // All nodes but the removed node await addition.
    let mut awaiting_addition: BTreeSet<_> = net
        .correct_nodes()
        .map(|node| *node.id())
        .filter(|id| *id != first_correct_node)
        .collect();

    // All, including the previously removed node, await the second half of transactions.
    let mut awaiting_second_half: BTreeSet<_> = awaiting_removal.clone();
    // Whether the first correct node was rejoined as a validator.
    let mut rejoined_first_correct = false;
    // The removed first correct node which is to be restarted as soon as all remaining
    // validators agreed to add it back.
    let mut saved_first_correct: Option<Node<SQ>> = None;

    // Handle messages in random order until all nodes have output all transactions.
    while net.correct_nodes().any(node_busy) {
        let stepped_id = net.crank_expect(&mut rng).0;
        if awaiting_removal.contains(&stepped_id) && has_remove(&net.get(stepped_id).unwrap()) {
            awaiting_removal.remove(&stepped_id);
            info!(
                "{:?} has finished waiting for node removal; still waiting: {:?}",
                stepped_id, awaiting_removal
            );

            if awaiting_removal.is_empty() {
                info!("Removing first correct node from the test network");
                saved_first_correct = net.remove_node(&first_correct_node);
            }
            // Vote to add the first correct node back.
            if stepped_id != first_correct_node {
                let _ = net.send_input(
                    stepped_id,
                    Input::Change(Change::NodeChange(pub_keys_add.clone())),
                    rng,
                );
                info!(
                    "Input the vote to add the first correct node into {:?} with netinfo {:?}",
                    stepped_id,
                    net.get(stepped_id).unwrap().algorithm().algo().netinfo()
                );
            }
        }

        if awaiting_removal.is_empty() && awaiting_addition.contains(&stepped_id) {
            // If the stepped node started voting to add the first correct node back,
            // take a note of that and rejoin it.
            if let Some(join_plan) =
                net.get(stepped_id)
                    .unwrap()
                    .outputs()
                    .iter()
                    .find_map(|batch| match batch.change() {
                        ChangeState::InProgress(Change::NodeChange(pub_keys))
                            if pub_keys == &pub_keys_add =>
                        {
                            batch.join_plan()
                        }
                        _ => None,
                    })
            {
                awaiting_addition.remove(&stepped_id);
                info!(
                    "{:?} has finished waiting for node addition; still waiting: {:?}",
                    stepped_id, awaiting_addition
                );
                if awaiting_addition.is_empty() && !rejoined_first_correct {
                    let node = saved_first_correct
                        .take()
                        .expect("first correct node wasn't saved");
                    let step = restart_node_for_add(&mut net, node, join_plan, &mut rng);
                    net.process_step(first_correct_node, &step)
                        .expect("processing a step failed");
                    rejoined_first_correct = true;
                }
            }
        }

        if rejoined_first_correct && awaiting_second_half.contains(&stepped_id) {
            // Input the second half of user transactions into the stepped node.
            input_second_half(&mut net, stepped_id, num_txs, &mut rng);
            awaiting_second_half.remove(&stepped_id);
        }
    }
    let node_1 = net
        .correct_nodes()
        .nth(1)
        .expect("second correct node is missing");
    net.verify_batches(node_1);
}

/// Restarts specified node on the test network for adding it back as a validator.
fn restart_node_for_add<R, A>(
    net: &mut VirtualNet<SQ, A>,
    mut node: Node<SQ>,
    join_plan: JoinPlan<NodeId>,
    mut rng: &mut R,
) -> Step<QueueingHoneyBadger<usize, NodeId, Vec<usize>>>
where
    R: rand::Rng,
    A: Adversary<SQ>,
{
    let our_id = *node.id();
    println!("Restarting node {} with {:?}", node.id(), join_plan);

    // TODO: When an observer node is added to the network, it should also be added to peer_ids.
    let peer_ids: Vec<_> = net
        .nodes()
        .map(Node::id)
        .filter(|id| *id != node.id())
        .cloned()
        .collect();

    let secret_key = node.algorithm().algo().dyn_hb().secret_key().clone();
    let (qhb, qhb_step) =
        QueueingHoneyBadger::builder_joining(our_id, secret_key, join_plan, &mut rng)
            .and_then(|builder| builder.batch_size(3).build(&mut rng))
            .expect("failed to rebuild the node with a join plan");
    let (sq, mut sq_step) = SenderQueue::builder(qhb, peer_ids.into_iter()).build(our_id);
    *node.algorithm_mut() = sq;
    sq_step.extend(qhb_step.map(|output| output, |fault| fault, Message::from));
    net.insert_node(node);
    sq_step
}

// Allow passing `netinfo` by value. `TestNetwork` expects this function signature.
#[allow(clippy::needless_pass_by_value)]
fn new_queueing_hb(node_info: NewNodeInfo<SQ>, seed: TestRngSeed) -> (SQ, Step<QHB>) {
    let mut rng: TestRng = TestRng::from_seed(seed);
    let peer_ids = node_info.netinfo.other_ids().cloned();
    let netinfo = node_info.netinfo.clone();
    let dhb =
        DynamicHoneyBadger::builder().build(netinfo, node_info.secret_key, node_info.pub_keys);
    let (qhb, qhb_step) = QueueingHoneyBadger::builder(dhb)
        .batch_size(3)
        .build(&mut rng)
        .expect("failed to build QueueingHoneyBadger");
    let our_id = *node_info.netinfo.our_id();
    let (sq, mut step) = SenderQueue::builder(qhb, peer_ids).build(our_id);
    let output = step.extend_with(qhb_step, |fault| fault, Message::from);
    assert!(output.is_empty());
    (sq, step)
}

fn test_queueing_honey_badger_different_sizes<A, F>(
    new_adversary: F,
    num_txs: usize,
    seed: TestRngSeed,
) where
    A: Adversary<SQ>,
    F: Fn() -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng: TestRng = TestRng::from_seed(seed);

    let sizes = vec![2, 3, 5, rng.gen_range(6, 10)];
    for size in sizes {
        // The test is removing one correct node, so we allow fewer faulty ones.
        let num_adv_nodes = util::max_faulty(size - 1);
        let num_good_nodes = size - num_adv_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_adv_nodes
        );

        let (net, _) = NetBuilder::new(0..size as u16)
            .num_faulty(num_adv_nodes)
            .message_limit(20_000 * size)
            .no_time_limit()
            .adversary(new_adversary())
            .using_step(move |node_info: NewNodeInfo<_>| {
                // Note: The "seed" variable is implicitly copied by the move closure.
                // The "Copy" trait is *not* implemented for TestRng, which additionally
                // needs to be mutable, while we are in a function which captures immutably.
                // To avoid convoluted clone/borrow constructs we pass a TestRngSeed
                // rather than a TestRng instance.
                new_queueing_hb(node_info, seed)
            })
            .build(&mut rng)
            .expect("Could not construct test network.");

        test_queueing_honey_badger(net, num_txs, &mut rng);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1, .. ProptestConfig::default()
    })]

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_queueing_honey_badger_random_delivery_silent(seed in gen_seed()) {
        do_test_queueing_honey_badger_random_delivery_silent(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_queueing_honey_badger_first_delivery_silent(seed in gen_seed()) {
        do_test_queueing_honey_badger_first_delivery_silent(seed)
    }
}

fn do_test_queueing_honey_badger_random_delivery_silent(seed: TestRngSeed) {
    test_queueing_honey_badger_different_sizes(ReorderingAdversary::new, 30, seed);
}

fn do_test_queueing_honey_badger_first_delivery_silent(seed: TestRngSeed) {
    test_queueing_honey_badger_different_sizes(NodeOrderAdversary::new, 30, seed);
}
