#![deny(unused_must_use)]
//! Network tests for Queueing Honey Badger.

mod network;

use std::collections::BTreeMap;
use std::iter;
use std::sync::Arc;

use itertools::Itertools;
use log::info;
use rand::{Isaac64Rng, Rng};

use hbbft::dynamic_honey_badger::{DynamicHoneyBadger, JoinPlan};
use hbbft::queueing_honey_badger::{Batch, Change, ChangeState, Input, QueueingHoneyBadger};
use hbbft::sender_queue::{Message, SenderQueue, Step};
use hbbft::{util, NetworkInfo};

use crate::network::{Adversary, MessageScheduler, NodeId, SilentAdversary, TestNetwork, TestNode};

type QHB = SenderQueue<QueueingHoneyBadger<usize, NodeId, Vec<usize>>>;

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_queueing_honey_badger<A>(mut network: TestNetwork<A, QHB>, num_txs: usize)
where
    A: Adversary<QHB>,
{
    let netinfo = network.observer.instance().algo().netinfo().clone();
    let pub_keys_add = netinfo.public_key_map().clone();
    let mut pub_keys_rm = pub_keys_add.clone();
    pub_keys_rm.remove(&NodeId(0));
    network.input_all(Input::Change(Change::NodeChange(pub_keys_rm.clone())));

    // The second half of the transactions will be input only after a node has been removed.
    for tx in 0..(num_txs / 2) {
        network.input_all(Input::User(tx));
    }

    let has_remove = |node: &TestNode<QHB>| {
        node.outputs().iter().any(|batch| match batch.change() {
            ChangeState::Complete(Change::NodeChange(pub_keys)) => pub_keys == &pub_keys_rm,
            _ => false,
        })
    };

    let has_add = |node: &TestNode<QHB>| {
        node.outputs().iter().any(|batch| match batch.change() {
            ChangeState::Complete(Change::NodeChange(pub_keys)) => pub_keys == &pub_keys_add,
            _ => false,
        })
    };

    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &mut TestNode<QHB>| {
        if !has_remove(node) || !has_add(node) {
            return true;
        }
        node.id != NodeId(0)
            && node.outputs().iter().flat_map(Batch::iter).unique().count() < num_txs
    };

    let mut input_add = false;
    let mut rejoined_node0 = false; // Whether node 0 was rejoined as a validator.

    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values_mut().any(node_busy) {
        network.step();
        if !input_add {
            if network.nodes.values().all(has_remove) {
                for tx in (num_txs / 2)..num_txs {
                    network.input_all(Input::User(tx));
                }
                network.input_all(Input::Change(Change::NodeChange(pub_keys_add.clone())));
                input_add = true;
            }
        } else if !rejoined_node0 {
            if let Some(join_plan) = network
                .nodes
                .values()
                .flat_map(|node| node.outputs())
                .find_map(|batch| match batch.change() {
                    ChangeState::InProgress(Change::NodeChange(pub_keys))
                        if pub_keys == &pub_keys_add =>
                    {
                        Some(
                            batch
                                .join_plan()
                                .expect("failed to get the join plan of the batch"),
                        )
                    }
                    _ => None,
                }) {
                let step = restart_node_0_for_add(&mut network, join_plan);
                network.dispatch_messages(NodeId(0), step.messages);
                rejoined_node0 = true;
            }
        }
    }
    network.verify_batches();
}

/// Restarts node 0 on the test network for adding it back as a validator.
fn restart_node_0_for_add<A>(
    network: &mut TestNetwork<A, QHB>,
    join_plan: JoinPlan<NodeId>,
) -> Step<QueueingHoneyBadger<usize, NodeId, Vec<usize>>>
where
    A: Adversary<QHB>,
{
    info!("Restarting node 0 with {:?}", join_plan);
    let our_id = NodeId(0);
    let peer_ids: Vec<NodeId> = network
        .nodes
        .keys()
        .cloned()
        .filter(|id| *id != NodeId(0))
        .collect();
    let node0 = network
        .nodes
        .get_mut(&our_id)
        .expect("failed to get node 0");
    let secret_key = node0.instance().algo().netinfo().secret_key().clone();
    let queue = node0.instance().algo().queue().clone();
    let (qhb, qhb_step) = QueueingHoneyBadger::builder_joining(
        NodeId(0),
        secret_key,
        join_plan,
        rand::thread_rng().gen::<Isaac64Rng>(),
    ).expect("failed to rebuild node 0 with a join plan")
    .batch_size(3)
    .build_with_transactions(queue, rand::thread_rng().gen::<Isaac64Rng>())
    .expect("failed to rebuild node 0 with transactions");
    let (sq, mut sq_step) = SenderQueue::builder(qhb, peer_ids.into_iter()).build(our_id);
    *node0.instance_mut() = sq;
    sq_step.extend(qhb_step.map(|output| output, Message::from));
    sq_step
}

// Allow passing `netinfo` by value. `TestNetwork` expects this function signature.
#[allow(clippy::needless_pass_by_value)]
fn new_queueing_hb(
    netinfo: Arc<NetworkInfo<NodeId>>,
) -> (QHB, Step<QueueingHoneyBadger<usize, NodeId, Vec<usize>>>) {
    let observer = NodeId(netinfo.num_nodes());
    let our_id = *netinfo.our_id();
    let peer_ids = netinfo
        .all_ids()
        .filter(|&&them| them != our_id)
        .cloned()
        .chain(iter::once(observer));
    let dhb = DynamicHoneyBadger::builder().build((*netinfo).clone());
    let mut rng = rand::thread_rng().gen::<Isaac64Rng>();
    let (qhb, qhb_step) = QueueingHoneyBadger::builder(dhb)
        .batch_size(3)
        .build(&mut rng);
    let (sq, mut step) = SenderQueue::builder(qhb, peer_ids).build(our_id);
    step.extend_with(qhb_step, Message::from);
    (sq, step)
}

fn test_queueing_honey_badger_different_sizes<A, F>(new_adversary: F, num_txs: usize)
where
    A: Adversary<QHB>,
    F: Fn(usize, usize, BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>) -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();
    let sizes = vec![3, 5, rng.gen_range(6, 10)];
    for size in sizes {
        // The test is removing one correct node, so we allow fewer faulty ones.
        let num_adv_nodes = util::max_faulty(size - 1);
        let num_good_nodes = size - num_adv_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_adv_nodes
        );
        let adversary = |adv_nodes| new_adversary(num_good_nodes, num_adv_nodes, adv_nodes);
        let network =
            TestNetwork::new_with_step(num_good_nodes, num_adv_nodes, adversary, new_queueing_hb);
        test_queueing_honey_badger(network, num_txs);
    }
}

#[test]
fn test_queueing_honey_badger_random_delivery_silent() {
    let new_adversary = |_: usize, _: usize, _| SilentAdversary::new(MessageScheduler::Random);
    test_queueing_honey_badger_different_sizes(new_adversary, 30);
}

#[test]
fn test_queueing_honey_badger_first_delivery_silent() {
    let new_adversary = |_: usize, _: usize, _| SilentAdversary::new(MessageScheduler::First);
    test_queueing_honey_badger_different_sizes(new_adversary, 30);
}
