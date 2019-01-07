#![deny(unused_must_use)]
//! Network tests for Queueing Honey Badger.

mod network;

use std::collections::{BTreeMap, BTreeSet};
use std::iter;
use std::sync::Arc;

use log::info;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

use hbbft::dynamic_honey_badger::{DynamicHoneyBadger, JoinPlan};
use hbbft::queueing_honey_badger::{Change, ChangeState, Input, QueueingHoneyBadger};
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

    // The second half of the transactions will be input only after a node has been removed and
    // readded.
    for tx in 0..(num_txs / 2) {
        network.input_all(Input::User(tx));
    }

    let input_second_half = |network: &mut TestNetwork<_, _>, id: NodeId| {
        for tx in (num_txs / 2)..num_txs {
            network.input(id, Input::User(tx));
        }
    };

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

    // Returns `true` if the node has not output all changes or transactions yet.
    let node_busy = |node: &TestNode<QHB>| {
        !has_remove(node) || !has_add(node) || !node.instance().algo().queue().is_empty()
    };

    let mut awaiting_removal: BTreeSet<_> = network.nodes.iter().map(|(id, _)| *id).collect();
    let mut awaiting_addition: BTreeSet<_> = network
        .nodes
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| *id != NodeId(0))
        .collect();
    // The set of nodes awaiting the second half of user transactions.
    let mut awaiting_second_half: BTreeSet<_> = awaiting_removal.clone();
    // Whether node 0 was rejoined as a validator.
    let mut rejoined_node0 = false;
    // The removed node 0 which is to be restarted as soon as all remaining validators agree to add
    // it back.
    let mut saved_node0: Option<TestNode<QHB>> = None;

    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values().any(node_busy) || !has_add(&network.observer) {
        let stepped_id = network.step();
        if awaiting_removal.contains(&stepped_id) && has_remove(&network.nodes[&stepped_id]) {
            awaiting_removal.remove(&stepped_id);
            info!(
                "{:?} has finished waiting for node removal; still waiting: {:?}",
                stepped_id, awaiting_removal
            );
            if awaiting_removal.is_empty() {
                info!("Removing node 0 from the test network");
                saved_node0 = network.nodes.remove(&NodeId(0));
            }
            // Vote to add node 0 back.
            if stepped_id != NodeId(0) {
                network.input(
                    stepped_id,
                    Input::Change(Change::NodeChange(pub_keys_add.clone())),
                );
                info!(
                    "Input the vote to add node 0 into {:?} with netinfo {:?}",
                    stepped_id,
                    network.nodes[&stepped_id].instance().algo().netinfo()
                );
            }
        }
        if awaiting_removal.is_empty() && awaiting_addition.contains(&stepped_id) {
            // If the stepped node started voting to add node 0 back, take a note of that and rejoin
            // node 0.
            if let Some(join_plan) = network.nodes[&stepped_id]
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
                if awaiting_addition.is_empty() && !rejoined_node0 {
                    let node = saved_node0.take().expect("node 0 wasn't saved");
                    let step = restart_node_for_add(&mut network, node, join_plan);
                    network.dispatch_messages(NodeId(0), step.messages);
                    rejoined_node0 = true;
                }
            }
        }
        if rejoined_node0 && awaiting_second_half.contains(&stepped_id) {
            // Input the second half of user transactions into the stepped node.
            input_second_half(&mut network, stepped_id);
            awaiting_second_half.remove(&stepped_id);
        }
    }
    let node1 = network.nodes.get(&NodeId(1)).expect("node 1 is missing");
    network.verify_batches(&node1);
}

/// Restarts a stopped and removed node with a given join plan and adds the node back on the test
/// network.
fn restart_node_for_add<A>(
    network: &mut TestNetwork<A, QHB>,
    mut node: TestNode<QHB>,
    join_plan: JoinPlan<NodeId>,
) -> Step<QueueingHoneyBadger<usize, NodeId, Vec<usize>>>
where
    A: Adversary<QHB>,
{
    let our_id = node.id;
    info!("Restarting {:?} with {:?}", our_id, join_plan);
    let observer = network.observer.id;
    let peer_ids: Vec<NodeId> = network
        .nodes
        .keys()
        .cloned()
        .filter(|id| *id != our_id)
        .chain(iter::once(observer))
        .collect();
    let secret_key = node.instance().algo().netinfo().secret_key().clone();
    let mut rng = XorShiftRng::from_seed(rand::thread_rng().gen::<[u8; 16]>());
    let (qhb, qhb_step) =
        QueueingHoneyBadger::builder_joining(our_id, secret_key, join_plan, &mut rng)
            .and_then(|builder| builder.batch_size(3).build(&mut rng))
            .expect("failed to rebuild the node with a join plan");
    let (sq, mut sq_step) = SenderQueue::builder(qhb, peer_ids.into_iter()).build(our_id);
    *node.instance_mut() = sq;
    sq_step.extend(qhb_step.map(|output| output, |fault| fault, Message::from));
    network.nodes.insert(our_id, node);
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
    let mut rng = XorShiftRng::from_seed(rand::thread_rng().gen::<[u8; 16]>());
    let (qhb, qhb_step) = QueueingHoneyBadger::builder(dhb)
        .batch_size(3)
        .build(&mut rng)
        .expect("failed to build QueueingHoneyBadger");
    let (sq, mut step) = SenderQueue::builder(qhb, peer_ids).build(our_id);
    let output = step.extend_with(qhb_step, |fault| fault, Message::from);
    assert!(output.is_empty());
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
