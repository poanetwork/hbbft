#![deny(unused_must_use)]
//! Network tests for Dynamic Honey Badger.

mod network;

use std::collections::{BTreeMap, BTreeSet};
use std::iter;
use std::sync::Arc;

use itertools::Itertools;
use log::info;
use rand::{Isaac64Rng, Rng};

use hbbft::dynamic_honey_badger::{
    Batch, Change, ChangeState, DynamicHoneyBadger, Input, JoinPlan,
};
use hbbft::sender_queue::{Message, SenderQueue, Step};
use hbbft::transaction_queue::TransactionQueue;
use hbbft::{util, NetworkInfo};

use crate::network::{Adversary, MessageScheduler, NodeId, SilentAdversary, TestNetwork, TestNode};

type UsizeDhb = SenderQueue<DynamicHoneyBadger<Vec<usize>, NodeId>>;

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_dynamic_honey_badger<A>(mut network: TestNetwork<A, UsizeDhb>, num_txs: usize)
where
    A: Adversary<UsizeDhb>,
{
    let mut rng = rand::thread_rng().gen::<Isaac64Rng>();
    let new_queue = |id: &NodeId| (*id, (0..num_txs).collect::<Vec<usize>>());
    let mut queues: BTreeMap<_, _> = network.nodes.keys().map(new_queue).collect();
    for (id, queue) in &mut queues {
        network.input(*id, Input::User(queue.choose(&mut rng, 3, 10)));
    }

    let netinfo = network.observer.instance().algo().netinfo().clone();
    let pub_keys_add = netinfo.public_key_map().clone();
    let mut pub_keys_rm = pub_keys_add.clone();
    pub_keys_rm.remove(&NodeId(0));
    network.input_all(Input::Change(Change::NodeChange(pub_keys_rm.clone())));

    let has_remove = |node: &TestNode<UsizeDhb>| {
        node.outputs().iter().any(|batch| match batch.change() {
            ChangeState::Complete(Change::NodeChange(pub_keys)) => pub_keys == &pub_keys_rm,
            _ => false,
        })
    };

    let has_add = |node: &TestNode<UsizeDhb>| {
        node.outputs().iter().any(|batch| match batch.change() {
            ChangeState::Complete(Change::NodeChange(pub_keys)) => pub_keys == &pub_keys_add,
            _ => false,
        })
    };

    // Returns `true` if the node has not output all transactions yet.
    let node_busy = |node: &TestNode<UsizeDhb>| {
        if !has_remove(node) || !has_add(node) {
            return true;
        }
        node.outputs().iter().flat_map(Batch::iter).unique().count() < num_txs
    };

    let mut rng = rand::thread_rng();
    let mut awaiting_removal: BTreeSet<_> = network.nodes.iter().map(|(id, _)| *id).collect();
    let mut awaiting_addition: BTreeSet<_> = network.nodes.iter().map(|(id, _)| *id).collect();
    // Whether node 0 was rejoined as a validator.
    let mut rejoined_node0 = false;
    // The removed node 0 which is to be restarted as soon as all remaining validators agree to add
    // it back.
    let mut saved_node0 = None;

    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values().any(node_busy) {
        // If a node is expecting input, take it from the queue. Otherwise handle a message.
        let input_ids: Vec<_> = network
            .nodes
            .iter()
            .filter(|(_, node)| {
                node_busy(*node)
                    && !node.instance().algo().has_input()
                    && node.instance().algo().netinfo().is_validator()
                    // If there's only one node, it will immediately output on input. Make sure we
                    // first process all incoming messages before providing input again.
                    && (network.nodes.len() > 1 || node.queue.is_empty())
            }).map(|(id, _)| *id)
            .collect();
        if let Some(id) = rng.choose(&input_ids) {
            let queue = queues.get_mut(id).unwrap();
            queue.remove_multiple(network.nodes[id].outputs().iter().flat_map(Batch::iter));
            network.input(*id, Input::User(queue.choose(&mut rng, 3, 10)));
            info!("Input user transactions to {:?}", id);
        }
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
        if awaiting_addition.contains(&stepped_id) && has_add(&network.nodes[&stepped_id]) {
            awaiting_addition.remove(&stepped_id);
            info!(
                "{:?} has finished waiting for node addition; still waiting: {:?}",
                stepped_id, awaiting_addition
            );
            if awaiting_addition.is_empty() && !rejoined_node0 {
                if let Some(join_plan) =
                    network.nodes[&stepped_id]
                        .outputs()
                        .iter()
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
                    if let Some(node) = saved_node0.take() {
                        let step = restart_node_for_add(&mut network, node, join_plan);
                        network.dispatch_messages(NodeId(0), step.messages);
                        rejoined_node0 = true;
                    }
                }
            }
        }
    }
    let node1 = network.nodes.get(&NodeId(1)).expect("node 1 is missing");
    network.verify_batches(&node1);
}

/// Restarts a stopped and removed node with a given join plan and adds the node back on the test
/// network.
fn restart_node_for_add<A>(
    network: &mut TestNetwork<A, UsizeDhb>,
    mut node: TestNode<UsizeDhb>,
    join_plan: JoinPlan<NodeId>,
) -> Step<DynamicHoneyBadger<Vec<usize>, NodeId>>
where
    A: Adversary<UsizeDhb>,
{
    let our_id = node.id;
    info!("Restarting {:?} with {:?}", our_id, join_plan);
    let peer_ids: Vec<NodeId> = network
        .nodes
        .keys()
        .cloned()
        .filter(|id| *id != our_id)
        .collect();
    let secret_key = node.instance().algo().netinfo().secret_key().clone();
    let (dhb, dhb_step) = DynamicHoneyBadger::new_joining(
        our_id,
        secret_key,
        join_plan,
        rand::thread_rng().gen::<Isaac64Rng>(),
    ).expect("failed to reconstruct the node");
    let (sq, mut sq_step) = SenderQueue::builder(dhb, peer_ids.into_iter()).build(our_id);
    *node.instance_mut() = sq;
    sq_step.extend(dhb_step.map(|output| output, Message::from));
    network.nodes.insert(our_id, node);
    sq_step
}

// Allow passing `netinfo` by value. `TestNetwork` expects this function signature.
#[allow(clippy::needless_pass_by_value)]
fn new_dynamic_hb(
    netinfo: Arc<NetworkInfo<NodeId>>,
) -> (UsizeDhb, Step<DynamicHoneyBadger<Vec<usize>, NodeId>>) {
    let observer = NodeId(netinfo.num_nodes());
    let our_id = *netinfo.our_id();
    let peer_ids = netinfo
        .all_ids()
        .filter(|&&them| them != our_id)
        .cloned()
        .chain(iter::once(observer));
    SenderQueue::builder(
        DynamicHoneyBadger::builder().build((*netinfo).clone()),
        peer_ids,
    ).build(our_id)
}

fn test_dynamic_honey_badger_different_sizes<A, F>(new_adversary: F, num_txs: usize)
where
    A: Adversary<UsizeDhb>,
    F: Fn(usize, usize, BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>) -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();
    let sizes = vec![2, 3, 5, rng.gen_range(6, 10)];
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
            TestNetwork::new_with_step(num_good_nodes, num_adv_nodes, adversary, new_dynamic_hb);
        test_dynamic_honey_badger(network, num_txs);
    }
}

#[test]
fn test_dynamic_honey_badger_random_delivery_silent() {
    let new_adversary = |_: usize, _: usize, _| SilentAdversary::new(MessageScheduler::Random);
    test_dynamic_honey_badger_different_sizes(new_adversary, 10);
}

#[test]
fn test_dynamic_honey_badger_first_delivery_silent() {
    let new_adversary = |_: usize, _: usize, _| SilentAdversary::new(MessageScheduler::First);
    test_dynamic_honey_badger_different_sizes(new_adversary, 10);
}
