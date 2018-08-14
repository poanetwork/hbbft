#![deny(unused_must_use)]
//! Network tests for Dynamic Honey Badger.

extern crate hbbft;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pairing;
extern crate rand;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate rand_derive;
extern crate threshold_crypto as crypto;

mod network;

use std::cmp;
use std::collections::BTreeMap;
use std::sync::Arc;

use itertools::Itertools;
use rand::Rng;

use hbbft::dynamic_honey_badger::{Batch, Change, ChangeState, DynamicHoneyBadger, Input};
use hbbft::messaging::NetworkInfo;
use hbbft::transaction_queue::TransactionQueue;

use network::{Adversary, MessageScheduler, NodeUid, SilentAdversary, TestNetwork, TestNode};

type UsizeDhb = DynamicHoneyBadger<Vec<usize>, NodeUid>;

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_dynamic_honey_badger<A>(mut network: TestNetwork<A, UsizeDhb>, num_txs: usize)
where
    A: Adversary<UsizeDhb>,
{
    let new_queue = |id: &NodeUid| (*id, TransactionQueue((0..num_txs).collect()));
    let mut queues: BTreeMap<_, _> = network.nodes.keys().map(new_queue).collect();
    for (id, queue) in &queues {
        network.input(*id, Input::User(queue.choose(3, 10)));
    }

    network.input_all(Input::Change(Change::Remove(NodeUid(0))));

    fn has_remove(node: &TestNode<UsizeDhb>) -> bool {
        node.outputs()
            .iter()
            .any(|batch| *batch.change() == ChangeState::Complete(Change::Remove(NodeUid(0))))
    }

    fn has_add(node: &TestNode<UsizeDhb>) -> bool {
        node.outputs().iter().any(|batch| match *batch.change() {
            ChangeState::Complete(Change::Add(ref id, _)) => *id == NodeUid(0),
            _ => false,
        })
    }

    // Returns `true` if the node has not output all transactions yet.
    let node_busy = |node: &TestNode<UsizeDhb>| {
        if !has_remove(node) || !has_add(node) {
            return true;
        }
        node.outputs().iter().flat_map(Batch::iter).unique().count() < num_txs
    };

    let mut rng = rand::thread_rng();
    let mut input_add = false; // Whether the vote to add node 0 has already been input.

    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values().any(node_busy) {
        // If a node is expecting input, take it from the queue. Otherwise handle a message.
        let input_ids: Vec<_> = network
            .nodes
            .iter()
            .filter(|(_, node)| {
                node_busy(*node)
                    && !node.instance().has_input()
                    && node.instance().netinfo().is_validator()
                    // Wait until all nodes have completed removing 0, before inputting `Add`.
                    && (input_add || !has_remove(node))
                    // If there's only one node, it will immediately output on input. Make sure we
                    // first process all incoming messages before providing input again.
                    && (network.nodes.len() > 2 || node.queue.is_empty())
            })
            .map(|(id, _)| *id)
            .collect();
        if let Some(id) = rng.choose(&input_ids) {
            let queue = queues.get_mut(id).unwrap();
            queue.remove_all(network.nodes[id].outputs().iter().flat_map(Batch::iter));
            network.input(*id, Input::User(queue.choose(3, 10)));
        }
        network.step();
        // Once all nodes have processed the removal of node 0, add it again.
        if !input_add && network.nodes.values().all(has_remove) {
            let pk = network.nodes[&NodeUid(0)]
                .instance()
                .netinfo()
                .secret_key()
                .public_key();
            network.input_all(Input::Change(Change::Add(NodeUid(0), pk)));
            input_add = true;
        }
    }
    verify_output_sequence(&network);
}

/// Verifies that all instances output the same sequence of batches. We already know that all of
/// them have output all transactions and events, but some may have advanced a few empty batches
/// more than others, so we ignore those.
fn verify_output_sequence<A>(network: &TestNetwork<A, UsizeDhb>)
where
    A: Adversary<UsizeDhb>,
{
    let expected = network.nodes[&NodeUid(0)].outputs().to_vec();
    assert!(!expected.is_empty());
    for node in network.nodes.values() {
        let len = cmp::min(expected.len(), node.outputs().len());
        assert_eq!(&expected[..len], &node.outputs()[..len]);
    }
}

// Allow passing `netinfo` by value. `TestNetwork` expects this function signature.
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn new_dynamic_hb(netinfo: Arc<NetworkInfo<NodeUid>>) -> UsizeDhb {
    DynamicHoneyBadger::builder().build((*netinfo).clone())
}

fn test_dynamic_honey_badger_different_sizes<A, F>(new_adversary: F, num_txs: usize)
where
    A: Adversary<UsizeDhb>,
    F: Fn(usize, usize, BTreeMap<NodeUid, Arc<NetworkInfo<NodeUid>>>) -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();
    let sizes = vec![2, 3, 5, rng.gen_range(6, 10)];
    for size in sizes {
        // The test is removing one correct node, so we allow fewer faulty ones.
        let num_adv_nodes = (size - 2) / 3;
        let num_good_nodes = size - num_adv_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_adv_nodes
        );
        let adversary = |adv_nodes| new_adversary(num_good_nodes, num_adv_nodes, adv_nodes);
        let network = TestNetwork::new(num_good_nodes, num_adv_nodes, adversary, new_dynamic_hb);
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
