#![deny(unused_must_use)]
//! Network tests for Queueing Honey Badger.

extern crate env_logger;
extern crate hbbft;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate rand;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate rand_derive;
extern crate threshold_crypto as crypto;

mod network;

use std::collections::BTreeMap;
use std::sync::Arc;

use itertools::Itertools;
use rand::{Isaac64Rng, Rng};

use hbbft::dynamic_honey_badger::DynamicHoneyBadger;
use hbbft::queueing_honey_badger::{Batch, Change, ChangeState, Input, QueueingHoneyBadger, Step};
use hbbft::NetworkInfo;

use network::{Adversary, MessageScheduler, NodeId, SilentAdversary, TestNetwork, TestNode};

type QHB = QueueingHoneyBadger<usize, NodeId, Vec<usize>>;

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_queueing_honey_badger<A>(mut network: TestNetwork<A, QHB>, num_txs: usize)
where
    A: Adversary<QHB>,
{
    // The second half of the transactions will be input only after a node has been removed.
    network.input_all(Input::Change(Change::Remove(NodeId(0))));
    for tx in 0..(num_txs / 2) {
        network.input_all(Input::User(tx));
    }

    fn has_remove(node: &TestNode<QHB>) -> bool {
        node.outputs()
            .iter()
            .any(|batch| *batch.change() == ChangeState::Complete(Change::Remove(NodeId(0))))
    }

    fn has_add(node: &TestNode<QHB>) -> bool {
        node.outputs().iter().any(|batch| match *batch.change() {
            ChangeState::Complete(Change::Add(ref id, _)) => *id == NodeId(0),
            _ => false,
        })
    }

    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &mut TestNode<QHB>| {
        if !has_remove(node) || !has_add(node) {
            return true;
        }
        if node.outputs().iter().flat_map(Batch::iter).unique().count() < num_txs {
            return true;
        }
        false
    };

    let mut input_add = false;
    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values_mut().any(node_busy) {
        network.step();
        if !input_add && network.nodes.values().all(has_remove) {
            for tx in (num_txs / 2)..num_txs {
                network.input_all(Input::User(tx));
            }
            let pk = network.nodes[&NodeId(0)]
                .instance()
                .dyn_hb()
                .netinfo()
                .secret_key()
                .public_key();
            network.input_all(Input::Change(Change::Add(NodeId(0), pk)));
            input_add = true;
        }
    }
    network.verify_batches();
}

// Allow passing `netinfo` by value. `TestNetwork` expects this function signature.
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn new_queueing_hb(netinfo: Arc<NetworkInfo<NodeId>>) -> (QHB, Step<usize, NodeId, Vec<usize>>) {
    let dyn_hb = DynamicHoneyBadger::builder().build((*netinfo).clone());
    let rng = rand::thread_rng().gen::<Isaac64Rng>();
    QueueingHoneyBadger::builder(dyn_hb)
        .batch_size(3)
        .build(rng)
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
        let num_adv_nodes = (size - 2) / 3;
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
