//! Network tests for Dynamic Honey Badger.

extern crate hbbft;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pairing;
extern crate rand;
#[macro_use]
extern crate serde_derive;

mod network;

use std::collections::BTreeMap;
use std::iter::once;
use std::rc::Rc;

use rand::Rng;

use hbbft::dynamic_honey_badger::{Change, DynamicHoneyBadger, Input, Message};
use hbbft::messaging::NetworkInfo;

use network::{Adversary, MessageScheduler, NodeUid, SilentAdversary, TestNetwork, TestNode};

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_dynamic_honey_badger<A>(
    mut network: TestNetwork<A, DynamicHoneyBadger<usize, NodeUid>>,
    num_txs: usize,
) where
    A: Adversary<DynamicHoneyBadger<usize, NodeUid>>,
{
    // The second half of the transactions will be input only after a node has been removed.
    network.input_all(Input::Change(Change::Remove(NodeUid(0))));
    for tx in 0..(num_txs / 2) {
        network.input_all(Input::User(tx));
    }

    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &mut TestNode<DynamicHoneyBadger<usize, NodeUid>>| {
        if !node
            .outputs()
            .iter()
            .filter_map(|batch| batch.change())
            .any(|change| *change == Change::Remove(NodeUid(0)))
        {
            return true;
        }
        let mut min_missing = 0;
        for batch in node.outputs() {
            for tx in batch.iter() {
                if *tx >= min_missing {
                    min_missing = tx + 1;
                }
            }
        }
        if min_missing < num_txs {
            return true;
        }
        if node.outputs().last().unwrap().is_empty() {
            let last = node.outputs().last().unwrap().epoch;
            node.queue.retain(|(_, ref msg)| match msg {
                Message::HoneyBadger(_, hb_msg) => hb_msg.epoch() < last,
            });
        }
        false
    };

    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values_mut().any(node_busy) {
        let id = network.step();
        if network.nodes[&id]
            .outputs()
            .last()
            .and_then(|batch| batch.change())
            .map_or(false, |change| *change == Change::Remove(id))
        {
            network.nodes.remove(&id);
            for tx in (num_txs / 2)..num_txs {
                network.input_all(Input::User(tx));
            }
        }
    }
    // TODO: Verify that all nodes output the same epochs.
}

// Allow passing `netinfo` by value. `TestNetwork` expects this function signature.
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn new_dynamic_hb(netinfo: Rc<NetworkInfo<NodeUid>>) -> DynamicHoneyBadger<usize, NodeUid> {
    DynamicHoneyBadger::new((*netinfo).clone(), 12).expect("Instantiate dynamic_honey_badger")
}

fn test_dynamic_honey_badger_different_sizes<A, F>(new_adversary: F, num_txs: usize)
where
    A: Adversary<DynamicHoneyBadger<usize, NodeUid>>,
    F: Fn(usize, usize, BTreeMap<NodeUid, Rc<NetworkInfo<NodeUid>>>) -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();
    let sizes = (3..5).chain(once(rng.gen_range(6, 10)));
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
