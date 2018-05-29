//! Network tests for Honey Badger.

extern crate hbbft;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rand;

mod network;

use std::iter::once;
use std::rc::Rc;

use rand::Rng;

use hbbft::honey_badger::{self, HoneyBadger};
use hbbft::messaging::NetworkInfo;

use network::{Adversary, MessageScheduler, NodeUid, SilentAdversary, TestNetwork, TestNode};

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_honey_badger<A>(mut network: TestNetwork<A, HoneyBadger<usize, NodeUid>>, num_txs: usize)
where
    A: Adversary<HoneyBadger<usize, NodeUid>>,
{
    for tx in 0..num_txs {
        network.input_all(tx);
    }

    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &mut TestNode<HoneyBadger<usize, NodeUid>>| {
        let mut min_missing = 0;
        for batch in node.outputs() {
            for tx in &batch.transactions {
                if *tx >= min_missing {
                    min_missing = tx + 1;
                }
            }
        }
        if min_missing < num_txs {
            return true;
        }
        if node.outputs().last().unwrap().transactions.is_empty() {
            let last = node.outputs().last().unwrap().epoch;
            node.queue.retain(|(_, ref msg)| match msg {
                honey_badger::Message::CommonSubset(e, _) => *e < last,
            });
        }
        false
    };

    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values_mut().any(node_busy) {
        network.step();
    }
    // TODO: Verify that all nodes output the same epochs.
}

fn new_honey_badger(netinfo: Rc<NetworkInfo<NodeUid>>) -> HoneyBadger<usize, NodeUid> {
    let our_uid = netinfo.our_uid().clone();
    let all_uids = netinfo.all_uids().clone();
    HoneyBadger::new(our_uid, all_uids, 12, 0..5).expect("Instantiate honey_badger")
}

fn test_honey_badger_different_sizes<A, F>(new_adversary: F, num_txs: usize)
where
    A: Adversary<HoneyBadger<usize, NodeUid>>,
    F: Fn(usize, usize) -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();
    let sizes = (4..5)
        .chain(once(rng.gen_range(6, 10)))
        .chain(once(rng.gen_range(11, 15)));
    for size in sizes {
        let num_faulty_nodes = (size - 1) / 3;
        let num_good_nodes = size - num_faulty_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_faulty_nodes
        );
        let adversary = new_adversary(num_good_nodes, num_faulty_nodes);
        let network = TestNetwork::new(
            num_good_nodes,
            num_faulty_nodes,
            adversary,
            new_honey_badger,
        );
        test_honey_badger(network, num_txs);
    }
}

#[test]
fn test_honey_badger_random_delivery_silent() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::Random);
    test_honey_badger_different_sizes(new_adversary, 10);
}

#[test]
fn test_honey_badger_first_delivery_silent() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::First);
    test_honey_badger_different_sizes(new_adversary, 10);
}
