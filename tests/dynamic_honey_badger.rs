//! Network tests for Dynamic Honey Badger.

extern crate hbbft;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pairing;
extern crate rand;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate rand_derive;

mod network;

use std::cmp;
use std::collections::BTreeMap;
use std::iter::once;
use std::sync::Arc;

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
            .any(|batch| batch.change == ChangeState::Complete(Change::Remove(NodeUid(0))))
    }

    fn has_add(node: &TestNode<UsizeDhb>) -> bool {
        node.outputs().iter().any(|batch| match batch.change {
            ChangeState::Complete(Change::Add(ref id, _)) => *id == NodeUid(0),
            _ => false,
        })
    }

    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &mut TestNode<UsizeDhb>| {
        if !has_remove(node) || !has_add(node) {
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
            node.queue.retain(|(_, ref msg)| msg.epoch() < last);
        }
        false
    };

    let mut input_add = false;
    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values_mut().any(node_busy) {
        let id = network.step();
        if !network.nodes[&id].instance().has_input() {
            queues
                .get_mut(&id)
                .unwrap()
                .remove_all(network.nodes[&id].outputs().iter().flat_map(Batch::iter));
            network.input(id, Input::User(queues[&id].choose(3, 10)));
        }
        if !input_add && network.nodes.values().all(has_remove) {
            let pk = network.pk_set.public_key_share(0);
            network.input_all(Input::Change(Change::Add(NodeUid(0), pk)));
            info!("Input!");
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
    DynamicHoneyBadger::builder((*netinfo).clone()).build()
}

fn test_dynamic_honey_badger_different_sizes<A, F>(new_adversary: F, num_txs: usize)
where
    A: Adversary<UsizeDhb>,
    F: Fn(usize, usize, BTreeMap<NodeUid, Arc<NetworkInfo<NodeUid>>>) -> A,
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
