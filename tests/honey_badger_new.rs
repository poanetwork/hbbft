#![deny(unused_must_use)]
//! Network tests for Honey Badger.

pub mod net;

use std::collections::BTreeMap;
use std::sync::Arc;

use itertools::Itertools;
use log::info;
use rand::{seq::SliceRandom, Rng};

use hbbft::honey_badger::{Batch, EncryptionSchedule, HoneyBadger};
use hbbft::sender_queue::{SenderQueue, Step};
use hbbft::transaction_queue::TransactionQueue;
use hbbft::{util, NetworkInfo};

use crate::net::adversary::{Adversary, NodeOrderAdversary, RandomAdversary, ReorderingAdversary};
use crate::net::{NetBuilder, NewNodeInfo, Node, VirtualNet};

type NodeId = u16;
type UsizeHoneyBadger = SenderQueue<HoneyBadger<Vec<usize>, NodeId>>;

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_honey_badger<A>(mut net: VirtualNet<UsizeHoneyBadger, A>, num_txs: usize)
where
    A: Adversary<UsizeHoneyBadger>,
{
    let mut queues: BTreeMap<_, _> = net
        .correct_nodes()
        .map(|node| (*node.id(), (0..num_txs).collect::<Vec<usize>>()))
        .collect();

    let mut rng = rand::thread_rng();

    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &Node<UsizeHoneyBadger>| {
        node.outputs().iter().flat_map(Batch::iter).unique().count() < num_txs
    };

    // Handle messages in random order until all nodes have output all transactions.
    while net.correct_nodes().any(node_busy) {
        // If a node is expecting input, take it from the queue. Otherwise handle a message.
        let input_ids: Vec<_> = net
            .correct_nodes()
            .filter(|node| !node.algorithm().algo().has_input())
            .map(|node| *node.id())
            .collect();

        if let Some(id) = input_ids[..].choose(&mut rng) {
            let queue = queues.get_mut(id).unwrap();
            queue.remove_multiple(net.get(*id).unwrap().outputs().iter().flat_map(Batch::iter));
            let _ = net.send_input(*id, queue.choose(&mut rng, 3, 10), &mut rng);
        } else {
            let _ = net.crank_expect(&mut rng);
        }
    }
    verify_output_sequence(&net);
}

/// Verifies that all instances output the same sequence of batches.
fn verify_output_sequence<A>(network: &VirtualNet<UsizeHoneyBadger, A>)
    where
        A: Adversary<UsizeHoneyBadger>,
{
    let mut expected: Option<BTreeMap<u64, &_>> = None;
    for node in network.correct_nodes() {
        assert!(!node.outputs().is_empty());
        let outputs: BTreeMap<u64, &BTreeMap<NodeId, Vec<usize>>> = node
            .outputs()
            .iter()
            .map(|batch| (batch.epoch, &batch.contributions))
            .collect();
        if expected.is_none() {
            expected = Some(outputs);
        } else if let Some(expected) = &expected {
            assert_eq!(expected, &outputs);
        }
    }
}

fn new_honey_badger(
    netinfo: Arc<NetworkInfo<NodeId>>,
) -> (UsizeHoneyBadger, Step<HoneyBadger<Vec<usize>, NodeId>>) {
    let our_id = *netinfo.our_id();
    let nc = netinfo.clone();
    let peer_ids = nc.all_ids().filter(|&&them| them != our_id).cloned();
    let hb = HoneyBadger::builder(netinfo)
        .encryption_schedule(EncryptionSchedule::EveryNthEpoch(2))
        .build();
    SenderQueue::builder(hb, peer_ids).build(our_id)
}

fn test_honey_badger_different_sizes<A, F>(new_adversary: F, num_txs: usize)
where
    A: Adversary<UsizeHoneyBadger>,
    F: Fn() -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();
    let sizes = vec![1, 2, 3, 5, rng.gen_range(6, 10)];
    for size in sizes {
        let num_adv_nodes = util::max_faulty(size);
        let num_good_nodes = size - num_adv_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_adv_nodes
        );

        let adversary = || new_adversary();

        let (net, _) = NetBuilder::new(0..size as u16)
            .num_faulty(num_adv_nodes as usize)
            .message_limit(10_000 * size as usize)
            .no_time_limit()
            .adversary(adversary())
            .using_step(move |node_info: NewNodeInfo<_>| {
                new_honey_badger(Arc::new(node_info.netinfo))
            })
            .build(&mut rng)
            .expect("Could not construct test network.");

        test_honey_badger(net, num_txs);
    }
}

#[test]
fn test_honey_badger_random_delivery_silent_new() {
    let new_adversary = || ReorderingAdversary::new();
    test_honey_badger_different_sizes(new_adversary, 30);
}

#[test]
fn test_honey_badger_first_delivery_silent_new() {
    let new_adversary = || NodeOrderAdversary::new();
    test_honey_badger_different_sizes(new_adversary, 30);
}

#[test]
fn test_honey_badger_random_adversary_new() {
    let new_adversary = || {
        // A 10% injection chance is roughly ~13k extra messages added.
        RandomAdversary::new(0.1, 0.1)
    };
    test_honey_badger_different_sizes(new_adversary, 8);
}
