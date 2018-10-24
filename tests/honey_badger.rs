#![deny(unused_must_use)]
//! Network tests for Honey Badger.

extern crate bincode;
extern crate hbbft;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rand;
#[macro_use]
extern crate rand_derive;
#[macro_use]
extern crate serde_derive;
extern crate threshold_crypto as crypto;

mod network;

use std::collections::BTreeMap;
use std::sync::Arc;

use itertools::Itertools;
use rand::Rng;

use hbbft::honey_badger::{self, Batch, HoneyBadger, MessageContent};
use hbbft::transaction_queue::TransactionQueue;
use hbbft::{threshold_decryption, NetworkInfo, Target, TargetedMessage};

use network::{
    Adversary, MessageScheduler, MessageWithSender, NodeId, RandomAdversary, SilentAdversary,
    TestNetwork, TestNode,
};

type UsizeHoneyBadger = HoneyBadger<Vec<usize>, NodeId>;

/// An adversary whose nodes only send messages with incorrect decryption shares.
pub struct FaultyShareAdversary {
    num_good: usize,
    num_adv: usize,
    adv_nodes: BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>,
    scheduler: MessageScheduler,
    share_triggers: BTreeMap<u64, bool>,
}

impl FaultyShareAdversary {
    /// Creates a new silent adversary with the given message scheduler.
    pub fn new(
        num_good: usize,
        num_adv: usize,
        adv_nodes: BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>,
        scheduler: MessageScheduler,
    ) -> FaultyShareAdversary {
        FaultyShareAdversary {
            num_good,
            num_adv,
            scheduler,
            share_triggers: BTreeMap::new(),
            adv_nodes,
        }
    }
}

impl Adversary<UsizeHoneyBadger> for FaultyShareAdversary {
    fn pick_node(&self, nodes: &BTreeMap<NodeId, TestNode<UsizeHoneyBadger>>) -> NodeId {
        self.scheduler.pick_node(nodes)
    }

    fn push_message(
        &mut self,
        sender_id: NodeId,
        msg: TargetedMessage<honey_badger::Message<NodeId>, NodeId>,
    ) {
        let NodeId(sender_id) = sender_id;
        if sender_id < self.num_good {
            if let TargetedMessage {
                target: Target::All,
                message,
            } = msg
            {
                let epoch = message.epoch();
                // Set the trigger to simulate decryption share messages.
                self.share_triggers.entry(epoch).or_insert(true);
            }
        }
    }

    fn step(&mut self) -> Vec<MessageWithSender<UsizeHoneyBadger>> {
        let mut outgoing = vec![];
        let fake_proposal = &Vec::from("X marks the spot");

        for (epoch, trigger_set) in &mut self.share_triggers {
            if *trigger_set {
                // Unset the trigger.
                *trigger_set = false;
                // Broadcast fake decryption shares from all adversarial nodes.
                for sender_id in self.num_good..self.num_adv {
                    let adv_node = &self.adv_nodes[&NodeId(sender_id)];
                    let fake_ciphertext = (*adv_node)
                        .public_key_set()
                        .public_key()
                        .encrypt(fake_proposal);
                    let share = adv_node
                        .secret_key_share()
                        .decrypt_share(&fake_ciphertext)
                        .expect("decryption share");
                    // Send the share to remote nodes.
                    for proposer_id in 0..self.num_good + self.num_adv {
                        outgoing.push(MessageWithSender::new(
                            NodeId(sender_id),
                            Target::All.message(
                                MessageContent::DecryptionShare {
                                    proposer_id: NodeId(proposer_id),
                                    share: threshold_decryption::Message(share.clone()),
                                }.with_epoch(*epoch),
                            ),
                        ))
                    }
                }
            }
        }
        outgoing
    }
}

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_honey_badger<A>(mut network: TestNetwork<A, UsizeHoneyBadger>, num_txs: usize)
where
    A: Adversary<UsizeHoneyBadger>,
{
    let new_queue = |id: &NodeId| (*id, (0..num_txs).collect::<Vec<usize>>());
    let mut queues: BTreeMap<_, _> = network.nodes.keys().map(new_queue).collect();

    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &mut TestNode<UsizeHoneyBadger>| {
        node.outputs().iter().flat_map(Batch::iter).unique().count() < num_txs
    };

    let mut rng = rand::thread_rng();

    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values_mut().any(node_busy) {
        // If a node is expecting input, take it from the queue. Otherwise handle a message.
        let input_ids: Vec<_> = network
            .nodes
            .iter()
            .filter(|(_, node)| !node.instance().has_input())
            .map(|(id, _)| *id)
            .collect();
        if let Some(id) = rng.choose(&input_ids) {
            let queue = queues.get_mut(id).unwrap();
            queue.remove_multiple(network.nodes[id].outputs().iter().flat_map(Batch::iter));
            network.input(*id, queue.choose(&mut rng, 3, 10));
        } else {
            network.step();
        }
    }
    verify_output_sequence(&network);
}

/// Verifies that all instances output the same sequence of batches.
fn verify_output_sequence<A>(network: &TestNetwork<A, UsizeHoneyBadger>)
where
    A: Adversary<UsizeHoneyBadger>,
{
    let mut expected: Option<BTreeMap<&_, &_>> = None;
    for node in network.nodes.values() {
        assert!(!node.outputs().is_empty());
        let outputs: BTreeMap<&u64, &BTreeMap<NodeId, Vec<usize>>> = node
            .outputs()
            .iter()
            .map(
                |Batch {
                     epoch,
                     contributions,
                 }| (epoch, contributions),
            ).collect();
        if expected.is_none() {
            expected = Some(outputs);
        } else if let Some(expected) = &expected {
            assert_eq!(expected, &outputs);
        }
    }
}

fn new_honey_badger(netinfo: Arc<NetworkInfo<NodeId>>) -> UsizeHoneyBadger {
    HoneyBadger::builder(netinfo).build()
}

fn test_honey_badger_different_sizes<A, F>(new_adversary: F, num_txs: usize)
where
    A: Adversary<UsizeHoneyBadger>,
    F: Fn(usize, usize, BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>) -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();
    let sizes = vec![1, 2, 3, 5, rng.gen_range(6, 10)];
    for size in sizes {
        let num_adv_nodes = (size - 1) / 3;
        let num_good_nodes = size - num_adv_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_adv_nodes
        );
        let adversary = |adv_nodes| new_adversary(num_good_nodes, num_adv_nodes, adv_nodes);
        let network = TestNetwork::new(num_good_nodes, num_adv_nodes, adversary, new_honey_badger);
        test_honey_badger(network, num_txs);
    }
}

#[test]
fn test_honey_badger_random_delivery_silent() {
    let new_adversary = |_: usize, _: usize, _| SilentAdversary::new(MessageScheduler::Random);
    test_honey_badger_different_sizes(new_adversary, 30);
}

#[test]
fn test_honey_badger_first_delivery_silent() {
    let new_adversary = |_: usize, _: usize, _| SilentAdversary::new(MessageScheduler::First);
    test_honey_badger_different_sizes(new_adversary, 30);
}

#[test]
fn test_honey_badger_faulty_share() {
    let new_adversary = |num_good: usize, num_adv: usize, adv_nodes| {
        FaultyShareAdversary::new(num_good, num_adv, adv_nodes, MessageScheduler::Random)
    };
    test_honey_badger_different_sizes(new_adversary, 8);
}

#[test]
fn test_honey_badger_random_adversary() {
    let new_adversary = |_, _, _| {
        // A 10% injection chance is roughly ~13k extra messages added.
        RandomAdversary::new(0.1, 0.1, || TargetedMessage {
            target: Target::All,
            message: rand::random(),
        })
    };
    test_honey_badger_different_sizes(new_adversary, 8);
}
