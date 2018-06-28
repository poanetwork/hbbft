//! Network tests for Honey Badger.

extern crate bincode;
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

use hbbft::honey_badger::{self, Batch, HoneyBadger, MessageContent};
use hbbft::messaging::{NetworkInfo, Target, TargetedMessage};

use network::{
    Adversary, MessageScheduler, MessageWithSender, NodeUid, SilentAdversary, TestNetwork, TestNode,
};

/// An adversary whose nodes only send messages with incorrect decryption shares.
pub struct FaultyShareAdversary {
    num_good: usize,
    num_adv: usize,
    adv_nodes: BTreeMap<NodeUid, Rc<NetworkInfo<NodeUid>>>,
    scheduler: MessageScheduler,
    share_triggers: BTreeMap<u64, bool>,
}

impl FaultyShareAdversary {
    /// Creates a new silent adversary with the given message scheduler.
    pub fn new(
        num_good: usize,
        num_adv: usize,
        adv_nodes: BTreeMap<NodeUid, Rc<NetworkInfo<NodeUid>>>,
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

impl Adversary<HoneyBadger<usize, NodeUid>> for FaultyShareAdversary {
    fn pick_node(
        &self,
        nodes: &BTreeMap<NodeUid, TestNode<HoneyBadger<usize, NodeUid>>>,
    ) -> NodeUid {
        self.scheduler.pick_node(nodes)
    }

    fn push_message(
        &mut self,
        sender_id: NodeUid,
        msg: TargetedMessage<honey_badger::Message<NodeUid>, NodeUid>,
    ) {
        let NodeUid(sender_id) = sender_id;
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

    fn step(&mut self) -> Vec<MessageWithSender<HoneyBadger<usize, NodeUid>>> {
        let mut outgoing = vec![];
        let fake_proposal = &Vec::from("X marks the spot");

        for (epoch, trigger_set) in &mut self.share_triggers {
            if *trigger_set {
                // Unset the trigger.
                *trigger_set = false;
                // Broadcast fake decryption shares from all adversarial nodes.
                for sender_id in self.num_good..self.num_adv {
                    let adv_node = &self.adv_nodes[&NodeUid(sender_id)];
                    let fake_ciphertext = (*adv_node)
                        .public_key_set()
                        .public_key()
                        .encrypt(fake_proposal);
                    let share = adv_node
                        .secret_key()
                        .decrypt_share(&fake_ciphertext)
                        .expect("decryption share");
                    // Send the share to remote nodes.
                    for proposer_id in 0..self.num_good + self.num_adv {
                        outgoing.push((
                            NodeUid(sender_id),
                            Target::All.message(
                                MessageContent::DecryptionShare {
                                    proposer_id: NodeUid(proposer_id),
                                    share: share.clone(),
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

    // Handle messages in random order until all nodes have output all transactions.
    while network.nodes.values_mut().any(node_busy) {
        network.step();
    }
    verify_output_sequence(&network);
}

/// Verifies that all instances output the same sequence of batches.
fn verify_output_sequence<A>(network: &TestNetwork<A, HoneyBadger<usize, NodeUid>>)
where
    A: Adversary<HoneyBadger<usize, NodeUid>>,
{
    let mut expected: Option<BTreeMap<&_, &_>> = None;
    for node in network.nodes.values() {
        assert!(!node.outputs().is_empty());
        let outputs: BTreeMap<&u64, &BTreeMap<NodeUid, Vec<usize>>> = node
            .outputs()
            .iter()
            .map(
                |Batch {
                     epoch,
                     transactions,
                 }| (epoch, transactions),
            )
            .collect();
        if expected.is_none() {
            expected = Some(outputs);
        } else if let Some(expected) = &expected {
            assert_eq!(expected, &outputs);
        }
    }
}

fn new_honey_badger(netinfo: Rc<NetworkInfo<NodeUid>>) -> HoneyBadger<usize, NodeUid> {
    HoneyBadger::new(netinfo, 12, 0, 0..5).expect("Instantiate honey_badger")
}

fn test_honey_badger_different_sizes<A, F>(new_adversary: F, num_txs: usize)
where
    A: Adversary<HoneyBadger<usize, NodeUid>>,
    F: Fn(usize, usize, BTreeMap<NodeUid, Rc<NetworkInfo<NodeUid>>>) -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();
    let sizes = (4..5)
        .chain(once(rng.gen_range(6, 10)))
        .chain(once(rng.gen_range(11, 15)));
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
    test_honey_badger_different_sizes(new_adversary, 10);
}

#[test]
fn test_honey_badger_first_delivery_silent() {
    let new_adversary = |_: usize, _: usize, _| SilentAdversary::new(MessageScheduler::First);
    test_honey_badger_different_sizes(new_adversary, 10);
}

#[test]
fn test_honey_badger_faulty_share() {
    let new_adversary = |num_good: usize, num_adv: usize, adv_nodes| {
        FaultyShareAdversary::new(num_good, num_adv, adv_nodes, MessageScheduler::Random)
    };
    test_honey_badger_different_sizes(new_adversary, 8);
}
