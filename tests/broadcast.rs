#![deny(unused_must_use)]
//! Integration test of the reliable broadcast protocol.

extern crate env_logger;
extern crate hbbft;
extern crate log;
extern crate rand;
extern crate rand_derive;
extern crate serde_derive;
extern crate threshold_crypto as crypto;

mod network;

use std::collections::BTreeMap;
use std::iter::once;
use std::sync::Arc;

use log::info;
use rand::Rng;

use hbbft::broadcast::{Broadcast, Message};
use hbbft::{util, DistAlgorithm, NetworkInfo, Target, TargetedMessage};
use network::{
    Adversary, MessageScheduler, MessageWithSender, NodeId, RandomAdversary, SilentAdversary,
    TestNetwork, TestNode,
};

/// An adversary that inputs an alternate value.
struct ProposeAdversary {
    scheduler: MessageScheduler,
    adv_nodes: BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>,
    has_sent: bool,
}

impl ProposeAdversary {
    /// Creates a new replay adversary with the given message scheduler.
    fn new(
        scheduler: MessageScheduler,
        adv_nodes: BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>,
    ) -> ProposeAdversary {
        ProposeAdversary {
            scheduler,
            adv_nodes,
            has_sent: false,
        }
    }
}

impl Adversary<Broadcast<NodeId>> for ProposeAdversary {
    fn pick_node(&self, nodes: &BTreeMap<NodeId, TestNode<Broadcast<NodeId>>>) -> NodeId {
        self.scheduler.pick_node(nodes)
    }

    fn push_message(&mut self, _: NodeId, _: TargetedMessage<Message, NodeId>) {
        // All messages are ignored.
    }

    fn step(&mut self) -> Vec<MessageWithSender<Broadcast<NodeId>>> {
        if self.has_sent {
            return vec![];
        }
        self.has_sent = true;
        self.adv_nodes
            .iter()
            .flat_map(|(&id, netinfo)| {
                Broadcast::new(netinfo.clone(), id)
                    .expect("broadcast instance")
                    .handle_input(b"Fake news".to_vec())
                    .expect("propose")
                    .messages
                    .into_iter()
                    .map(move |msg| MessageWithSender::new(id, msg))
            }).collect()
    }
}

/// Broadcasts a value from node 0 and expects all good nodes to receive it.
fn test_broadcast<A: Adversary<Broadcast<NodeId>>>(
    mut network: TestNetwork<A, Broadcast<NodeId>>,
    proposed_value: &[u8],
) {
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    // Make node 0 propose the value.
    network.input(NodeId(0), proposed_value.to_vec());

    // Handle messages in random order until all nodes have output the proposed value.
    while !network.nodes.values().all(TestNode::terminated) {
        network.step();
    }
    // Verify that all instances output the proposed value.
    for node in network.nodes.values() {
        assert!(once(&proposed_value.to_vec()).eq(node.outputs()));
    }
    assert!(once(&proposed_value.to_vec()).eq(network.observer.outputs()));
}

fn new_broadcast(netinfo: Arc<NetworkInfo<NodeId>>) -> Broadcast<NodeId> {
    Broadcast::new(netinfo, NodeId(0)).expect("Instantiate broadcast")
}

fn test_broadcast_different_sizes<A, F>(new_adversary: F, proposed_value: &[u8])
where
    A: Adversary<Broadcast<NodeId>>,
    F: Fn(BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>) -> A,
{
    let mut rng = rand::thread_rng();
    let sizes = (1..6)
        .chain(once(rng.gen_range(6, 20)))
        .chain(once(rng.gen_range(30, 50)));
    for size in sizes {
        let num_faulty_nodes = util::max_faulty(size);
        let num_good_nodes = size - num_faulty_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_faulty_nodes
        );
        let adversary = |adv_nodes| new_adversary(adv_nodes);
        let network = TestNetwork::new(num_good_nodes, num_faulty_nodes, adversary, new_broadcast);
        test_broadcast(network, proposed_value);
    }
}

#[test]
fn test_8_broadcast_equal_leaves_silent() {
    let adversary = |_| SilentAdversary::new(MessageScheduler::Random);
    // Space is ASCII character 32. So 32 spaces will create shards that are all equal, even if the
    // length of the value is inserted.
    test_broadcast(
        TestNetwork::new(8, 0, adversary, new_broadcast),
        &[b' '; 32],
    );
}

#[test]
fn test_broadcast_random_delivery_silent() {
    let new_adversary = |_| SilentAdversary::new(MessageScheduler::Random);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_first_delivery_silent() {
    let new_adversary = |_| SilentAdversary::new(MessageScheduler::First);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_random_delivery_adv_propose() {
    let new_adversary = |adv_nodes| ProposeAdversary::new(MessageScheduler::Random, adv_nodes);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_first_delivery_adv_propose() {
    let new_adversary = |adv_nodes| ProposeAdversary::new(MessageScheduler::First, adv_nodes);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_random_adversary() {
    let new_adversary = |_| {
        // Note: Set this to 0.8 to watch 30 gigs of RAM disappear.
        RandomAdversary::new(0.2, 0.2, || TargetedMessage {
            target: Target::All,
            message: rand::random(),
        })
    };
    test_broadcast_different_sizes(new_adversary, b"RandomFoo");
}
