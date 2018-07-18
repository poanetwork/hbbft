#![deny(unused_must_use)]
//! Integration test of the reliable broadcast protocol.

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

use std::collections::{BTreeMap, BTreeSet};
use std::iter::once;
use std::sync::Arc;

use rand::Rng;

use hbbft::broadcast::{Broadcast, BroadcastMessage};
use hbbft::crypto::SecretKeySet;
use hbbft::messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};
use network::{
    Adversary, MessageScheduler, MessageWithSender, NodeUid, RandomAdversary, SilentAdversary,
    TestNetwork, TestNode,
};

/// An adversary that inputs an alternate value.
struct ProposeAdversary {
    scheduler: MessageScheduler,
    good_nodes: BTreeSet<NodeUid>,
    adv_nodes: BTreeSet<NodeUid>,
    has_sent: bool,
}

impl ProposeAdversary {
    /// Creates a new replay adversary with the given message scheduler.
    fn new(
        scheduler: MessageScheduler,
        good_nodes: BTreeSet<NodeUid>,
        adv_nodes: BTreeSet<NodeUid>,
    ) -> ProposeAdversary {
        ProposeAdversary {
            scheduler,
            good_nodes,
            adv_nodes,
            has_sent: false,
        }
    }
}

impl Adversary<Broadcast<NodeUid>> for ProposeAdversary {
    fn pick_node(&self, nodes: &BTreeMap<NodeUid, TestNode<Broadcast<NodeUid>>>) -> NodeUid {
        self.scheduler.pick_node(nodes)
    }

    fn push_message(&mut self, _: NodeUid, _: TargetedMessage<BroadcastMessage, NodeUid>) {
        // All messages are ignored.
    }

    fn step(&mut self) -> Vec<MessageWithSender<Broadcast<NodeUid>>> {
        if self.has_sent {
            return vec![];
        }
        self.has_sent = true;
        let node_ids: BTreeSet<NodeUid> = self
            .adv_nodes
            .iter()
            .chain(self.good_nodes.iter())
            .cloned()
            .collect();
        let id = match self.adv_nodes.iter().next() {
            Some(id) => *id,
            None => return vec![],
        };

        // FIXME: Take the correct, known keys from the network.
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(self.adv_nodes.len(), &mut rng);
        let pk_set = sk_set.public_keys();

        let netinfo = Arc::new(NetworkInfo::new(
            id,
            node_ids,
            sk_set.secret_key_share(0),
            pk_set,
        ));
        let mut bc = Broadcast::new(netinfo, id).expect("broadcast instance");
        // FIXME: Use the output.
        let _ = bc.input(b"Fake news".to_vec()).expect("propose");
        bc.message_iter()
            .map(|msg| MessageWithSender::new(id, msg))
            .collect()
    }
}

/// Broadcasts a value from node 0 and expects all good nodes to receive it.
fn test_broadcast<A: Adversary<Broadcast<NodeUid>>>(
    mut network: TestNetwork<A, Broadcast<NodeUid>>,
    proposed_value: &[u8],
) {
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    // Make node 0 propose the value.
    network.input(NodeUid(0), proposed_value.to_vec());

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

fn new_broadcast(netinfo: Arc<NetworkInfo<NodeUid>>) -> Broadcast<NodeUid> {
    Broadcast::new(netinfo, NodeUid(0)).expect("Instantiate broadcast")
}

fn test_broadcast_different_sizes<A, F>(new_adversary: F, proposed_value: &[u8])
where
    A: Adversary<Broadcast<NodeUid>>,
    F: Fn(usize, usize) -> A,
{
    let mut rng = rand::thread_rng();
    let sizes = (1..6)
        .chain(once(rng.gen_range(6, 20)))
        .chain(once(rng.gen_range(30, 50)));
    for size in sizes {
        let num_faulty_nodes = (size - 1) / 3;
        let num_good_nodes = size - num_faulty_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_faulty_nodes
        );
        let adversary = |_| new_adversary(num_good_nodes, num_faulty_nodes);
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
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::Random);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_first_delivery_silent() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::First);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_random_delivery_adv_propose() {
    let new_adversary = |num_good_nodes: usize, num_faulty_nodes: usize| {
        let good_nodes: BTreeSet<NodeUid> = (0..num_good_nodes).map(NodeUid).collect();
        let adv_nodes: BTreeSet<NodeUid> = (num_good_nodes..(num_good_nodes + num_faulty_nodes))
            .map(NodeUid)
            .collect();
        ProposeAdversary::new(MessageScheduler::Random, good_nodes, adv_nodes)
    };
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_first_delivery_adv_propose() {
    let new_adversary = |num_good_nodes: usize, num_faulty_nodes: usize| {
        let good_nodes: BTreeSet<NodeUid> = (0..num_good_nodes).map(NodeUid).collect();
        let adv_nodes: BTreeSet<NodeUid> = (num_good_nodes..(num_good_nodes + num_faulty_nodes))
            .map(NodeUid)
            .collect();
        ProposeAdversary::new(MessageScheduler::First, good_nodes, adv_nodes)
    };
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_random_adversary() {
    let new_adversary = |_, _| {
        // Note: Set this to 0.8 to watch 30 gigs of RAM disappear.
        RandomAdversary::new(0.2, 0.2, || TargetedMessage {
            target: Target::All,
            message: rand::random(),
        })
    };
    test_broadcast_different_sizes(new_adversary, b"RandomFoo");
}
