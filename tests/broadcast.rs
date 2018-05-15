//! Integration test of the reliable broadcast protocol.

extern crate hbbft;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate merkle;
extern crate rand;

use rand::Rng;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::{fmt, iter};

use hbbft::broadcast::{Broadcast, BroadcastMessage};
use hbbft::messaging::{DistAlgorithm, Target, TargetedMessage};

#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Clone, Copy)]
struct NodeUid(usize);

type ProposedValue = Vec<u8>;

/// A "node" running a broadcast instance.
struct TestNode<D: DistAlgorithm> {
    /// This node's own ID.
    id: D::NodeUid,
    /// The instance of the broadcast algorithm.
    algo: D,
    /// Incoming messages from other nodes that this node has not yet handled.
    queue: VecDeque<(D::NodeUid, D::Message)>,
    /// The values this node has output so far.
    outputs: Vec<D::Output>,
}

impl<D: DistAlgorithm> TestNode<D> {
    /// Creates a new test node with the given broadcast instance.
    fn new(algo: D) -> TestNode<D> {
        TestNode {
            id: algo.our_id().clone(),
            algo,
            queue: VecDeque::new(),
            outputs: Vec::new(),
        }
    }

    /// Handles the first message in the node's queue.
    fn handle_message(&mut self) {
        let (from_id, msg) = self.queue.pop_front().expect("message not found");
        debug!("Handling {:?} -> {:?}: {:?}", from_id, self.id, msg);
        self.algo
            .handle_message(&from_id, msg)
            .expect("handling message");
        self.outputs.extend(self.algo.output_iter());
    }

    /// Inputs a value into the instance.
    fn input(&mut self, input: D::Input) {
        self.algo.input(input).expect("input");
        self.outputs.extend(self.algo.output_iter());
    }
}

/// A strategy for picking the next good node to handle a message.
enum MessageScheduler {
    /// Picks a random node.
    Random,
    /// Picks the first non-idle node.
    First,
}

impl MessageScheduler {
    /// Chooses a node to be the next one to handle a message.
    fn pick_node<D: DistAlgorithm>(&self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid {
        match *self {
            MessageScheduler::First => nodes
                .iter()
                .find(|(_, node)| !node.queue.is_empty())
                .map(|(id, _)| id.clone())
                .expect("no more messages in queue"),
            MessageScheduler::Random => {
                let ids: Vec<D::NodeUid> = nodes
                    .iter()
                    .filter(|(_, node)| !node.queue.is_empty())
                    .map(|(id, _)| id.clone())
                    .collect();
                rand::thread_rng()
                    .choose(&ids)
                    .expect("no more messages in queue")
                    .clone()
            }
        }
    }
}

type MessageWithSender<D> = (
    <D as DistAlgorithm>::NodeUid,
    TargetedMessage<<D as DistAlgorithm>::Message, <D as DistAlgorithm>::NodeUid>,
);

/// An adversary that can control a set of nodes and pick the next good node to receive a message.
trait Adversary<D: DistAlgorithm> {
    /// Chooses a node to be the next one to handle a message.
    fn pick_node(&self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid;

    /// Adds a message sent to one of the adversary's nodes.
    fn push_message(&mut self, sender_id: D::NodeUid, msg: TargetedMessage<D::Message, D::NodeUid>);

    /// Produces a list of messages to be sent from the adversary's nodes.
    fn step(&mut self) -> Vec<MessageWithSender<D>>;
}

/// An adversary whose nodes never send any messages.
struct SilentAdversary {
    scheduler: MessageScheduler,
}

impl SilentAdversary {
    /// Creates a new silent adversary with the given message scheduler.
    fn new(scheduler: MessageScheduler) -> SilentAdversary {
        SilentAdversary { scheduler }
    }
}

impl<D: DistAlgorithm> Adversary<D> for SilentAdversary {
    fn pick_node(&self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid {
        self.scheduler.pick_node(nodes)
    }

    fn push_message(&mut self, _: D::NodeUid, _: TargetedMessage<D::Message, D::NodeUid>) {
        // All messages are ignored.
    }

    fn step(&mut self) -> Vec<MessageWithSender<D>> {
        vec![] // No messages are sent.
    }
}

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

    fn step(&mut self) -> Vec<(NodeUid, TargetedMessage<BroadcastMessage, NodeUid>)> {
        if self.has_sent {
            return vec![];
        }
        self.has_sent = true;
        let node_ids: BTreeSet<NodeUid> = self.adv_nodes
            .iter()
            .chain(self.good_nodes.iter())
            .cloned()
            .collect();
        let id = match self.adv_nodes.iter().next() {
            Some(id) => *id,
            None => return vec![],
        };
        let mut bc = Broadcast::new(id, id, node_ids).expect("broadcast instance");
        bc.input(b"Fake news".to_vec()).expect("propose");
        bc.message_iter().map(|msg| (id, msg)).collect()
    }
}

/// A collection of `TestNode`s representing a network.
struct TestNetwork<A: Adversary<D>, D: DistAlgorithm> {
    nodes: BTreeMap<D::NodeUid, TestNode<D>>,
    adv_nodes: BTreeSet<D::NodeUid>,
    adversary: A,
}

impl<A: Adversary<Broadcast<NodeUid>>> TestNetwork<A, Broadcast<NodeUid>> {
    /// Creates a new network with `good_num` good nodes, and the given `adversary` controlling
    /// `adv_num` nodes.
    fn new(good_num: usize, adv_num: usize, adversary: A) -> TestNetwork<A, Broadcast<NodeUid>> {
        let node_ids: BTreeSet<NodeUid> = (0..(good_num + adv_num)).map(NodeUid).collect();
        let new_broadcast = |id: NodeUid| {
            let bc =
                Broadcast::new(id, NodeUid(0), node_ids.clone()).expect("Instantiate broadcast");
            (id, TestNode::new(bc))
        };
        let mut network = TestNetwork {
            nodes: (0..good_num).map(NodeUid).map(new_broadcast).collect(),
            adversary,
            adv_nodes: (good_num..(good_num + adv_num)).map(NodeUid).collect(),
        };
        let msgs = network.adversary.step();
        for (sender_id, msg) in msgs {
            network.dispatch_messages(sender_id, vec![msg]);
        }
        network
    }

    /// Pushes the messages into the queues of the corresponding recipients.
    fn dispatch_messages<Q>(&mut self, sender_id: NodeUid, msgs: Q)
    where
        Q: IntoIterator<Item = TargetedMessage<BroadcastMessage, NodeUid>> + fmt::Debug,
    {
        for msg in msgs {
            match msg {
                TargetedMessage {
                    target: Target::All,
                    ref message,
                } => {
                    for node in self.nodes.values_mut() {
                        if node.id != sender_id {
                            node.queue.push_back((sender_id, message.clone()))
                        }
                    }
                    self.adversary.push_message(sender_id, msg.clone());
                }
                TargetedMessage {
                    target: Target::Node(to_id),
                    ref message,
                } => {
                    if self.adv_nodes.contains(&to_id) {
                        self.adversary.push_message(sender_id, msg.clone());
                    } else {
                        self.nodes
                            .get_mut(&to_id)
                            .unwrap()
                            .queue
                            .push_back((sender_id, message.clone()));
                    }
                }
            }
        }
    }

    /// Handles a queued message in a randomly selected node and returns the selected node's ID.
    fn step(&mut self) -> NodeUid {
        let msgs = self.adversary.step();
        for (sender_id, msg) in msgs {
            self.dispatch_messages(sender_id, Some(msg));
        }
        // Pick a random non-idle node..
        let id = self.adversary.pick_node(&self.nodes);
        let msgs: Vec<_> = {
            let node = self.nodes.get_mut(&id).unwrap();
            node.handle_message();
            node.algo.message_iter().collect()
        };
        self.dispatch_messages(id, msgs);
        id
    }

    /// Makes the node `proposer_id` propose a value.
    fn input(&mut self, proposer_id: NodeUid, value: ProposedValue) {
        let msgs: Vec<_> = {
            let node = self.nodes.get_mut(&proposer_id).expect("proposer instance");
            node.input(value);
            node.algo.message_iter().collect()
        };
        self.dispatch_messages(proposer_id, msgs);
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
    while network.nodes.values().any(|node| node.outputs.is_empty()) {
        let id = network.step();
        if !network.nodes[&id].outputs.is_empty() {
            assert_eq!(vec![proposed_value.to_vec()], network.nodes[&id].outputs);
            debug!("Node {:?} received", id);
        }
    }
}

fn test_broadcast_different_sizes<A, F>(new_adversary: F, proposed_value: &[u8])
where
    A: Adversary<Broadcast<NodeUid>>,
    F: Fn(usize, usize) -> A,
{
    let mut rng = rand::thread_rng();
    let sizes = (1..6)
        .chain(iter::once(rng.gen_range(6, 20)))
        .chain(iter::once(rng.gen_range(30, 50)));
    for size in sizes {
        let num_faulty_nodes = (size - 1) / 3;
        let num_good_nodes = size - num_faulty_nodes;
        println!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_faulty_nodes
        );
        let adversary = new_adversary(num_good_nodes, num_faulty_nodes);
        let network = TestNetwork::new(num_good_nodes, num_faulty_nodes, adversary);
        test_broadcast(network, proposed_value);
    }
}

#[test]
fn test_8_broadcast_equal_leaves_silent() {
    let adversary = SilentAdversary::new(MessageScheduler::Random);
    // Space is ASCII character 32. So 32 spaces will create shards that are all equal, even if the
    // length of the value is inserted.
    test_broadcast(TestNetwork::new(8, 0, adversary), &[b' '; 32]);
}

#[test]
fn test_broadcast_random_delivery_silent() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::Random);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_nodes_first_delivery_silent() {
    let new_adversary = |_: usize, _: usize| SilentAdversary::new(MessageScheduler::First);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_nodes_random_delivery_adv_propose() {
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
fn test_broadcast_nodes_first_delivery_adv_propose() {
    let new_adversary = |num_good_nodes: usize, num_faulty_nodes: usize| {
        let good_nodes: BTreeSet<NodeUid> = (0..num_good_nodes).map(NodeUid).collect();
        let adv_nodes: BTreeSet<NodeUid> = (num_good_nodes..(num_good_nodes + num_faulty_nodes))
            .map(NodeUid)
            .collect();
        ProposeAdversary::new(MessageScheduler::First, good_nodes, adv_nodes)
    };
    test_broadcast_different_sizes(new_adversary, b"Foo");
}
