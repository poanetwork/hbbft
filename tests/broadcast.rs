//! Integration test of the reliable broadcast protocol.

extern crate hbbft;
#[macro_use]
extern crate log;
extern crate crossbeam;
extern crate crossbeam_channel;
extern crate merkle;
extern crate rand;
extern crate simple_logger;

use rand::Rng;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fmt;

use hbbft::broadcast::{Broadcast, BroadcastTarget, TargetedBroadcastMessage};
use hbbft::messaging::ProposedValue;
use hbbft::proto::BroadcastMessage;

#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Clone, Copy)]
struct NodeId(usize);

type MessageQueue = VecDeque<TargetedBroadcastMessage<NodeId>>;

/// A "node" running a broadcast instance.
struct TestNode {
    /// This node's own ID.
    id: NodeId,
    /// The instance of the broadcast algorithm.
    broadcast: Broadcast<NodeId>,
    /// Incoming messages from other nodes that this node has not yet handled.
    queue: VecDeque<(NodeId, BroadcastMessage<ProposedValue>)>,
    /// The values this node has output so far.
    outputs: Vec<ProposedValue>,
}

impl TestNode {
    /// Creates a new test node with the given broadcast instance.
    fn new(broadcast: Broadcast<NodeId>) -> TestNode {
        TestNode {
            id: *broadcast.our_id(),
            broadcast,
            queue: VecDeque::new(),
            outputs: Vec::new(),
        }
    }

    /// Handles the first message in the node's queue.
    fn handle_message(&mut self) -> (Option<ProposedValue>, MessageQueue) {
        let (from_id, msg) = self.queue.pop_front().expect("message not found");
        debug!("Handling {:?} -> {:?}: {:?}", from_id, self.id, msg);
        let (output, msgs) = self.broadcast
            .handle_broadcast_message(&from_id, &msg)
            .expect("handling message");
        if let Some(output) = output.clone() {
            self.outputs.push(output);
        }
        (output, msgs)
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
    fn pick_node(&self, nodes: &BTreeMap<NodeId, TestNode>) -> NodeId {
        match *self {
            MessageScheduler::First => nodes
                .iter()
                .find(|(_, node)| !node.queue.is_empty())
                .map(|(id, _)| *id)
                .expect("no more messages in queue"),
            MessageScheduler::Random => {
                let ids: Vec<NodeId> = nodes
                    .iter()
                    .filter(|(_, node)| !node.queue.is_empty())
                    .map(|(id, _)| *id)
                    .collect();
                *rand::thread_rng()
                    .choose(&ids)
                    .expect("no more messages in queue")
            }
        }
    }
}

/// An adversary that can control a set of nodes and pick the next good node to receive a message.
trait Adversary {
    /// Chooses a node to be the next one to handle a message.
    fn pick_node(&self, nodes: &BTreeMap<NodeId, TestNode>) -> NodeId;

    /// Adds a message sent to one of the adversary's nodes.
    fn push_message(&mut self, sender_id: NodeId, msg: TargetedBroadcastMessage<NodeId>);

    /// Produces a list of messages to be sent from the adversary's nodes.
    fn step(&mut self) -> Vec<(NodeId, TargetedBroadcastMessage<NodeId>)>;
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

impl Adversary for SilentAdversary {
    fn pick_node(&self, nodes: &BTreeMap<NodeId, TestNode>) -> NodeId {
        self.scheduler.pick_node(nodes)
    }

    fn push_message(&mut self, _: NodeId, _: TargetedBroadcastMessage<NodeId>) {
        // All messages are ignored.
    }

    fn step(&mut self) -> Vec<(NodeId, TargetedBroadcastMessage<NodeId>)> {
        vec![] // No messages are sent.
    }
}

/// An adversary that proposes an alternate value.
struct ProposeAdversary {
    scheduler: MessageScheduler,
    good_nodes: BTreeSet<NodeId>,
    adv_nodes: BTreeSet<NodeId>,
    has_sent: bool,
}

impl ProposeAdversary {
    /// Creates a new replay adversary with the given message scheduler.
    fn new(
        scheduler: MessageScheduler,
        good_nodes: BTreeSet<NodeId>,
        adv_nodes: BTreeSet<NodeId>,
    ) -> ProposeAdversary {
        ProposeAdversary {
            scheduler,
            good_nodes,
            adv_nodes,
            has_sent: false,
        }
    }
}

impl Adversary for ProposeAdversary {
    fn pick_node(&self, nodes: &BTreeMap<NodeId, TestNode>) -> NodeId {
        self.scheduler.pick_node(nodes)
    }

    fn push_message(&mut self, _: NodeId, _: TargetedBroadcastMessage<NodeId>) {
        // All messages are ignored.
    }

    fn step(&mut self) -> Vec<(NodeId, TargetedBroadcastMessage<NodeId>)> {
        if self.has_sent {
            return vec![];
        }
        self.has_sent = true;
        let value = b"Fake news";
        let node_ids: HashSet<NodeId> = self.adv_nodes
            .iter()
            .cloned()
            .chain(self.good_nodes.iter().cloned())
            .collect();
        let id = *self.adv_nodes.iter().next().unwrap();
        let bc = Broadcast::new(id, id, node_ids).expect("broadcast instance");
        let msgs = bc.propose_value(value.to_vec()).expect("propose");
        msgs.into_iter().map(|msg| (id, msg)).collect()
    }
}

/// A collection of `TestNode`s representing a network.
struct TestNetwork<A: Adversary> {
    nodes: BTreeMap<NodeId, TestNode>,
    adv_nodes: BTreeSet<NodeId>,
    adversary: A,
}

impl<A: Adversary> TestNetwork<A> {
    /// Creates a new network with `good_num` good nodes, and the given `adversary` controlling
    /// `adv_num` nodes.
    fn new(good_num: usize, adv_num: usize, adversary: A) -> TestNetwork<A> {
        let node_ids: HashSet<NodeId> = (0..(good_num + adv_num)).map(NodeId).collect();
        let new_broadcast = |id: NodeId| {
            let bc =
                Broadcast::new(id, NodeId(0), node_ids.clone()).expect("Instantiate broadcast");
            (id, TestNode::new(bc))
        };
        let mut network = TestNetwork {
            nodes: (0..good_num).map(NodeId).map(new_broadcast).collect(),
            adversary,
            adv_nodes: (good_num..(good_num + adv_num)).map(NodeId).collect(),
        };
        let msgs = network.adversary.step();
        for (sender_id, msg) in msgs {
            network.dispatch_messages(sender_id, vec![msg]);
        }
        network
    }

    /// Pushes the messages into the queues of the corresponding recipients.
    fn dispatch_messages<Q>(&mut self, sender_id: NodeId, msgs: Q)
    where
        Q: IntoIterator<Item = TargetedBroadcastMessage<NodeId>> + fmt::Debug,
    {
        debug!("Sending: {:?}", msgs);
        for msg in msgs {
            match msg {
                TargetedBroadcastMessage {
                    target: BroadcastTarget::All,
                    ref message,
                } => {
                    for node in self.nodes.values_mut() {
                        if node.id != sender_id {
                            node.queue.push_back((sender_id, message.clone()))
                        }
                    }
                    self.adversary.push_message(sender_id, msg.clone());
                }
                TargetedBroadcastMessage {
                    target: BroadcastTarget::Node(to_id),
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

    /// Handles a queued message in a randomly selected node and returns the selected node's ID and
    /// its output value, if any.
    fn step(&mut self) -> (NodeId, Option<ProposedValue>) {
        let msgs = self.adversary.step();
        for (sender_id, msg) in msgs {
            self.dispatch_messages(sender_id, Some(msg));
        }
        // Pick a random non-idle node..
        let id = self.adversary.pick_node(&self.nodes);
        let (output, msgs) = self.nodes.get_mut(&id).unwrap().handle_message();
        self.dispatch_messages(id, msgs);
        (id, output)
    }

    /// Makes the node `proposer_id` propose a value.
    fn propose_value(&mut self, proposer_id: NodeId, value: ProposedValue) {
        let msgs = self.nodes[&proposer_id]
            .broadcast
            .propose_value(value)
            .expect("propose");
        self.dispatch_messages(proposer_id, msgs);
    }
}

/// Broadcasts a value from node 0 and expects all good nodes to receive it.
fn test_broadcast<A: Adversary>(mut network: TestNetwork<A>) {
    // TODO: This returns an error in all but the first test.
    let _ = simple_logger::init_with_level(log::Level::Debug);

    // Make node 0 propose a value.
    let proposed_value = b"Foo";
    network.propose_value(NodeId(0), proposed_value.to_vec());

    // Handle messages in random order until all nodes have output the proposed value.
    while network.nodes.values().any(|node| node.outputs.is_empty()) {
        let (id, output) = network.step();
        if let Some(value) = output {
            assert_eq!(value, proposed_value);
            assert_eq!(1, network.nodes[&id].outputs.len());
            debug!("Node {:?} received", id);
        }
    }
}

#[test]
fn test_11_5_broadcast_nodes_random_delivery() {
    let adversary = SilentAdversary::new(MessageScheduler::Random);
    test_broadcast(TestNetwork::new(11, 5, adversary));
}

#[test]
fn test_11_5_broadcast_nodes_first_delivery() {
    let adversary = SilentAdversary::new(MessageScheduler::First);
    test_broadcast(TestNetwork::new(11, 5, adversary));
}

#[test]
fn test_11_5_broadcast_nodes_random_delivery_adv_propose() {
    let good_nodes: BTreeSet<NodeId> = (0..11).map(NodeId).collect();
    let adv_nodes: BTreeSet<NodeId> = (11..16).map(NodeId).collect();
    let adversary = ProposeAdversary::new(MessageScheduler::Random, good_nodes, adv_nodes);
    test_broadcast(TestNetwork::new(11, 5, adversary));
}

#[test]
fn test_11_5_broadcast_nodes_first_delivery_adv_propose() {
    let good_nodes: BTreeSet<NodeId> = (0..11).map(NodeId).collect();
    let adv_nodes: BTreeSet<NodeId> = (11..16).map(NodeId).collect();
    let adversary = ProposeAdversary::new(MessageScheduler::First, good_nodes, adv_nodes);
    test_broadcast(TestNetwork::new(11, 5, adversary));
}
