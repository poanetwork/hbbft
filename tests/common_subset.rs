//! Integration tests of the Asynchronous Common Subset protocol.

extern crate hbbft;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use hbbft::common_subset;
use hbbft::common_subset::CommonSubset;
use hbbft::messaging::{Target, TargetedMessage};

type ProposedValue = Vec<u8>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct NodeUid(usize);

/// The queue of messages of a particular Common Subset instance received by a node or output from a
/// Common Subset instance.
type MessageQueue = VecDeque<TargetedMessage<common_subset::Message<NodeUid>, NodeUid>>;

struct TestNode {
    /// Sender ID.
    id: NodeUid,
    /// The Common Subset algorithm.
    cs: CommonSubset<NodeUid>,
    /// Queue of tuples of a sender ID and a message.
    queue: VecDeque<(NodeUid, common_subset::Message<NodeUid>)>,
    /// The output of the Common Subset algorithm, if there is one.
    decision: Option<HashMap<NodeUid, ProposedValue>>,
}

impl TestNode {
    fn new(id: NodeUid, cs: CommonSubset<NodeUid>) -> TestNode {
        TestNode {
            id,
            cs,
            queue: VecDeque::new(),
            decision: None,
        }
    }

    fn handle_message(&mut self) -> (Option<HashMap<NodeUid, Vec<u8>>>, MessageQueue) {
        let (sender_id, message) = self.queue
            .pop_front()
            .expect("popping a message off the queue");
        let (output, messages) = self.cs
            .handle_message(&sender_id, message)
            .expect("handling a Common Subset message");
        debug!("{:?} produced messages: {:?}", self.id, messages);
        if let Some(ref decision) = output {
            self.decision = Some(decision.clone());
        }
        (output, messages)
    }
}

struct TestNetwork {
    nodes: BTreeMap<NodeUid, TestNode>,
    /// The next node to handle a message in its queue.
    scheduled_node_id: NodeUid,
}

impl TestNetwork {
    fn new(all_ids: &HashSet<NodeUid>) -> TestNetwork {
        let num_nodes = all_ids.len();
        // Make a node with an Agreement instance associated with the proposer node 0.
        let make_node = |id: NodeUid| {
            let cs = CommonSubset::new(id, all_ids).expect("Node creation");
            (id, TestNode::new(id, cs))
        };
        TestNetwork {
            nodes: (0..num_nodes).map(NodeUid).map(make_node).collect(),
            scheduled_node_id: NodeUid(0),
        }
    }

    fn dispatch_messages(&mut self, sender_id: NodeUid, messages: MessageQueue) {
        for message in messages {
            match message {
                TargetedMessage {
                    target: Target::Node(id),
                    message,
                } => {
                    let node = self.nodes.get_mut(&id).expect("finding recipient node");
                    node.queue.push_back((sender_id, message));
                }
                TargetedMessage {
                    target: Target::All,
                    message,
                } => {
                    // Multicast the message to other nodes.
                    let _: Vec<()> = self.nodes
                        .iter_mut()
                        .filter(|(id, _)| **id != sender_id)
                        .map(|(_, node)| node.queue.push_back((sender_id, message.clone())))
                        .collect();
                }
            }
        }
    }

    // Gets a node for receiving a message and picks the next node with a
    // non-empty message queue in a cyclic order.
    fn pick_node(&mut self) -> NodeUid {
        let id = self.scheduled_node_id;
        // Try a node with a higher ID for fairness.
        if let Some(next_id) = self.nodes
            .iter()
            .find(|(&next_id, node)| id < next_id && !node.queue.is_empty())
            .map(|(id, _)| *id)
        {
            self.scheduled_node_id = next_id;
        } else {
            // Fall back to nodes up to the currently scheduled ID.
            self.scheduled_node_id = self.nodes
                .iter()
                .find(|(&next_id, node)| id >= next_id && !node.queue.is_empty())
                .map(|(id, _)| *id)
                .expect("no more messages in any node's queue")
        }
        debug!("Picked node {:?}", self.scheduled_node_id);
        id
    }

    fn step(&mut self) -> (NodeUid, Option<HashMap<NodeUid, ProposedValue>>) {
        let sender_id = self.pick_node();
        let (output, messages) = self.nodes.get_mut(&sender_id).unwrap().handle_message();
        self.dispatch_messages(sender_id, messages);
        (sender_id, output)
    }

    /// Make Node 0 propose a value.
    fn send_proposed_value(&mut self, sender_id: NodeUid, value: ProposedValue) {
        let messages = self.nodes
            .get_mut(&sender_id)
            .unwrap()
            .cs
            .send_proposed_value(value)
            .expect("send proposed value");
        self.dispatch_messages(sender_id, messages);
    }
}

fn test_common_subset(mut network: TestNetwork) -> BTreeMap<NodeUid, TestNode> {
    let _ = env_logger::try_init();

    // Pick the first node with a non-empty queue.
    network.pick_node();

    while network.nodes.values().any(|node| node.decision.is_none()) {
        let (NodeUid(id), output) = network.step();
        if let Some(decision) = output {
            debug!("Node {} output {:?}", id, decision);
        }
    }
    network.nodes
}

#[test]
fn test_common_subset_4_nodes_same_proposed_value() {
    let proposed_value = Vec::from("Fake news");
    let all_ids: HashSet<NodeUid> = (0..4).map(NodeUid).collect();
    let mut network = TestNetwork::new(&all_ids);
    let expected_node_decision: HashMap<NodeUid, ProposedValue> = all_ids
        .iter()
        .map(|id| (*id, proposed_value.clone()))
        .collect();

    network.send_proposed_value(NodeUid(0), proposed_value.clone());
    network.send_proposed_value(NodeUid(1), proposed_value.clone());
    network.send_proposed_value(NodeUid(2), proposed_value.clone());
    network.send_proposed_value(NodeUid(3), proposed_value.clone());

    let nodes = test_common_subset(network);

    for node in nodes.values() {
        assert_eq!(node.decision, Some(expected_node_decision.clone()));
    }
}

#[test]
fn test_common_subset_5_nodes_different_proposed_values() {
    let proposed_values = vec![
        Vec::from("Alpha"),
        Vec::from("Bravo"),
        Vec::from("Charlie"),
        Vec::from("Delta"),
        Vec::from("Echo"),
    ];
    let all_ids: HashSet<NodeUid> = (0..5).map(NodeUid).collect();
    let mut network = TestNetwork::new(&all_ids);
    let expected_node_decisions: HashMap<NodeUid, ProposedValue> =
        all_ids.into_iter().zip(proposed_values).collect();

    // Nodes propose their values.
    let _: Vec<()> = expected_node_decisions
        .iter()
        .map(|(id, value)| network.send_proposed_value(*id, value.clone()))
        .collect();

    let nodes = test_common_subset(network);

    for node in nodes.values() {
        assert_eq!(node.decision, Some(expected_node_decisions.clone()));
    }
}
