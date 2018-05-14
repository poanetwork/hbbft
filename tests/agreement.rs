//! Tests of the Binary Byzantine Agreement protocol.
//!
//! There are three properties that are tested:
//!
//! - Agreement: If any correct node outputs the bit b, then every correct node outputs b.
//!
//! - Termination: If all correct nodes receive input, then every correct node outputs a bit.
//!
//! - Validity: If any correct node outputs b, then at least one correct node received b as input.
//!
//! TODO: Implement adversaries and send BVAL messages at different times.

extern crate hbbft;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::collections::{BTreeMap, VecDeque};

use hbbft::agreement::{Agreement, AgreementMessage};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct NodeId(usize);

/// Message pertaining to a particular Agreement instance.
type InstanceMessage = (NodeId, AgreementMessage);
type MessageQueue = VecDeque<InstanceMessage>;

struct TestNode {
    /// Sender ID.
    id: NodeId,
    num_nodes: usize,
    /// Map from proposer IDs into agreement instances.
    agreements: BTreeMap<NodeId, Agreement<NodeId>>,
    /// Queue of triples (sender_id, proposer_id, message).
    queue: VecDeque<(NodeId, NodeId, AgreementMessage)>,
    outputs: BTreeMap<NodeId, Vec<bool>>,
}

impl TestNode {
    fn new(
        id: NodeId,
        num_nodes: usize,
        agreements: BTreeMap<NodeId, Agreement<NodeId>>,
    ) -> TestNode {
        TestNode {
            id,
            num_nodes,
            agreements,
            queue: VecDeque::new(),
            outputs: BTreeMap::new(),
        }
    }

    fn handle_message(&mut self) -> (Option<bool>, MessageQueue) {
        let (sender_id, proposer_id, message) = self.queue
            .pop_front()
            .expect("popping a message off the queue");
        let (output, messages) = self.agreements
            .get_mut(&proposer_id)
            .unwrap()
            .handle_agreement_message(&sender_id, &message)
            .map(|(output, messages)| {
                // Annotate messages with the proposer ID.
                let instance_messages = messages.into_iter().map(|m| (proposer_id, m)).collect();
                (output, instance_messages)
            })
            .expect("handling an agreement message");
        debug!("{:?} produced messages: {:?}", self.id, messages);
        if let Some(output) = output {
            self.outputs
                .entry(proposer_id)
                .and_modify(|e| e.push(output))
                .or_insert(Vec::new());
        }
        (output, messages)
    }
}

struct TestNetwork {
    nodes: BTreeMap<NodeId, TestNode>,
    /// The next node to handle a message in its queue.
    scheduled_node_id: NodeId,
}

impl TestNetwork {
    fn new(num_nodes: usize) -> TestNetwork {
        let make_node = |id: NodeId| {
            let mut agreements = BTreeMap::new();

            for i in 0..num_nodes {
                agreements.insert(NodeId(i), Agreement::new(NodeId(i), num_nodes));
            }
            (id, TestNode::new(id, num_nodes, agreements))
        };
        let network = TestNetwork {
            nodes: (0..num_nodes).map(NodeId).map(make_node).collect(),
            scheduled_node_id: NodeId(0),
        };
        network
    }

    fn dispatch_messages(&mut self, sender_id: NodeId, messages: MessageQueue) {
        for (proposer_id, message) in messages {
            for (id, node) in self.nodes.iter_mut() {
                if *id != sender_id {
                    debug!(
                        "Dispatching from {:?} to {:?}: {:?}",
                        sender_id, id, message
                    );
                    node.queue
                        .push_back((sender_id, proposer_id, message.clone()));
                }
            }
        }
    }

    // Gets a node for receiving a message and picks the next node with a
    // non-empty message queue in a cyclic order.
    fn pick_node(&mut self) -> NodeId {
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

    fn step(&mut self) -> (NodeId, Option<bool>) {
        let sender_id = self.pick_node();
        let (output, messages) = self.nodes.get_mut(&sender_id).unwrap().handle_message();
        self.dispatch_messages(sender_id, messages);
        (sender_id, output)
    }

    fn set_input(&mut self, sender_id: NodeId, proposer_id: NodeId, input: bool) {
        let message = self.nodes
            .get_mut(&proposer_id)
            .unwrap()
            .agreements
            .get_mut(&proposer_id)
            .unwrap()
            .set_input(input)
            .expect("set input");
        self.dispatch_messages(sender_id, VecDeque::from(vec![(proposer_id, message)]));
    }
}

fn test_agreement(mut network: TestNetwork) -> BTreeMap<NodeId, TestNode> {
    let _ = env_logger::try_init();

    // Pick the first node with a non-empty queue.
    network.pick_node();

    while network.nodes.values().any(|node| node.outputs.is_empty()) {
        let (NodeId(id), output) = network.step();
        if let Some(value) = output {
            debug!("Node {} output {}", id, value);
        }
    }
    network.nodes
}

/// Test 3 correct and 1 faulty node. The faulty node simply negates all other
/// nodes' inputs.
#[test]
fn test_agreement_and_validity_with_1_faulty_node() {
    let mut network = TestNetwork::new(4);

    for i in 0..4 {
        network.set_input(NodeId(0), NodeId(i), true);
        network.set_input(NodeId(1), NodeId(i), true);
        network.set_input(NodeId(2), NodeId(i), true);
        network.set_input(NodeId(3), NodeId(i), false);
    }

    let nodes = test_agreement(network);

    for node in nodes.values() {
        for proposer_id in node.agreements.keys() {
            assert_eq!(node.outputs[proposer_id], vec![true]);
        }
    }
}
