//! Tests of the Binary Byzantine Agreement protocol. Only one proposer instance
//! is tested. Each of the nodes in the simulated network run only one instance
//! of Agreement. This way we only test correctness of the protocol and not
//! message dispatch between multiple proposers.
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

/// The queue of messages of a particular Agreement instance.
type InstanceQueue = VecDeque<AgreementMessage>;

struct TestNode {
    /// Sender ID.
    id: NodeId,
    /// The only agreement instance.
    agreement: Agreement<NodeId>,
    /// Queue of tuples of a sender ID and a message.
    queue: VecDeque<(NodeId, AgreementMessage)>,
    /// All outputs
    outputs: Vec<bool>,
}

impl TestNode {
    fn new(id: NodeId, agreement: Agreement<NodeId>) -> TestNode {
        TestNode {
            id,
            agreement,
            queue: VecDeque::new(),
            outputs: Vec::new(),
        }
    }

    fn handle_message(&mut self) -> (Option<bool>, InstanceQueue) {
        let (sender_id, message) = self.queue
            .pop_front()
            .expect("popping a message off the queue");
        self.agreement
            .handle_message(&sender_id, &message)
            .expect("handling an agreement message");
        debug!("{:?} produced messages: {:?}", self.id, messages);
        if let Some(output) = output {
            self.outputs.push(output);
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
        // Make a node with an Agreement instance associated with the proposer node 0.
        let make_node = |id: NodeId| (id, TestNode::new(id, Agreement::new(NodeId(0), num_nodes)));
        TestNetwork {
            nodes: (0..num_nodes).map(NodeId).map(make_node).collect(),
            scheduled_node_id: NodeId(0),
        }
    }

    fn dispatch_messages(&mut self, sender_id: NodeId, messages: InstanceQueue) {
        for message in messages {
            for (id, node) in &mut self.nodes {
                if *id != sender_id {
                    debug!(
                        "Dispatching from {:?} to {:?}: {:?}",
                        sender_id, id, message
                    );
                    node.queue.push_back((sender_id, message.clone()));
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

    fn set_input(&mut self, sender_id: NodeId, input: bool) {
        let message = self.nodes
            .get_mut(&sender_id)
            .unwrap()
            .agreement
            .set_input(input)
            .expect("set input");
        self.dispatch_messages(sender_id, VecDeque::from(vec![message]));
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

/// Test 4 correct nodes. One of the nodes, #3, hasn't finished broadcast yet
/// and gets an input 0 as a result.
#[test]
fn test_agreement_and_validity_with_1_late_node() {
    let mut network = TestNetwork::new(4);

    network.set_input(NodeId(0), true);
    network.set_input(NodeId(1), true);
    network.set_input(NodeId(2), true);
    network.set_input(NodeId(3), false);

    let nodes = test_agreement(network);

    for node in nodes.values() {
        assert_eq!(node.outputs, vec![true]);
    }
}
