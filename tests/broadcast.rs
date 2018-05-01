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
use std::collections::{HashSet, VecDeque};

use hbbft::broadcast::{Broadcast, BroadcastTarget, TargetedBroadcastMessage};
use hbbft::messaging::ProposedValue;
use hbbft::proto::BroadcastMessage;

struct TestNode {
    broadcast: Broadcast<usize>,
    queue: VecDeque<(usize, BroadcastMessage<ProposedValue>)>,
}

impl TestNode {
    fn new(broadcast: Broadcast<usize>) -> TestNode {
        TestNode {
            broadcast,
            queue: VecDeque::new(),
        }
    }
}

/// Creates `num` nodes, and returns the set of node IDs as well as the new `TestNode`s.
fn create_test_nodes(num: usize) -> Vec<TestNode> {
    let node_ids: HashSet<usize> = (0..num).collect();
    (0..num)
        .map(|id| {
            TestNode::new(Broadcast::new(id, node_ids.clone(), num).expect("Instantiate broadcast"))
        })
        .collect()
}

/// Pushes the messages into the queues of the corresponding recipients.
fn dispatch_messages(
    nodes: &mut Vec<TestNode>,
    sender_id: usize,
    msgs: VecDeque<TargetedBroadcastMessage<usize>>,
) {
    for msg in msgs {
        match msg {
            TargetedBroadcastMessage {
                target: BroadcastTarget::All,
                message,
            } => {
                for (i, node) in nodes.iter_mut().enumerate() {
                    if i != sender_id {
                        node.queue.push_back((sender_id, message.clone()))
                    }
                }
            }
            TargetedBroadcastMessage {
                target: BroadcastTarget::Node(to_id),
                message,
            } => nodes[to_id].queue.push_back((sender_id, message)),
        }
    }
}

/// Handles a queued message in a randomly selected node.
fn handle_message(nodes: &mut Vec<TestNode>) -> (usize, Option<ProposedValue>) {
    let ids: Vec<usize> = nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| !node.queue.is_empty())
        .map(|(id, _)| id)
        .collect();
    let id = *rand::thread_rng()
        .choose(&ids)
        .expect("no more messages in queue");
    let (from_id, msg) = nodes[id].queue.pop_front().expect("message not found");
    debug!("Handling {} -> {}: {:?}", from_id, id, msg);
    let (output, msgs) = nodes[id]
        .broadcast
        .handle_broadcast_message(&id, &msg)
        .expect("handling message");
    debug!("Sending: {:?}", msgs);
    dispatch_messages(nodes, id, msgs);
    (id, output)
}

#[test]
fn test_16_broadcast_nodes() {
    simple_logger::init_with_level(log::Level::Debug).unwrap();

    // Create 4 nodes.
    const NUM_NODES: usize = 16;
    let mut nodes = create_test_nodes(NUM_NODES);

    // Make node 0 propose a value.
    let proposed_value = b"Foo";
    let msgs = nodes[0]
        .broadcast
        .propose_value(proposed_value.to_vec())
        .expect("propose");
    dispatch_messages(&mut nodes, 0, msgs);

    // Handle messages in random order until all nodes have output the proposed value.
    let mut received = 0;
    while received < NUM_NODES {
        let (id, output) = handle_message(&mut nodes);
        if let Some(value) = output {
            assert_eq!(value, proposed_value);
            received += 1;
            debug!("Node {} received", id);
        }
    }
}
