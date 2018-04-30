//! Integration test of the reliable broadcast protocol.

extern crate hbbft;
#[macro_use]
extern crate log;
extern crate crossbeam;
extern crate crossbeam_channel;
extern crate merkle;
extern crate simple_logger;

mod netsim;

use crossbeam_channel::{Receiver, Sender};
use std::collections::{HashMap, HashSet};

use hbbft::broadcast;
use hbbft::broadcast::Broadcast;
use hbbft::common_subset;
use hbbft::messaging;
use hbbft::messaging::{AlgoMessage, Algorithm, Handler, LocalMessage, MessageLoop, NodeUid,
                       ProposedValue, QMessage, RemoteMessage, RemoteNode};
use hbbft::proto::*;

use netsim::NetSim;

/// This is a structure to start a consensus node.
pub struct TestNode<'a> {
    /// Node identifier.
    uid: NodeUid,
    /// RX handle indexed with the transmitting node address. One handle for
    /// each other node.
    rxs: HashMap<NodeUid, Receiver<Message<ProposedValue>>>,
    /// Optionally, a value to be broadcast by this node.
    value: Option<ProposedValue>,
    /// Messaging system.
    message_loop: MessageLoop<'a, Error>,
}

impl<'a> TestNode<'a> {
    /// Consensus node constructor. It only initialises initial parameters.
    pub fn new(
        uid: NodeUid,
        txs: HashMap<NodeUid, Sender<Message<ProposedValue>>>,
        rxs: HashMap<NodeUid, Receiver<Message<ProposedValue>>>,
        value: Option<ProposedValue>,
    ) -> Self {
        TestNode {
            uid,
            rxs,
            value,
            message_loop: MessageLoop::new(txs),
        }
    }

    pub fn add_handler<H: 'a + Handler<Error>>(&'a self, algo: Algorithm, handler: &'a H) {
        self.message_loop.insert_algo(algo, handler);
    }

    pub fn run(&'a self) -> Result<HashSet<ProposedValue>, Error> {
        let tx = self.message_loop.queue_tx();

        if let Some(value) = &self.value {
            // Start the broadcast value transmission.
            tx.send(QMessage::Local(LocalMessage {
                dst: Algorithm::Broadcast(self.uid),
                message: AlgoMessage::BroadcastInput(value.clone()),
            }))?;
        }

        crossbeam::scope(|scope| {
            // Spawn receive loops for messages from simulated remote
            // nodes. Each loop receives a message from the simulated remote
            // node and forwards it to the local message loop having annotated
            // the message with the sender node UID.
            for (uid, rx) in &self.rxs {
                let tx = tx.clone();
                let self_uid = self.uid;
                scope.spawn(move || {
                    debug!("Node {} receiver {} starting", self_uid, uid);
                    while let Ok(message) = rx.recv() {
                        // FIXME: error handling
                        tx.send(QMessage::Remote(RemoteMessage {
                            node: RemoteNode::Node(*uid),
                            message,
                        })).unwrap();
                    }
                    debug!("Node {} receiver {} terminated", self_uid, uid);
                });
            }
            // Start the local message loop.
            let _ = self.message_loop.run();
        });

        Err(Error::NotImplemented)
    }
}

#[derive(Clone, Debug)]
pub enum Error {
    Messaging(messaging::Error),
    Broadcast(broadcast::Error),
    CommonSubset(common_subset::Error),
    Send(crossbeam_channel::SendError<QMessage>),
    NotImplemented,
}

impl From<messaging::Error> for Error {
    fn from(e: messaging::Error) -> Error {
        Error::Messaging(e)
    }
}

impl From<broadcast::Error> for Error {
    fn from(e: broadcast::Error) -> Error {
        Error::Broadcast(e)
    }
}

impl From<common_subset::Error> for Error {
    fn from(e: common_subset::Error) -> Error {
        Error::CommonSubset(e)
    }
}

impl From<crossbeam_channel::SendError<QMessage>> for Error {
    fn from(e: crossbeam_channel::SendError<QMessage>) -> Error {
        Error::Send(e)
    }
}

fn proposed_value(n: usize) -> ProposedValue {
    let b: u8 = (n & 0xff) as u8;
    vec![b; 10]
}

fn node_addr(node_index: usize) -> NodeUid {
    format!("127.0.0.1:{}", node_index).parse().unwrap()
}

/// Creates test nodes but does not run them.
fn create_test_nodes(
    num_nodes: usize,
    net: &NetSim<Message<Vec<u8>>>,
) -> HashMap<NodeUid, (TestNode, HashMap<NodeUid, Broadcast>)> {
    let mut nodes = HashMap::new();
    for n in 0..num_nodes {
        let value = proposed_value(n);
        let mut txs = HashMap::new();
        let mut rxs = HashMap::new();
        // Set up comms channels to other nodes.
        for m in 0..num_nodes {
            if n == m {
                // Skip the channel back to the node itself.
                continue;
            }
            let addr = node_addr(m);
            txs.insert(addr, net.tx(n, m));
            rxs.insert(addr, net.rx(m, n));
        }

        let uid = node_addr(n);
        let all_uids: HashSet<NodeUid> = (0..num_nodes).into_iter().map(node_addr).collect();
        let all_uids_copy = all_uids.clone();

        // Create a broadcast algorithm instance for each node.
        let mut broadcast_instances = HashMap::new();
        for uid in all_uids {
            match Broadcast::new(uid, all_uids_copy.clone(), num_nodes) {
                Ok(instance) => {
                    broadcast_instances.insert(uid, instance);
                }
                Err(e) => {
                    panic!("{:?}", e);
                }
            }
        }

        nodes.insert(
            uid,
            (
                TestNode::new(uid, txs, rxs, Some(value)),
                broadcast_instances,
            ),
        );
    }
    nodes
}

#[test]
fn test_4_broadcast_nodes() {
    simple_logger::init_with_level(log::Level::Debug).unwrap();

    const NUM_NODES: usize = 4;

    let net: NetSim<Message<Vec<u8>>> = NetSim::new(NUM_NODES);
    let nodes = create_test_nodes(NUM_NODES, &net);
    let mut join_handles: HashMap<NodeUid, _> = HashMap::new();

    crossbeam::scope(|scope| {
        // Run the test nodes, each in its own thread.
        for (uid, (node, broadcast_instances)) in &nodes {
            join_handles.insert(
                *uid,
                scope.spawn(move || {
                    // Register broadcast instance handlers with the message loop.
                    for (instance_uid, instance) in broadcast_instances {
                        node.add_handler(Algorithm::Broadcast(*instance_uid), instance);
                    }
                    debug!("Running {:?}", node.uid);
                    node.run()
                }),
            );
        }

        for (uid, join_handle) in join_handles {
            let result = join_handle.join();
            println!("Result of {}: {:?}", uid, result);
        }

        println!("Finished");
    });
}
