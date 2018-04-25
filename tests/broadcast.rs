//! Integration test of the reliable broadcast protocol.

extern crate hbbft;
#[macro_use]
extern crate log;
extern crate simple_logger;
extern crate crossbeam;
#[macro_use]
extern crate crossbeam_channel;
extern crate merkle;

mod netsim;

use std::collections::{BTreeMap, HashSet, HashMap, VecDeque};
use std::fmt;
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::ops::Deref;
use crossbeam::{Scope, ScopedJoinHandle};
use crossbeam_channel::{bounded, Sender, Receiver};

use hbbft::proto::*;
use hbbft::messaging;
use hbbft::messaging::{QMessage, NodeUid, Algorithm, ProposedValue,
                       AlgoMessage, Handler,
                       MessageLoopState, MessageLoop, RemoteMessage, RemoteNode};
use hbbft::broadcast::Broadcast;
use hbbft::broadcast;

use netsim::NetSim;

/// This is a structure to start a consensus node.
pub struct TestNode<'a> {
    /// Node identifier.
    uid: NodeUid,
    /// Total number of nodes.
    num_nodes: usize,
    /// TX handles indexed with the receiving node address. One handle for each
    /// other node.
    txs: HashMap<NodeUid, Sender<Message<ProposedValue>>>,
    /// RX handle indexed with the transmitting node address. One handle for
    /// each other node.
    rxs: HashMap<NodeUid, Receiver<Message<ProposedValue>>>,
    /// Optionally, a value to be broadcast by this node.
    value: Option<ProposedValue>,
    /// Messaging system.
    message_loop: MessageLoop<'a, Error>,
}

impl<'a> TestNode<'a>
{
    /// Consensus node constructor. It only initialises initial parameters.
    pub fn new(uid: NodeUid,
               num_nodes: usize,
               txs: HashMap<NodeUid, Sender<Message<ProposedValue>>>,
               rxs: HashMap<NodeUid, Receiver<Message<ProposedValue>>>,
               value: Option<ProposedValue>) -> Self
    {
        TestNode {
            uid,
            num_nodes,
            txs: txs.clone(),
            rxs,
            value,
            message_loop: MessageLoop::new(txs),
        }
    }

    pub fn add_handler<H: 'a + Handler<Error>>(&'a self,
                                               algo: Algorithm,
                                               handler: &'a H)
    {
        self.message_loop.insert_algo(algo, handler);
    }

    pub fn run(&'a self) -> Result<HashSet<ProposedValue>, Error>
    {
        let tx = self.message_loop.queue_tx();

        crossbeam::scope(|scope| {
            // Spawn receive loops for messages from simulated remote
            // nodes. Each loop receives a message from the simulated remote
            // node and forwards it to the local message loop having annotated
            // the message with the sender node UID.
            for (uid, rx) in &self.rxs {
                let tx = tx.clone();
                let self_uid = self.uid;
                scope.spawn(move || {
                    while let Ok(message) = rx.recv() {
                        // FIXME: error handling
                        tx.send(QMessage::Remote(RemoteMessage {
                            node: RemoteNode::Node(uid.clone()),
                            message
                        })).unwrap();
                    }
                    debug!("Node {} receiver {} terminated", self_uid, uid);
                });
            }
            let _ = self.message_loop.run();
        });

        Err(Error::NotImplemented)
    }
}

#[derive(Clone, Debug)]
pub enum Error {
    Messaging(messaging::Error),
    Broadcast(broadcast::Error),
    NotImplemented
}

impl From<messaging::Error> for Error {
    fn from(e: messaging::Error) -> Error { Error::Messaging(e) }
}

impl From<broadcast::Error> for Error {
    fn from(e: broadcast::Error) -> Error { Error::Broadcast(e) }
}

fn proposed_value(n: usize) -> ProposedValue {
    let b: u8 = (n & 0xff) as u8;
    vec![b; 10]
}

fn node_addr(node_index: usize) -> SocketAddr {
    format!("127.0.0.1:{}", node_index).parse().unwrap()
}

/// Creates a vector of test nodes but does not run them.
fn create_test_nodes(num_nodes: usize,
                     net: &NetSim<Message<Vec<u8>>>) ->
    Vec<TestNode>
{
    let mut nodes = Vec::new();
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
        nodes.push(TestNode::new(uid, num_nodes, txs, rxs, Some(value)));
    }
    nodes
}

#[test]
fn test_4_broadcast_nodes() {
    simple_logger::init_with_level(log::Level::Debug).unwrap();

    const NUM_NODES: usize = 4;
    let mut node_uids = Vec::new();
    for i in 0..NUM_NODES {
        node_uids.push(node_addr(i));
    }
    let node_uids_r = &node_uids;

    // Create algorithm instances. FIXME.
    let bi0 = Arc::new(Broadcast::new());

    let net: NetSim<Message<Vec<u8>>> = NetSim::new(NUM_NODES);
    let nodes = create_test_nodes(NUM_NODES, &net);
    let mut join_handles: HashMap<NodeUid, _> = HashMap::new();

    crossbeam::scope(|scope| {
        let bi0 = &bi0;

        for node in nodes.iter() {
            join_handles.insert(node.uid, scope.spawn(move || {
                node.add_handler(Algorithm::Broadcast(node_uids_r[0]),
                                 bi0.deref());
                debug!("Running {:?}", node.uid);
                node.run()
            }));
        }

        for (uid, join_handle) in join_handles {
            let result = join_handle.join();
            println!("Result of {}: {:?}", uid, result);
        }

        println!("Finished");
    });
}
