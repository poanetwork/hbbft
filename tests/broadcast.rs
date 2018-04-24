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
use std::sync::RwLock;
use crossbeam::{Scope, ScopedJoinHandle};
use crossbeam_channel::{bounded, Sender, Receiver};

use hbbft::proto::*;
use hbbft::messaging;
use hbbft::messaging::{QMessage, NodeUid, AlgoError, Algorithm, ProposedValue,
                       AlgoMessage, Handler,
                       MessageLoopState, MessageLoop, RemoteMessage};
use hbbft::broadcast;

use netsim::NetSim;

/// This is a structure to start a consensus node.
pub struct TestNode<'a> {
    /// Node identifier.
    node_index: usize,
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
    message_loop: MessageLoop<'a, TestAlgoError>
}

impl<'a> TestNode<'a>
{
    /// Consensus node constructor. It only initialises initial parameters.
    pub fn new(node_index: usize,
               num_nodes: usize,
               txs: HashMap<NodeUid, Sender<Message<ProposedValue>>>,
               rxs: HashMap<NodeUid, Receiver<Message<ProposedValue>>>,
               value: Option<ProposedValue>) -> Self
    {
        TestNode {
            node_index,
            num_nodes,
            txs: txs.clone(),
            rxs,
            value,
            message_loop: MessageLoop::new(txs)
        }
    }

    pub fn run(&'a self) -> Result<HashSet<ProposedValue>, Error>
    {
        let node0_uid = "127.0.0.1:0".parse().unwrap();
        self.message_loop.insert_algo(Algorithm::Broadcast(node0_uid), self);

        Err(Error::NotImplemented)
    }

    pub fn handler(&self, m: QMessage, tx: Sender<QMessage>) ->
        Result<MessageLoopState, TestAlgoError>
    {
        Err(TestAlgoError::TestError)
    }
}

impl<'a> Handler<TestAlgoError> for TestNode<'a> {
    fn handle(&self, m: QMessage, tx: Sender<QMessage>) ->
        Result<MessageLoopState, TestAlgoError>
    {
        self.handler(m, tx)
    }
}

pub fn broadcast_handler(txs: RwLock<HashMap<NodeUid,
                                             Sender<Message<ProposedValue
                                                            >
                                                    >
                                             >
                                     >,
                         m: &QMessage, tx: Sender<QMessage>) ->
    Result<MessageLoopState, TestAlgoError>
{
    Err(TestAlgoError::TestError)
}

#[derive(Clone, Debug)]
pub enum Error {
    Broadcast(broadcast::Error),
    NotImplemented
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
        nodes.push(TestNode::new(n, num_nodes, txs, rxs, Some(value)));
    }
    nodes
}

#[derive(Debug)]
pub enum TestAlgoError {
    TestError
}

impl AlgoError for TestAlgoError {
    fn to_str(&self) -> &'static str {
        "TestError"
    }
}

#[test]
fn test_4_broadcast_nodes() {
    simple_logger::init_with_level(log::Level::Debug).unwrap();

    const NUM_NODES: usize = 4;
    let net: NetSim<Message<Vec<u8>>> = NetSim::new(NUM_NODES);
    let nodes = create_test_nodes(NUM_NODES, &net);

    crossbeam::scope(|scope| {
        for node in nodes.iter() {
            scope.spawn(move || {
                debug!("Running {:?}", node.node_index);
                node.run().unwrap();
            });
        }
    });
}
