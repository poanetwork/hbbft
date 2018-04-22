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
use std::rc::Rc;
use crossbeam::{Scope, ScopedJoinHandle};
use crossbeam_channel::{bounded, Sender, Receiver};

use hbbft::proto::*;
use hbbft::messaging;
use hbbft::messaging::{AlgoError, Algorithm, ProposedValue, AlgoMessage,
                       MessageLoopState, MessageQueue, RemoteMessage};
use hbbft::broadcast;

use netsim::NetSim;

/// This is a structure to start a consensus node.
#[derive(Debug)]
pub struct TestNode {
    /// Node identifier.
    node_index: usize,
    /// Total number of nodes.
    num_nodes: usize,
    /// TX handles indexed with the receiving node address. One handle for each
    /// other node.
    txs: HashMap<SocketAddr, Sender<Message<Vec<u8>>>>,
    /// RX handle indexed with the transmitting node address. One handle for
    /// each other node.
    rxs: HashMap<SocketAddr, Receiver<Message<Vec<u8>>>>,
    /// Optionally, a value to be broadcast by this node.
    value: Option<ProposedValue>
}

impl TestNode
{
    /// Consensus node constructor. It only initialises initial parameters.
    pub fn new(node_index: usize,
               num_nodes: usize,
               txs: HashMap<SocketAddr, Sender<Message<Vec<u8>>>>,
               rxs: HashMap<SocketAddr, Receiver<Message<Vec<u8>>>>,
               value: Option<ProposedValue>) -> Self
    {
        TestNode {
            node_index,
            num_nodes,
            txs,
            rxs,
            value
        }
    }

    pub fn run(&self) ->
        Result<HashSet<ProposedValue>, Error>
    {
        let mut stop = false;

        // FIXME: localise to the Node context.
        // let f: fn(&VecDeque<RemoteMessage>) = self.send_remote;
        let mut mq: MessageQueue<TestAlgoError> = MessageQueue::new(
            self.txs.clone()
        );

        Err(Error::NotImplemented)
    }

    fn send_remote(&self, messages: &VecDeque<RemoteMessage>) {
        // FIXME
    }
}

fn send_remote(messages: &VecDeque<RemoteMessage>) {

    // FIXME
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
        for node in nodes {
            scope.spawn(move || {
                debug!("Running {:?}", node);
                node.run().unwrap();
            });
        }
    });
}
