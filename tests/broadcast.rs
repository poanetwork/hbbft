//! Integration test of the reliable broadcast protocol.

extern crate hbbft;
extern crate crossbeam;
#[macro_use]
extern crate crossbeam_channel;
extern crate merkle;

mod netsim;

use std::collections::HashSet;
use std::fmt::Debug;
use std::io;
use crossbeam_channel::{Sender, Receiver};

use hbbft::proto::*;

use netsim::NetSim;

/// This is a structure to start a consensus node.
pub struct TestNode<'a> {
    /// Node identifier
    ident: usize,
    /// TX handles, one for each other node
    txs: Vec<&'a Sender<Message<TestValue>>>,
    /// RX handle, one for each other node
    rxs: Vec<&'a Receiver<Message<TestValue>>>,
    /// Optionally, a value to be broadcast by this node.
    value: Option<TestValue>
}

impl<'a> TestNode<'a>
{
    /// Consensus node constructor. It only initialises initial parameters.
    pub fn new(ident: usize,
               txs: Vec<&'a Sender<Message<TestValue>>>,
               rxs: Vec<&'a Receiver<Message<TestValue>>>,
               value: Option<TestValue>) -> Self
    {
        TestNode {
            ident: ident,
            txs: txs,
            rxs: rxs,
            value: value
        }
    }

    pub fn run(&self) -> Result<HashSet<TestValue>, Error> {
        assert_eq!(self.rxs.len(), 3);
        let mut result = None;
        for n in 0..3 {
            self.txs[n].send(Message::Broadcast(
                BroadcastMessage::Ready(Vec::new()))
            ).unwrap();
        }
        while result.is_none() {
            select_loop! {
                recv(self.rxs[0], message) => {
                    println!("Node {}/0 received {:?}", self.ident, message);
                    result = Some(Err(Error::NotImplemented));
                }
                recv(self.rxs[1], message) => {
                    println!("Node {}/1 received {:?}", self.ident, message);
                    result = Some(Err(Error::NotImplemented));
                }
                recv(self.rxs[2], message) => {
                    println!("Node {}/2 received {:?}", self.ident, message);
                    result = Some(Err(Error::NotImplemented));
                }
            }
        }
        result.unwrap()
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    NotImplemented
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct TestValue {
    pub value: String
}

/// `TestValue: merkle::Hashable` is derived from `TestValue: AsRef<[u8]>`.
impl AsRef<[u8]> for TestValue {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl From<Vec<u8>> for TestValue {
    fn from(bytes: Vec<u8>) -> TestValue {
        TestValue {
            value: String::from_utf8(bytes).expect("Found invalid UTF-8")
        }
    }
}

impl From<TestValue> for Vec<u8> {
    fn from(v: TestValue) -> Vec<u8> {
        match v {
            TestValue { value } => {
                value.as_bytes().to_vec()
            }
        }
    }
}

fn create_test_nodes<'a>(num_nodes: usize,
                         net: &'a NetSim<Message<TestValue>>) ->
    Vec<TestNode<'a>>
{
    let mut nodes = Vec::new();
    for n in 0..num_nodes {
        let value = TestValue {
            value: format!("-{}-{}-{}-", n, n, n)
        };
        let mut txs = Vec::new();
        let mut rxs = Vec::new();
        for m in 0..num_nodes {
            if n == m {
                // Skip the channel back to the node itself.
                continue;
            }
            txs.push(net.tx(n, m));
            rxs.push(net.rx(m, n));
        }
        nodes.push(TestNode::new(n, txs, rxs, Some(value)));
    }
    nodes
}

#[test]
fn test_4_broadcast_nodes() {
    const NUM_NODES: usize = 4;
    let net: NetSim<Message<TestValue>> = NetSim::new(NUM_NODES);
    let nodes = create_test_nodes(NUM_NODES, &net);

    crossbeam::scope(|scope| {
        let mut handles = Vec::new();

        for node in nodes {
            handles.push(scope.spawn(move || {
                node.run()
            }));
        }

        // Compare the set of values returned by broadcast against the expected
        // set.
        for h in handles {
            assert_eq!(h.join(), Err(Error::NotImplemented));
        }
    });
}
