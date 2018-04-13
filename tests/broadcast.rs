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
mod node_comms;

use std::sync::Arc;
use std::collections::HashSet;
use std::fmt::Debug;
use std::io;
use crossbeam::{Scope, ScopedJoinHandle};
use crossbeam_channel::{bounded, Sender, Receiver};

use hbbft::proto::*;
use hbbft::messaging::{Messaging, SourcedMessage};
use hbbft::broadcast;

use netsim::NetSim;
use node_comms::CommsTask;

/// This is a structure to start a consensus node.
pub struct TestNode<'a> {
    /// Node identifier.
    node_index: usize,
    /// Total number of nodes.
    num_nodes: usize,
    /// TX handles, one for each other node.
    txs: Vec<&'a Sender<Message<TestValue>>>,
    /// RX handle, one for each other node.
    rxs: Vec<&'a Receiver<Message<TestValue>>>,
    /// Optionally, a value to be broadcast by this node.
    value: Option<TestValue>
}

impl<'a> TestNode<'a>
{
    /// Consensus node constructor. It only initialises initial parameters.
    pub fn new(node_index: usize,
               num_nodes: usize,
               txs: Vec<&'a Sender<Message<TestValue>>>,
               rxs: Vec<&'a Receiver<Message<TestValue>>>,
               value: Option<TestValue>) -> Self
    {
        TestNode {
            node_index: node_index,
            num_nodes: num_nodes,
            txs: txs,
            rxs: rxs,
            value: value
        }
    }

    pub fn run(&self, messaging: Messaging<TestValue>) ->
        Result<HashSet<TestValue>, Error<TestValue>>
    {
        assert_eq!(self.rxs.len(), 3);

        let to_comms_rxs = messaging.to_comms_rxs();
        let from_comms_tx = messaging.from_comms_tx();
        let to_algo_rxs = messaging.to_algo_rxs();
        let from_algo_tx = messaging.from_algo_tx();
        let ref to_algo_rx0 = to_algo_rxs[0];
        let value = self.value.to_owned();
        let num_nodes = self.num_nodes;
        let mut values = HashSet::new();

        crossbeam::scope(|scope| {
            let mut handles = Vec::new();

            // Spawn the 0-th instance corresponding to this node. The return
            // value shall be equal to `value` if computation succeeded or error
            // otherwise.
            handles.push(scope.spawn(move || {
                broadcast::Instance::new(from_algo_tx,
                                         to_algo_rx0,
                                         value,
                                         num_nodes,
                                         0)
                    .run()
            }));

            // Control TX handles to stop all comms threads.
            let mut comms_stop_txs = Vec::new();

            // Spawn instances 1 through num_nodes-1 together with simulated
            // remote comms tasks.
            for i in 1..num_nodes {
                // Make a channel to be used to stop the comms task.
                let (comms_stop_tx, comms_stop_rx): (Sender<()>, Receiver<()>) =
                    bounded(1);
                // Record the TX handle for using it later.
                comms_stop_txs.push(comms_stop_tx);
                // Spawn the comms task.
                scope.spawn(move || {
                    // Termination condition variable.
                    let mut stop = false;

                    // Receive messages from the simulated node or locally.
                    while !stop { select_loop! {
                        // Receive from the simulated remote node.
                        recv(self.rxs[i-1], message) => {
                            debug!("Node {}/{} received {:?}",
                                   self.node_index, i, message);
                            from_comms_tx.send(
                                SourcedMessage {
                                    source: i,
                                    message
                                }).unwrap();
                        },
                        // Receive from an algorithm via local
                        // messaging. Forward the message to the simulated
                        // remote node.
                        recv(to_comms_rxs[i-1], message) => {
                            self.txs[i-1].send(message).unwrap();
                        }
                        recv(comms_stop_rx, _) => {
                            stop = true;
                        }
                    }}
                });

                let ref to_algo_rx = to_algo_rxs[i];

                // Spawn a broadcast instance associated with the above comms
                // task.
                handles.push(scope.spawn(move || {
                    broadcast::Instance::new(from_algo_tx,
                                             to_algo_rx,
                                             None,
                                             num_nodes,
                                             i)
                    .run()
                }));
            }

            let mut error = None;

            // Collect the values computed by broadcast instances.
            for h in handles {
                match h.join() {
                    Ok(v) => {
                        values.insert(v);
                    },
                    Err(e) => {
                        error = Some(Error::Broadcast(e));
                    }
                };
            }

            // Stop the comms tasks.
            for tx in comms_stop_txs {
                tx.send(()).unwrap();
            }

            if error.is_some() {
                Err(error.unwrap())
            }
            else {
                Ok(values)
            }
        })
    }
}

#[derive(Clone, Debug)]
pub enum Error<T: Clone + Debug + Send + Sync> {
    Broadcast(broadcast::Error<T>),
    NotImplemented
}

impl<T: Clone + Debug + Send + Sync> From<broadcast::Error<T>> for Error<T> {
    fn from(e: broadcast::Error<T>) -> Error<T> { Error::Broadcast(e) }
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

/// Creates a vector of test nodes but does not run them.
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
        // Set up comms channels to other nodes.
        for m in 0..num_nodes {
            if n == m {
                // Skip the channel back to the node itself.
                continue;
            }
            txs.push(net.tx(n, m));
            rxs.push(net.rx(m, n));
        }
        nodes.push(TestNode::new(n, num_nodes, txs, rxs, Some(value)));
    }
    nodes
}

#[test]
fn test_4_broadcast_nodes() {
    simple_logger::init_with_level(log::Level::Debug).unwrap();

    const NUM_NODES: usize = 4;
    let net: NetSim<Message<TestValue>> = NetSim::new(NUM_NODES);
    let nodes = create_test_nodes(NUM_NODES, &net);

    crossbeam::scope(|scope| {

        let mut handles = Vec::new();
        let mut messaging_stop_txs = Vec::new();

        for node in nodes {
            // Start a local messaging service on the simulated node.
            let messaging: Messaging<TestValue> =
                Messaging::new(NUM_NODES);
            messaging.spawn(scope);
            // Take the thread control handle.
            messaging_stop_txs.push(messaging.stop_tx());

            handles.push(scope.spawn(move || {
                node.run(messaging)
            }));
        }

        // Compare the set of values returned by broadcast against the expected
        // set.
        for h in handles {
            assert!(match h.join() {
                Err(Error::NotImplemented) => true,
                _ => false
            });
        }
        // Stop all messaging tasks.
        for tx in messaging_stop_txs {
            tx.send(()).unwrap();
        }
    });
}
