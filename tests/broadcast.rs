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
use std::fmt;
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
    txs: Vec<&'a Sender<Message<Vec<u8>>>>,
    /// RX handle, one for each other node.
    rxs: Vec<&'a Receiver<Message<Vec<u8>>>>,
    /// Optionally, a value to be broadcast by this node.
    value: Option<TestValue>
}

impl<'a> TestNode<'a>
{
    /// Consensus node constructor. It only initialises initial parameters.
    pub fn new(node_index: usize,
               num_nodes: usize,
               txs: Vec<&'a Sender<Message<Vec<u8>>>>,
               rxs: Vec<&'a Receiver<Message<Vec<u8>>>>,
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

    pub fn run(&self, messaging: Messaging<Vec<u8>>) ->
        Result<HashSet<TestValue>, Error>
    {
        assert_eq!(self.rxs.len(), self.num_nodes - 1);

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
                                }).map_err(|e| {
                                    error!("{}", e);
                                }).unwrap();
                        },
                        // Receive from an algorithm via local
                        // messaging. Forward the message to the simulated
                        // remote node.
                        recv(to_comms_rxs[i-1], message) => {
                            self.txs[i-1].send(message).map_err(|e| {
                                error!("{}", e);
                            }).unwrap();
                        }
                        recv(comms_stop_rx, _) => {
                            debug!("Stopping comms task {}/{}",
                                   self.node_index, i);
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
                        debug!("Received value {:?}", v);
                        values.insert(v);
                    },
                    Err(e) => {
                        error = Some(Error::Broadcast(e));
                    }
                };
            }

            // Stop the comms tasks.
            for tx in comms_stop_txs {
                tx.send(()).map_err(|e| {
                    error!("{}", e);
                }).unwrap();
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
pub enum Error {
    Broadcast(broadcast::Error),
    NotImplemented
}

impl From<broadcast::Error> for Error {
    fn from(e: broadcast::Error) -> Error { Error::Broadcast(e) }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct TestValue {
    pub value: String
}

impl Debug for TestValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value)?;
        Ok(())
    }
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
                // conversion from UTF-8 often panics:
                // String::from_utf8(bytes).expect("Found invalid UTF-8")
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

fn test_value_fmt(n: usize) -> TestValue {
    TestValue {
        value: format!("-{}-{}-{}-", n, n, n)
    }
}

/// Creates a vector of test nodes but does not run them.
fn create_test_nodes<'a>(num_nodes: usize,
                         net: &'a NetSim<Message<Vec<u8>>>) ->
    Vec<TestNode<'a>>
{
    let mut nodes = Vec::new();
    for n in 0..num_nodes {
        let value = test_value_fmt(n);
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
    let net: NetSim<Message<Vec<u8>>> = NetSim::new(NUM_NODES);
    let nodes = create_test_nodes(NUM_NODES, &net);

    crossbeam::scope(|scope| {

        let mut handles = Vec::new();
        let mut messaging_stop_txs = Vec::new();
        let mut msg_handles = Vec::new();

        for node in nodes {
            // Start a local messaging service on the simulated node.
            let messaging: Messaging<Vec<u8>> =
                Messaging::new(NUM_NODES);
            // Take the handle to receive the result after the thread finishes.
            msg_handles.push(messaging.spawn(scope));
            // Take the thread control handle.
            messaging_stop_txs.push(messaging.stop_tx());

            handles.push(scope.spawn(move || {
                node.run(messaging)
            }));
        }

        // Compare the set of values returned by broadcast against the expected
        // set.
        for h in handles {
            match h.join() {
                Err(Error::NotImplemented) => panic!(),
                Err(err) => panic!("Error: {:?}", err),
                Ok(v) => {
                    let mut expected = HashSet::new();
                    for n in 0..NUM_NODES {
                        expected.insert(test_value_fmt(n));
                    }
                    debug!("Finished with values {:?}", v);
                    assert_eq!(v, expected);
                },
            }
        }
        // Stop all messaging tasks.
        for tx in messaging_stop_txs {
            tx.send(()).map_err(|e| {
                error!("{}", e);
            }).unwrap();
        }
        for (i, h) in msg_handles.into_iter().enumerate() {
            match h.join() {
                Ok(()) => debug!("Messaging[{}] stopped OK", i),
                Err(e) => debug!("Messaging[{}] error: {:?}", i, e)
            }
        }
    });
}
