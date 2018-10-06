//! Networking controls of the consensus node.
//!
//! ## Example
//!
//! The following code could be run on host 192.168.1.1:
//!
//! ```ignore
//! extern crate hbbft;
//!
//! use hbbft::node::Node;
//! use std::net::SocketAddr;
//! use std::vec::Vec;
//!
//! fn main() {
//!     let bind_address = "127.0.0.1:10001".parse().unwrap();
//!     let remote_addresses = vec!["192.168.1.2:10002",
//!                                 "192.168.1.3:10003",
//!                                 "192.168.1.4:10004"]
//!         .iter()
//!         .map(|s| s.parse().unwrap())
//!         .collect();
//!
//!     let value = "Value #1".as_bytes().to_vec();
//!
//!     let result = Node::new(bind_address, remote_addresses, Some(value))
//!         .run();
//!     println!("Consensus result {:?}", result);
//! }
//! ```
//!
//! Similar code shall then run on hosts 192.168.1.2, 192.168.1.3 and
//! 192.168.1.4 with appropriate changes in `bind_address` and
//! `remote_addresses`. Each host has it's own optional broadcast `value`. If
//! the consensus `result` is not an error then every successfully terminated
//! consensus node will be the same `result`.

use std::collections::{BTreeSet, HashSet};
use std::fmt::Debug;
use std::marker::{Send, Sync};
use std::net::SocketAddr;
use std::sync::Arc;
use std::{io, iter, process, thread, time};

use crossbeam;
use crypto::poly::Poly;
use crypto::{SecretKey, SecretKeySet};

use hbbft::broadcast::{Broadcast, Message};
use hbbft::{DistAlgorithm, NetworkInfo, SourcedMessage};
use network::messaging::Messaging;
use network::{commst, connection};

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    CommsError(commst::Error),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<commst::Error> for Error {
    fn from(err: commst::Error) -> Error {
        Error::CommsError(err)
    }
}

/// This is a structure to start a consensus node.
pub struct Node<T> {
    /// Incoming connection socket.
    addr: SocketAddr,
    /// Sockets of remote nodes.
    remotes: HashSet<SocketAddr>,
    /// Optionally, a value to be broadcast by this node.
    value: Option<T>,
}

impl<T: Clone + Debug + AsRef<[u8]> + PartialEq + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
    Node<T>
{
    /// Consensus node constructor. It only initialises initial parameters.
    pub fn new(addr: SocketAddr, remotes: HashSet<SocketAddr>, value: Option<T>) -> Self {
        Node {
            addr,
            remotes,
            value,
        }
    }

    /// Consensus node procedure implementing HoneyBadgerBFT.
    pub fn run(&self) -> Result<T, Error> {
        let value = &self.value;
        let (our_str, connections) = connection::make(&self.addr, &self.remotes);
        let mut node_strs: Vec<String> = iter::once(our_str.clone())
            .chain(connections.iter().map(|c| c.node_str.clone()))
            .collect();
        node_strs.sort();
        let our_id = node_strs.binary_search(&our_str).unwrap();
        let all_ids: BTreeSet<_> = (0..node_strs.len()).collect();

        // FIXME: This example doesn't call algorithms that use cryptography. However the keys are
        // required by the interface to all algorithms in Honey Badger. Therefore we set placeholder
        // keys here. A fully-featured application would need to take appropriately initialized keys
        // from elsewhere.
        let secret_key_set = SecretKeySet::from(Poly::zero());
        let sk_share = secret_key_set.secret_key_share(our_id);
        let pub_key_set = secret_key_set.public_keys();
        let sk = SecretKey::default();
        let pub_keys = all_ids
            .iter()
            .map(|id| (*id, SecretKey::default().public_key()))
            .collect();

        let netinfo = NetworkInfo::new(our_id, sk_share, pub_key_set, sk, pub_keys);

        if value.is_some() != (our_id == 0) {
            panic!("Exactly the first node must propose a value.");
        }

        // Initialise the message delivery system and obtain TX and RX handles.
        let messaging: Messaging<Message> = Messaging::new(all_ids.len());
        let rxs_to_comms = messaging.rxs_to_comms();
        let tx_from_comms = messaging.tx_from_comms();
        let rx_to_algo = messaging.rx_to_algo();
        let tx_from_algo = messaging.tx_from_algo();
        let stop_tx = messaging.stop_tx();

        // All spawned threads will have exited by the end of the scope.
        crossbeam::scope(|scope| {
            // Start the centralised message delivery system.
            let _msg_handle = messaging.spawn(scope);

            // Associate a broadcast instance with this node. This instance will
            // broadcast the proposed value. There is no remote node
            // corresponding to this instance, and no dedicated comms task. The
            // node index is 0.
            let broadcast_handle = scope.spawn(move || {
                let mut broadcast =
                    Broadcast::new(Arc::new(netinfo), 0).expect("failed to instantiate broadcast");

                if let Some(v) = value {
                    // FIXME: Use the output.
                    let step = broadcast
                        .handle_input(v.clone().into())
                        .expect("propose value");
                    for msg in step.messages {
                        tx_from_algo.send(msg).expect("send from algo");
                    }
                }

                loop {
                    // Receive a message from the socket IO task.
                    let message = rx_to_algo.recv().expect("receive from algo");
                    let SourcedMessage { source: i, message } = message;
                    debug!("{} received from {}: {:?}", our_id, i, message);
                    let step = broadcast
                        .handle_message(&i, message)
                        .expect("handle broadcast message");
                    for msg in step.messages {
                        debug!("{} sending to {:?}: {:?}", our_id, msg.target, msg.message);
                        tx_from_algo.send(msg).expect("send from algo");
                    }
                    if let Some(output) = step.output.into_iter().next() {
                        println!(
                            "Broadcast succeeded! Node {} output: {}",
                            our_id,
                            String::from_utf8(output).unwrap()
                        );
                        break;
                    }
                }
            });

            // Start a comms task for each connection. Node indices of those
            // tasks are 1 through N where N is the number of connections.
            for (i, c) in connections.iter().enumerate() {
                // Receive side of a single-consumer channel from algorithm
                // actor tasks to the comms task.
                let node_index = if c.node_str < our_str { i } else { i + 1 };
                let rx_to_comms = &rxs_to_comms[node_index];

                scope.spawn(move || {
                    match commst::CommsTask::<Message>::new(
                        tx_from_comms,
                        rx_to_comms,
                        // FIXME: handle error
                        c.stream.try_clone().unwrap(),
                        node_index,
                    ).run()
                    {
                        Ok(_) => debug!("Comms task {} succeeded", node_index),
                        Err(e) => error!("Comms task {}: {:?}", node_index, e),
                    }
                });
            }

            // Wait for the broadcast instances to finish before stopping the
            // messaging task.
            broadcast_handle.join();

            // Wait another second so that pending messages get sent out.
            thread::sleep(time::Duration::from_secs(1));

            // Stop the messaging task.
            stop_tx
                .send(())
                .map_err(|e| {
                    error!("{}", e);
                }).unwrap();

            process::exit(0);
        }) // end of thread scope
    }
}
