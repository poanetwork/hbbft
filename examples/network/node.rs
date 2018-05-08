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

use crossbeam;
use std::collections::HashSet;
use std::fmt::Debug;
use std::marker::{Send, Sync};
use std::net::SocketAddr;
use std::{io, iter, process};

use hbbft::broadcast;
use network::commst;
use network::connection;
use network::messaging::Messaging;

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
        debug!("Nodes:  {:?}", node_strs);
        let proposer_id = 0;
        let our_id = node_strs.binary_search(&our_str).unwrap();
        let num_nodes = connections.len() + 1;

        if value.is_some() != (our_id == proposer_id) {
            panic!("Exactly the first node must propose a value.");
        }

        // Initialise the message delivery system and obtain TX and RX handles.
        let messaging: Messaging<Vec<u8>> = Messaging::new(num_nodes);
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
                match broadcast::Instance::new(
                    tx_from_algo,
                    rx_to_algo,
                    value.to_owned(),
                    (0..num_nodes).collect(),
                    our_id,
                    proposer_id,
                ).run()
                {
                    Ok(t) => {
                        debug!(
                            "Broadcast succeeded: {}",
                            String::from_utf8(T::into(t)).unwrap()
                        );
                    }
                    Err(e) => error!("Broadcast instance: {:?}", e),
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
                    match commst::CommsTask::new(
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

            // Stop the messaging task.
            stop_tx
                .send(())
                .map_err(|e| {
                    error!("{}", e);
                })
                .unwrap();

            process::exit(0);

            // TODO: Exit cleanly.
            // match msg_handle.join() {
            //     Ok(()) => debug!("Messaging stopped OK"),
            //     Err(e) => debug!("Messaging error: {:?}", e),
            // }
            // Err(Error::NotImplemented)
        }) // end of thread scope
    }
}
