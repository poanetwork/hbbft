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
use std::io;
use std::marker::{Send, Sync};
use std::net::SocketAddr;

use hbbft::broadcast;
use network::commst;
use network::connection;
use network::messaging::Messaging;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    CommsError(commst::Error),
    NotImplemented,
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
        let connections = connection::make(&self.addr, &self.remotes);
        let num_nodes = connections.len() + 1;

        // Initialise the message delivery system and obtain TX and RX handles.
        let messaging: Messaging<Vec<u8>> = Messaging::new(num_nodes);
        let rxs_to_comms = messaging.rxs_to_comms();
        let tx_from_comms = messaging.tx_from_comms();
        let rxs_to_algo = messaging.rxs_to_algo();
        let tx_from_algo = messaging.tx_from_algo();
        let stop_tx = messaging.stop_tx();

        // All spawned threads will have exited by the end of the scope.
        crossbeam::scope(|scope| {
            // Start the centralised message delivery system.
            let msg_handle = messaging.spawn(scope);
            let mut broadcast_handles = Vec::new();

            // Associate a broadcast instance with this node. This instance will
            // broadcast the proposed value. There is no remote node
            // corresponding to this instance, and no dedicated comms task. The
            // node index is 0.
            let rx_to_algo0 = &rxs_to_algo[0];
            broadcast_handles.push(scope.spawn(move || {
                match broadcast::Instance::new(
                    tx_from_algo,
                    rx_to_algo0,
                    value.to_owned(),
                    num_nodes,
                    0,
                ).run()
                {
                    Ok(t) => {
                        debug!(
                            "Broadcast instance 0 succeeded: {}",
                            String::from_utf8(T::into(t)).unwrap()
                        );
                    }
                    Err(e) => error!("Broadcast instance 0: {:?}", e),
                }
            }));

            // Start a comms task for each connection. Node indices of those
            // tasks are 1 through N where N is the number of connections.
            for (i, c) in connections.iter().enumerate() {
                // Receive side of a single-consumer channel from algorithm
                // actor tasks to the comms task.
                let rx_to_comms = &rxs_to_comms[i];
                let node_index = i + 1;

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

                // Associate a broadcast instance to the above comms task.
                let rx_to_algo = &rxs_to_algo[node_index];
                broadcast_handles.push(scope.spawn(move || {
                    match broadcast::Instance::new(
                        tx_from_algo,
                        rx_to_algo,
                        None,
                        num_nodes,
                        node_index,
                    ).run()
                    {
                        Ok(t) => {
                            debug!(
                                "Broadcast instance {} succeeded: {}",
                                node_index,
                                String::from_utf8(T::into(t)).unwrap()
                            );
                        }
                        Err(e) => error!("Broadcast instance {}: {:?}", node_index, e),
                    }
                }));
            }

            // Wait for the broadcast instances to finish before stopping the
            // messaging task.
            for h in broadcast_handles {
                h.join();
            }

            // Stop the messaging task.
            stop_tx
                .send(())
                .map_err(|e| {
                    error!("{}", e);
                })
                .unwrap();

            match msg_handle.join() {
                Ok(()) => debug!("Messaging stopped OK"),
                Err(e) => debug!("Messaging error: {:?}", e),
            }
            // TODO: continue the implementation of the asynchronous common
            // subset algorithm.
            Err(Error::NotImplemented)
        }) // end of thread scope
    }
}

// #[cfg(test)]
// mod tests {
//     use std::collections::HashSet;
//     use node;

//     /// Test that the node works to completion.
//     #[test]
//     fn test_node_0() {
//         let node = node::Node::new("127.0.0.1:10000".parse().unwrap(),
//                                    HashSet::new(),
//                                    Some("abc".as_bytes().to_vec()));
//         let result = node.run();
//         assert!(match result { Err(node::Error::NotImplemented) => true,
//                                _ => false });
//     }
// }
