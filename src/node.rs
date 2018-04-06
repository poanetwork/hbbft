//! Networking controls of the consensus node.
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::{Send, Sync};
use std::net::SocketAddr;
use crossbeam;
use crossbeam_channel::{unbounded, Sender, Receiver};

use connection;
use broadcast;
use proto::Message;
use commst;
use messaging::Messaging;

/// This is a structure to start a consensus node.
pub struct Node<T> {
    /// Incoming connection socket.
    addr: SocketAddr,
    /// Sockets of remote nodes.
    remotes: HashSet<SocketAddr>,
    /// Optionally, a value to be broadcast by this node.
    value: Option<T>
}

impl<T: Clone + Debug + Eq + Hash + Send + Sync + From<Vec<u8>> + AsRef<[u8]>>
    Node<T>
where Vec<u8>: From<T>
{
    /// Consensus node constructor. It only initialises initial parameters.
    pub fn new(addr: SocketAddr,
               remotes: HashSet<SocketAddr>,
               value: Option<T>) -> Self
    {
        Node {addr, remotes, value}
    }

    /// Consensus node procedure implementing HoneyBadgerBFT.
    pub fn run(&self) -> Result<T, ()>
    {
        let value = &self.value;
        let connections = connection::make(&self.addr, &self.remotes);
        let num_nodes = connections.len() + 1;

        // Initialise the message delivery system and obtain TX and RX handles.
        let messaging: Messaging<T> = Messaging::new(num_nodes);
        let to_comms_rxs = messaging.to_comms_rxs();
        let from_comms_tx = messaging.from_comms_tx();
        let to_algo_rxs = messaging.to_algo_rxs();
        let from_algo_tx = messaging.from_algo_tx();

        // All spawned threads will have exited by the end of the scope.
        crossbeam::scope(|scope| {
            // Start the centralised message delivery system.
            messaging.spawn(scope);

            // Associate a broadcast instance with this node. This instance will
            // broadcast the proposed value. There is no remote node
            // corresponding to this instance, and no dedicated comms task. The
            // node index is 0.
            let ref to_algo_rx0 = to_algo_rxs[0];
            scope.spawn(move || {
                match broadcast::Instance::new(from_algo_tx,
                                               to_algo_rx0,
                                               value.to_owned(),
                                               num_nodes,
                                               0)
                    .run()
                {
                    Ok(t) => {
                        debug!("Broadcast instance 0 succeeded: {}",
                               String::from_utf8(Vec::from(t)).unwrap());
                    },
                    Err(_) => error!("Sender broadcast instance failed")
                }
            });

            // Start a comms task for each connection. Node indices of those
            // tasks are 1 through N where N is the number of connections.
            for (i, c) in connections.iter().enumerate() {

                // Receive side of a single-consumer channel from algorithm
                // actor tasks to the comms task.
                let ref to_comms_rx = to_comms_rxs[i];
                let node_index = i + 1;

                scope.spawn(move || {
                    commst::CommsTask::new(from_comms_tx,
                                           to_comms_rx,
                                           // FIXME: handle error
                                           c.stream.try_clone().unwrap(),
                                           node_index)
                        .run();
                });


                // Associate a broadcast instance to the above comms task.
                let ref to_algo_rx = to_algo_rxs[node_index];
                scope.spawn(move || {
                    match broadcast::Instance::new(from_algo_tx,
                                                   to_algo_rx,
                                                   None,
                                                   num_nodes,
                                                   node_index)
                        .run()
                    {
                        Ok(t) => {
                            debug!("Broadcast instance {} succeeded: {}",
                                   node_index,
                                   String::from_utf8(
                                       Vec::from(t)
                                   ).unwrap());
                        },
                        Err(_) => error!("Broadcast instance {} failed", i)
                    }
                });
            }

            // TODO: continue the implementation of the asynchronous common
            // subset algorithm.

        }); // end of thread scope

        Err(())
    }
}
