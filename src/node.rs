//! Networking controls of the consensus node.
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::{Send, Sync};
use std::net::SocketAddr;
use crossbeam;
use crossbeam_channel as channel;

use connection;
use broadcast;
use proto::Message;
use commst;

/// This is a structure to start a consensus node.
pub struct Node<T> {
    /// Incoming connection socket.
    addr: SocketAddr,
    /// Sockets of remote nodes. TODO.
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
        // Multiple-producer, multiple-consumer channel from comms tasks to
        // all algorithm actor tasks such as Reliable Broadcast.
        let (from_comms_tx, from_comms_rx):
        (
            channel::Sender<(usize, Message<T>)>,
            channel::Receiver<(usize, Message<T>)>
        ) = channel::unbounded();
        let (from_comms_tx, from_comms_rx) = (&from_comms_tx, &from_comms_rx);

        // Multiple-producer, multiple-consumer channel from algorithm actor
        // tasks such as Reliable Broadcast to all comms tasks.
        let (to_comms_tx, to_comms_rx):
        (
            channel::Sender<Message<T>>,
            channel::Receiver<Message<T>>
        ) = channel::unbounded();
        let (to_comms_tx, to_comms_rx) = (&to_comms_tx, &to_comms_rx);

        let value = &self.value;
        let connections = connection::make(&self.addr, &self.remotes);

        // Single-consumer channels from algorithm actor tasks to comms tasks.
        let to_comms_1: Vec<(channel::Sender<Message<T>>,
                             channel::Receiver<Message<T>>)> =
            (0 .. connections.len())
            .map(|_| channel::unbounded())
            .collect();
        // All transmit sides of channels to comms tasks are collected together
        // for sending messages to particular remote nodes.
        let to_comms_1_txs: Vec<channel::Sender<Message<T>>> =
            to_comms_1.iter().map(|(tx, _)| tx.to_owned()).collect();
        let to_comms_1 = &to_comms_1;
        let to_comms_1_txs = &to_comms_1_txs;

        // All spawned threads will have exited by the end of the scope.
        crossbeam::scope(|scope| {

            // Associate a broadcast instance with this node. This instance will
            // broadcast the proposed value. There is no remote node
            // corresponding to this instance, and no dedicated comms task. The
            // node index is 0.
            scope.spawn(move || {
                match broadcast::Instance::new(to_comms_tx,
                                               from_comms_rx,
                                               to_comms_1_txs,
                                               value.to_owned(),
                                               0)
                    .run()
                {
                    Ok(_) => debug!("Sender broadcast instance succeeded"),
                    Err(_) => error!("Sender broadcast instance failed")
                }
            });

            // Start a comms task for each connection. Node indices of those
            // tasks are 1 through N where N is the number of connections.
            for (i, c) in connections.iter().enumerate() {

                // Receive side of a single-consumer channel from algorithm
                // actor tasks to the comms task.
                let ref to_comms_1_rx = to_comms_1[i].1;
                let node_index = i + 1;

                scope.spawn(move || {
                    commst::CommsTask::new(from_comms_tx,
                                           to_comms_rx,
                                           to_comms_1_rx,
                                           &c.stream,
                                           node_index)
                        .run();
                });

                // Associate a broadcast instance to the above comms task.
                scope.spawn(move || {
                    match broadcast::Instance::new(to_comms_tx,
                                                   from_comms_rx,
                                                   to_comms_1_txs,
                                                   None,
                                                   node_index)
                        .run()
                    {
                        Ok(_) => debug!("Broadcast instance #{} succeeded", i),
                        Err(_) => error!("Broadcast instance #{} failed", i)
                    }
                });
            }

            // TODO: continue the implementation of the asynchronous common
            // subset algorithm.

        }); // end of thread scope

        Err(())
    }
}
