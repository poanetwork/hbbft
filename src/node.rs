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
use messaging::{Messaging, Target, TargetedMessage, SourcedMessage};

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
        // // Multiple-producer, multiple-consumer channel from comms tasks to
        // // all algorithm actor tasks such as Reliable Broadcast.
        // let (from_comms_tx, from_comms_rx):
        // (
        //     Sender<(usize, Message<T>)>,
        //     Receiver<(usize, Message<T>)>
        // ) = unbounded();
        // let (from_comms_tx, from_comms_rx) = (&from_comms_tx, &from_comms_rx);

        // // Multiple-producer, multiple-consumer channel from algorithm actor
        // // tasks such as Reliable Broadcast to all comms tasks.
        // let (to_comms_tx, to_comms_rx):
        // (
        //     Sender<Message<T>>,
        //     Receiver<Message<T>>
        // ) = unbounded();
        // let (to_comms_tx, to_comms_rx) = (&to_comms_tx, &to_comms_rx);

        let value = &self.value;
        let connections = connection::make(&self.addr, &self.remotes);

        // // Single-consumer channels from algorithm actor tasks to comms tasks.
        // let to_comms_1: Vec<(channel::Sender<Message<T>>,
        //                      channel::Receiver<Message<T>>)> =
        //     (0 .. connections.len())
        //     .map(|_| channel::unbounded())
        //     .collect();
        // // All transmit sides of channels to comms tasks are collected together
        // // for sending messages to particular remote nodes.
        // let to_comms_1_txs: Vec<channel::Sender<Message<T>>> =
        //     to_comms_1.iter().map(|(tx, _)| tx.to_owned()).collect();
        // let to_comms_1 = &to_comms_1;
        // let to_comms_1_txs = &to_comms_1_txs;

        // let (to_comms_tx, to_comms_rx):
        // (
        //     channel::Sender<Message<T>>,
        //     channel::Receiver<Message<T>>
        // ) = channel::unbounded();
        // let (to_comms_tx, to_comms_rx) = (&to_comms_tx, &to_comms_rx);

        let to_comms: Vec<(Sender<Message<T>>, Receiver<Message<T>>)>
            = (0 .. connections.len())
            .map(|_| unbounded())
            .collect();
        let to_comms_txs = &to_comms.iter()
            .map(|(tx, _)| tx.to_owned())
            .collect();
        let to_comms_rxs: &Vec<Receiver<Message<T>>> = &to_comms.iter()
            .map(|(_, rx)| rx.to_owned())
            .collect();
        let (from_comms_tx, from_comms_rx) = unbounded();
        let (from_comms_tx, from_comms_rx) = (&from_comms_tx, &from_comms_rx);
        let to_algo: Vec<(Sender<SourcedMessage<T>>,
                          Receiver<SourcedMessage<T>>)>
            = (0 .. connections.len() + 1)
            .map(|_| unbounded())
            .collect();
        let to_algo_txs = &to_algo.iter()
            .map(|(tx, _)| tx.to_owned())
            .collect();
        let to_algo_rxs: &Vec<Receiver<SourcedMessage<T>>> = &to_algo.iter()
            .map(|(_, rx)| rx.to_owned())
            .collect();
        let (from_algo_tx, from_algo_rx) = unbounded();
        let (from_algo_tx, from_algo_rx) = (&from_algo_tx, &from_algo_rx);
        let messaging: Messaging<T> =
            Messaging::new(to_comms_txs, from_comms_rx,
                           to_algo_txs, from_algo_rx);

        // All spawned threads will have exited by the end of the scope.
        crossbeam::scope(|scope| {

            let num_nodes = connections.len() + 1;
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
                    Ok(_) => debug!("Sender broadcast instance succeeded"),
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
