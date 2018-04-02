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
        // algorithm actor tasks such as Reliable Broadcast.
        let (from_comms_tx, from_comms_rx):
        (
            channel::Sender<Message<T>>,
            channel::Receiver<Message<T>>
        ) = channel::unbounded();
        let (from_comms_tx, from_comms_rx) = (&from_comms_tx, &from_comms_rx);

        // Multiple-producer, multiple-consumer channel from algorithm actor
        // tasks such as Reliable Broadcast to comms tasks.
        let (to_comms_tx, to_comms_rx):
        (
            channel::Sender<Message<T>>,
            channel::Receiver<Message<T>>
        ) = channel::unbounded();
        let (to_comms_tx, to_comms_rx) = (&to_comms_tx, &to_comms_rx);

        let broadcast_value = self.value.to_owned();
        let connections = connection::make(&self.addr, &self.remotes);

        // All spawned threads will have exited by the end of the scope.
        crossbeam::scope(|scope| {
            // FIXME: Compute [i <- connections | v_i].

            // Start a comms task for each connection.
            for (i, c) in connections.iter().enumerate() {
                // FIXME:
                //
                // - Connect the comms task to the broadcast instance.
                //
                // - Broadcast v_i through the broadcast instance?

                info!("Creating a comms task #{} for {:?}", i,
                      c.stream.peer_addr().unwrap());
                scope.spawn(move || {
                    commst::CommsTask::new(from_comms_tx,
                                           to_comms_rx,
                                           &c.stream)
                        .run();
                });

                // Associate a broadcast instance to the above comms task.
                scope.spawn(move || {
                    match broadcast::Instance::new(to_comms_tx,
                                                   from_comms_rx,
                                                   // FIXME
                                                   None)
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
