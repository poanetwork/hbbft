//! Comms task structure. A comms task communicates with a remote node through a
//! socket. Local communication with coordinating threads is made via
//! `crossbeam_channel::unbounded()`.
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use crossbeam;
use crossbeam_channel as channel;

use proto::Message;
use task;

/// A communication task connects a remote node to the thread that manages the
/// consensus algorithm.
pub struct CommsTask<'a, T: 'a + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
where Vec<u8>: From<T>
{
    /// The transmit side of the multiple producer channel from comms threads.
    tx: &'a channel::Sender<(usize, Message<T>)>,
    /// The receive side of the multiple consumer channel to comms threads.
    rx: &'a channel::Receiver<Message<T>>,
    /// The receive side of the private channel to the comms thread.
    rx_priv: &'a channel::Receiver<Message<T>>,
    /// The socket IO task.
    task: task::Task,
    /// The index of this comms task for identification against its remote node.
    pub node_index: usize
}

impl<'a, T: Debug + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
    CommsTask<'a, T>
where Vec<u8>: From<T>
{
    pub fn new(tx: &'a channel::Sender<(usize, Message<T>)>,
               rx: &'a channel::Receiver<Message<T>>,
               rx_priv: &'a channel::Receiver<Message<T>>,
               stream: ::std::net::TcpStream,
               node_index: usize) ->
        Self
    {
        debug!("Creating comms task #{} for {:?}", node_index,
               stream.peer_addr().unwrap());

        CommsTask {
            tx: tx,
            rx: rx,
            rx_priv: rx_priv,
            task: task::Task::new(stream),
            node_index: node_index
        }
    }

    /// The main socket IO loop and an asynchronous thread responding to manager
    /// thread requests.
    pub fn run(&mut self) {
        // Borrow parts of `self` before entering the thread binding scope.
        let tx = Arc::new(self.tx);
        let rx = Arc::new(self.rx);
        let rx_priv = Arc::new(self.rx_priv);
        let mut task1 = self.task.try_clone().unwrap(); // FIXME: handle errors
        let node_index = self.node_index;

        crossbeam::scope(|scope| {
            // Local comms receive loop thread.
            scope.spawn(move || {
                loop {
                    select_loop! {
                        // Receive a multicast message from the manager thread.
                        recv(rx, message) => {
                            debug!("Node {} <- {:?}", node_index, message);
                            // Forward the message to the remote node.
                            task1.send_message(message)
                                .unwrap();
                            debug!("SENT Node {}", node_index);
                        },
                        // Receive a private message from the manager thread.
                        recv(rx_priv, message) => {
                            debug!("Node {} <- {:?}", node_index, message);
                            // Forward the message to the remote node.
                            task1.send_message(message)
                                .unwrap();
                            debug!("SENT Node {}", node_index);
                        }
                    }
                }
            });

            // Remote comms receive loop.
            loop {
                debug!("Starting remote RX loop for node {}", node_index);
                match self.task.receive_message() {
                    Ok(message) => {
                        debug!("Node {} -> {:?}", node_index, message);
                        tx.send((node_index, message)).unwrap()
                    },
                    Err(task::Error::ProtobufError(e)) =>
                        warn!("Protobuf error {}", e),
                    Err(e) => {
                        warn!("Critical error {:?}", e);
                        break;
                    }
                }
            }
        });
    }
}
