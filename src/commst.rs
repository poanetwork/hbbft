//! Comms task structure. A comms task communicates with a remote node through a
//! socket. Local communication with coordinating threads is made via
//! `crossbeam_channel::unbounded()`.
use std::fmt::Debug;
use std::sync::Arc;
use crossbeam;
use crossbeam_channel as channel;

use proto::Message;
use task;
use messaging::{SourcedMessage};

/// A communication task connects a remote node to the thread that manages the
/// consensus algorithm.
pub struct CommsTask<'a, T: 'a + Clone + Debug + Send + Sync +
                     From<Vec<u8>> + Into<Vec<u8>>>
where Vec<u8>: From<T>
{
    /// The transmit side of the multiple producer channel from comms threads.
    tx: &'a channel::Sender<SourcedMessage<T>>,
    /// The receive side of the channel to the comms thread.
    rx: &'a channel::Receiver<Message<T>>,
    /// The socket IO task.
    task: task::Task,
    /// The index of this comms task for identification against its remote node.
    pub node_index: usize
}

impl<'a, T: Clone + Debug + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
    CommsTask<'a, T>
where Vec<u8>: From<T>
{
    pub fn new(tx: &'a channel::Sender<SourcedMessage<T>>,
               rx: &'a channel::Receiver<Message<T>>,
               stream: ::std::net::TcpStream,
               node_index: usize) ->
        Self
    {
        debug!("Creating comms task #{} for {:?}", node_index,
               stream.peer_addr().unwrap());

        CommsTask {
            tx: tx,
            rx: rx,
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
        let mut task1 = self.task.try_clone().unwrap(); // FIXME: handle errors
        let node_index = self.node_index;

        crossbeam::scope(|scope| {
            // Local comms receive loop thread.
            scope.spawn(move || {
                loop {
                    // Receive a multicast message from the manager thread.
                    let message = rx.recv().unwrap();
                    debug!("Node {} <- {:?}", node_index, message);
                    // Forward the message to the remote node.
                    task1.send_message(message).unwrap();
                }
            });

            // Remote comms receive loop.
            debug!("Starting remote RX loop for node {}", node_index);
            loop {
                match self.task.receive_message() {
                    Ok(message) => {
                        debug!("Node {} -> {:?}", node_index, message);
                        tx.send(
                            SourcedMessage {
                                source: node_index,
                                message
                            })
                            .unwrap()
                    },
                    Err(task::Error::ProtobufError(e)) =>
                        warn!("Node {} - Protobuf error {}", node_index, e),
                    Err(e) => {
                        warn!("Node {} - Critical error {:?}", node_index, e);
                        break;
                    }
                }
            }
        });
    }
}
