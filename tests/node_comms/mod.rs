//! Simulated comms task structure. A simulated comms task communicates with a
//! simulated remote node through a channel. Local communication with
//! coordinating threads is also made via a channel.

use std::io;
use std::fmt::Debug;
use std::sync::Arc;
use crossbeam::{Scope, ScopedJoinHandle};
use crossbeam_channel::{Sender, Receiver};

use hbbft::proto::Message;
use hbbft::messaging::SourcedMessage;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error { Error::IoError(err) }
}

/// A communication task connects a remote node to the thread that manages the
/// consensus algorithm.
pub struct CommsTask
    <'a, T: 'a + Clone + Debug + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
{
    /// The transmit side of the multiple producer channel from comms threads.
    tx: &'a Sender<SourcedMessage<T>>,
    /// The receive side of the channel to the comms thread.
    rx: &'a Receiver<Message<T>>,
    /// TX to the remote node.
    remote_tx: &'a Sender<Message<T>>,
    /// RX from the remote node.
    remote_rx: &'a Receiver<Message<T>>,
    /// The index of this comms task for identification against its remote node.
    pub node_index: usize
}

impl <'a, T: 'a + Clone + Debug + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
    CommsTask<'a, T>
{
    pub fn new(tx: &'a Sender<SourcedMessage<T>>,
               rx: &'a Receiver<Message<T>>,
               remote_tx: &'a Sender<Message<T>>,
               remote_rx: &'a Receiver<Message<T>>,
               node_index: usize) ->
        Self
    {
        CommsTask {
            tx: tx,
            rx: rx,
            remote_tx: remote_tx,
            remote_rx: remote_rx,
            node_index: node_index
        }
    }

    /// The main socket IO loop and an asynchronous thread responding to manager
    /// thread requests.
    pub fn spawn(&mut self, scope: &Scope<'a>) -> ScopedJoinHandle<()> {
        // Borrow parts of `self` before entering the thread binding scope.
        let tx = Arc::new(self.tx);
        let rx = Arc::new(self.rx);
        let remote_tx = Arc::new(self.remote_tx);
        let remote_rx = Arc::new(self.remote_rx);
        let node_index = self.node_index;

        scope.spawn(move || {
            // FIXME: refactor to a while loop with clean termination
            loop { select_loop! {
                recv(rx, message) => {
                    println!("Node {} <- {:?}", node_index, message);
                    // Forward the message to the remote node.
                    remote_tx.send(message).map_err(|e| {
                        error!("{}", e);
                    }).unwrap();
                },
                recv(remote_rx, message) => {
                    println!("Node {} -> {:?}", node_index, message);
                    tx.send(SourcedMessage {
                        source: node_index,
                        message
                    }).map_err(|e| {
                        error!("{}", e);
                    }).unwrap();
                }
            }}
        })
    }
}
