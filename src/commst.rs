//! Comms task structure. A comms task communicates with a remote node through a
//! socket. Local communication with coordinating threads is made via
//! `crossbeam_channel::unbounded()`.
use std::io;
use std::fmt::Debug;
use std::sync::Arc;
use std::net::TcpStream;
use crossbeam;
use crossbeam_channel::{Sender, Receiver};

use proto::Message;
use proto_io;
use proto_io::CodecIo;
use messaging::SourcedMessage;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error { Error::IoError(err) }
}

/// A communication task connects a remote node to the thread that manages the
/// consensus algorithm.
pub struct CommsTask<'a, T: 'a + Clone + Debug + Send + Sync +
                     From<Vec<u8>> + Into<Vec<u8>>>
where Vec<u8>: From<T>
{
    /// The transmit side of the multiple producer channel from comms threads.
    tx: &'a Sender<SourcedMessage<T>>,
    /// The receive side of the channel to the comms thread.
    rx: &'a Receiver<Message<T>>,
    /// The socket IO task.
    io: CodecIo,
    /// The index of this comms task for identification against its remote node.
    pub node_index: usize
}

impl<'a, T: Clone + Debug + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
    CommsTask<'a, T>
where Vec<u8>: From<T>
{
    pub fn new(tx: &'a Sender<SourcedMessage<T>>,
               rx: &'a Receiver<Message<T>>,
               stream: TcpStream,
               node_index: usize) ->
        Self
    {
        debug!("Creating comms task #{} for {:?}", node_index,
               stream.peer_addr().unwrap());

        CommsTask {
            tx: tx,
            rx: rx,
            io: CodecIo::new(stream),
            node_index: node_index
        }
    }

    /// The main socket IO loop and an asynchronous thread responding to manager
    /// thread requests.
    pub fn run(&mut self) -> Result<(), Error> {
        // Borrow parts of `self` before entering the thread binding scope.
        let tx = Arc::new(self.tx);
        let rx = Arc::new(self.rx);
        let mut io1 = self.io.try_clone()?;
        let node_index = self.node_index;

        crossbeam::scope(|scope| {
            // Local comms receive loop thread.
            scope.spawn(move || {
                loop {
                    // Receive a multicast message from the manager thread.
                    let message = rx.recv().unwrap();
                    debug!("Node {} <- {:?}", node_index, message);
                    // Forward the message to the remote node.
                    io1.send_message(message).unwrap();
                }
            });

            // Remote comms receive loop.
            debug!("Starting remote RX loop for node {}", node_index);
            loop {
                match self.io.receive_message() {
                    Ok(message) => {
                        debug!("Node {} -> {:?}", node_index, message);
                        tx.send(
                            SourcedMessage {
                                source: node_index,
                                message
                            }).unwrap();
                    },
                    Err(proto_io::Error::ProtobufError(e)) =>
                        warn!("Node {} - Protobuf error {}", node_index, e),
                    Err(e) => {
                        warn!("Node {} - Critical error {:?}", node_index, e);
                        break;
                    }
                }
            }
        });
        Ok(())
    }
}
