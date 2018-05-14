//! Comms task structure. A comms task communicates with a remote node through a
//! socket. Local communication with coordinating threads is made via
//! `crossbeam_channel::unbounded()`.
use crossbeam;
use crossbeam_channel::{Receiver, Sender};
use std::io;
use std::net::TcpStream;

use hbbft::messaging::SourcedMessage;
use hbbft::proto_io::{self, ProtoIo};
use protobuf::Message;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

/// A communication task connects a remote node to the thread that manages the
/// consensus algorithm.
pub struct CommsTask<'a, P: 'a, M: 'a> {
    /// The transmit side of the multiple producer channel from comms threads.
    tx: &'a Sender<SourcedMessage<M, usize>>,
    /// The receive side of the channel to the comms thread.
    rx: &'a Receiver<M>,
    /// The socket IO task.
    io: ProtoIo<TcpStream, P>,
    /// The index of this comms task for identification against its remote node.
    pub node_index: usize,
}

impl<'a, P: Message + 'a, M: Into<P> + From<P> + Send + 'a> CommsTask<'a, P, M> {
    pub fn new(
        tx: &'a Sender<SourcedMessage<M, usize>>,
        rx: &'a Receiver<M>,
        stream: TcpStream,
        node_index: usize,
    ) -> Self {
        debug!(
            "Creating comms task #{} for {:?}",
            node_index,
            stream.peer_addr().unwrap()
        );

        CommsTask {
            tx,
            rx,
            io: ProtoIo::from_stream(stream),
            node_index,
        }
    }

    /// The main socket IO loop and an asynchronous thread responding to manager
    /// thread requests.
    pub fn run(mut self) -> Result<(), Error> {
        // Borrow parts of `self` before entering the thread binding scope.
        let tx = self.tx;
        let rx = self.rx;
        let mut io1 = self.io.try_clone()?;
        let node_index = self.node_index;

        crossbeam::scope(move |scope| {
            // Local comms receive loop thread.
            scope.spawn(move || {
                loop {
                    // Receive a multicast message from the manager thread.
                    let message = rx.recv().unwrap();
                    // Forward the message to the remote node.
                    io1.send(&message.into()).unwrap();
                }
            });

            // Remote comms receive loop.
            debug!("Starting remote RX loop for node {}", node_index);
            loop {
                match self.io.recv() {
                    Ok(message) => {
                        tx.send(SourcedMessage {
                            source: node_index,
                            message: message.into(),
                        }).unwrap();
                    }
                    Err(proto_io::Error::ProtobufError(e)) => {
                        warn!("Node {} - Protobuf error {}", node_index, e)
                    }
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
