//! Comms task structure. A comms task communicates with a remote node through a
//! socket. Local communication with coordinating threads is made via
//! `crossbeam_channel::unbounded()`.
use std::io;
use std::net::TcpStream;

use bincode;
use crossbeam;
use crossbeam_channel::{Receiver, Sender};
use log::{debug, info};
use serde::{de::DeserializeOwned, Serialize};

use hbbft::SourcedMessage;

/// A communication task connects a remote node to the thread that manages the
/// consensus algorithm.
pub struct CommsTask<'a, M> {
    /// The transmit side of the multiple producer channel from comms threads.
    tx: &'a Sender<SourcedMessage<M, usize>>,
    /// The receive side of the channel to the comms thread.
    rx: &'a Receiver<M>,
    /// The socket IO task.
    stream: TcpStream,
    /// The index of this comms task for identification against its remote node.
    pub node_index: usize,
}

impl<'a, M: Serialize + DeserializeOwned + Send + 'a> CommsTask<'a, M> {
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
            stream,
            node_index,
        }
    }

    /// The main socket IO loop and an asynchronous thread responding to manager
    /// thread requests.
    pub fn run(mut self) -> Result<(), Box<dyn std::any::Any + Send + 'static>> {
        // Borrow parts of `self` before entering the thread binding scope.
        let tx = self.tx;
        let rx = self.rx;
        let mut stream1 = match self.stream.try_clone() {
            Ok(stream) => stream,
            Err(e) => return Err(Box::new(e)),
        };
        let node_index = self.node_index;

        crossbeam::scope(move |scope| {
            // Local comms receive loop thread.
            scope.spawn(move |_| {
                loop {
                    // Receive a multicast message from the manager thread.
                    let message = rx.recv().unwrap();
                    // Forward the message to the remote node.
                    bincode::serialize_into(&mut stream1, &message)
                        .expect("message serialization failed");
                }
            });

            // Remote comms receive loop.
            debug!("Starting remote RX loop for node {}", node_index);
            loop {
                match bincode::deserialize_from(&mut self.stream) {
                    Ok(message) => {
                        tx.send(SourcedMessage {
                            source: node_index,
                            message,
                        })
                        .unwrap();
                    }
                    Err(err) => {
                        if let bincode::ErrorKind::Io(ref io_err) = *err {
                            if io_err.kind() == io::ErrorKind::UnexpectedEof {
                                info!("Node {} disconnected.", node_index);
                                break;
                            }
                        }
                        panic!("Node {} - Deserialization error {:?}", node_index, err);
                    }
                }
            }
        })
    }
}
