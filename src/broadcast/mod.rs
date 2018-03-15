//! Reliable broadcast algorithm.
use std::collections::{HashMap, HashSet};
use std::net::{TcpStream, TcpListener, SocketAddr};
use errors::ResultExt;
use task::{Error, MessageLoop, Task};
use proto::message::{MessageProto, ValueProto, EchoProto, ReadyProto};
use merkle::*;

/// A broadcast task is an instance of `Task`, a message-handling task with a
/// main loop.
pub struct BroadcastTask<T> {
    /// The underlying task that handles sending and receiving messages.
    task: Task,
    /// Messages of type Value received so far, keyed with the root hash for
    /// easy access.
    values: HashMap<Vec<u8>, Proof<T>>,
    /// Messages of type Echo received so far, keyed with the root hash for
    /// easy access.
    echos: HashMap<Vec<u8>, Proof<T>>,
    /// Messages of type Ready received so far. That is, the root hashes in
    /// those messages.
    readys: HashSet<Vec<u8>>
}

impl<T> BroadcastTask<T> {
    pub fn new(stream: TcpStream) -> Self {
        BroadcastTask {
            task: Task::new(stream),
            values: Default::default(),
            echos: Default::default(),
            readys: Default::default()
        }
    }
}

impl<T> MessageLoop for BroadcastTask<T> {
    fn run(&mut self) {
        loop {
            match self.task.receive_message() {
                Ok(message) => self.on_message_received(message).unwrap(),
                Err(Error::ProtobufError(e)) => warn!("Protobuf error {}", e),
                Err(e) => {
                    warn!("Critical error {:?}", e);
                    break;
                }
            }
        }
    }

    fn on_message_received(&mut self, message: MessageProto) -> Result<(), Error> {
        if message.has_broadcast() {
            let broadcast = message.get_broadcast();
            if broadcast.has_value() {
                let value = broadcast.get_value();
            }
            else if broadcast.has_echo() {
                let echo = broadcast.get_echo();
            }
            else if broadcast.has_ready() {
                let ready = broadcast.get_ready();
            }
            return Ok(());
        }
        else {
            warn!("Unexpected message type");
            return Err(Error::ProtocolError);
        }
    }
}
