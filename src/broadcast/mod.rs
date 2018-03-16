//! Reliable broadcast algorithm.
use std::fmt::Debug;
use std::collections::{HashMap, HashSet};
use std::net::{TcpStream, TcpListener, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver};
//use errors::ResultExt;
use task::{Error, MessageLoop, Task};
use proto::*;
use std::marker::{Send, Sync};

pub mod stage;

use self::stage::*;

/// A broadcast task is an instance of `Task`, a message-handling task with a
/// main loop.
pub struct BroadcastTask<T: Send + Sync> {
    /// The underlying task that handles sending and receiving messages.
    task: Task,
    /// The receive end of the comms channel. The transmit end is stored in
    /// `stage`.
    receiver: Receiver<Message<T>>,
    /// Shared state of the broadcast stage.
    stage: Arc<Mutex<Stage<T>>>
}

impl<T: Clone + Debug + Send + Sync + 'static> BroadcastTask<T> {
    pub fn new(stream: TcpStream,
               receiver: Receiver<Message<T>>,
               stage: Arc<Mutex<Stage<T>>>) -> Self {
        BroadcastTask {
            task: Task::new(stream),
            receiver: receiver,
            stage: stage
        }
    }

    fn on_message_received(&mut self, message: Message<T>)
                           -> Result<(), Error>
    {
//        info!("Message received: {:?}", message);
        if let Message::Broadcast(b) = message {
            Ok(())
/*
            match b {
                BroadcastMessage::Value(proof) => {
                    self.stage.values.insert(proof.root_hash.clone(), proof.clone());
                    Ok(())
                },
                BroadcastMessage::Echo(proof) => {
                    self.echos.insert(proof.root_hash.clone(), proof.clone());
                    Ok(())
                },
                BroadcastMessage::Ready(root_hash) => {
                    self.readys.insert(root_hash);
                    Ok(())
                }
            }
*/
        }
        else {
            warn!("Unexpected message type");
            return Err(Error::ProtocolError);
        }
    }

    /// Receiver of messages from other broadcast tasks.
    ///
    /// TODO: This is only a placeholder.
    pub fn receiver_thread(&self) {
        ::std::thread::spawn(move || {
            loop {
                // let message = self.receiver.recv().unwrap();
                // info!("Task {:?} received message {:?}",
                //       self.task.stream.peer_addr().unwrap(),
                //       message);
            }
        });
    }
}

impl<T: Clone + Debug + From<Vec<u8>> + Send + Sync + 'static>
    MessageLoop for BroadcastTask<T> {
    fn run(&mut self) {
        self.receiver_thread();
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
        //interthread_receiver.join().unwrap();
    }
}
