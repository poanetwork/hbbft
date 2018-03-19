//! Comms task structure. A comms task communicates with a remote node through a
//! socket. Local communication with coordinating threads is made via
//! `spmc::channel()` and `mpsc::channel()`.
use std::fmt::Debug;
//use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::thread;
use spmc;
use proto::Message;
use task;

/// A communication task connects a remote node to the thread that manages the
/// consensus algorithm.
pub struct CommsTask<T: Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
where Vec<u8>: From<T>
{
    /// The transmit side of the multiple producer channel from comms threads.
    tx: mpsc::Sender<Message<T>>,
    /// The receive side of the multiple consumer channel to comms threads.
    rx: spmc::Receiver<Message<T>>,
    /// The socket IO task.
    task: task::Task
}

impl<T: Debug + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
    CommsTask<T>
where Vec<u8>: From<T>
{
    pub fn new(tx: mpsc::Sender<Message<T>>,
               rx: spmc::Receiver<Message<T>>,
               stream: ::std::net::TcpStream) -> Self {
        CommsTask {
            tx: tx,
            rx: rx,
            task: task::Task::new(stream)
        }
    }

    /// The main socket IO loop and an asynchronous thread responding to manager
    /// thread requests.
    pub fn run(&mut self) {
        // Local comms receive loop.
        let comms = thread::spawn(move || {
            loop {
                // Receive a message from the manager thread.
                let message = self.rx.recv().unwrap();
                // Forward the message to the remote node.
                self.task.send_message(message).unwrap();
            }
        });

        // Remote comms receive loop.
        loop {
            match self.task.receive_message() {
                Ok(message) => self.on_message_received(message),
                Err(task::Error::ProtobufError(e)) =>
                    warn!("Protobuf error {}", e),
                Err(e) => {
                    warn!("Critical error {:?}", e);
                    break;
                }
            }
        }

        comms.join().unwrap();
    }

    /// Handler of a received message.
    fn on_message_received(&mut self, message: Message<T>) {
        // Forward the message to the manager thread.
        self.tx.send(message).unwrap();
    }
}
