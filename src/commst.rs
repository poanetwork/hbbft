//! Comms task structure. A comms task communicates with a remote node through a
//! socket. Local communication with coordinating threads is made via
//! `spmc::channel()` and `mpsc::channel()`.
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use spmc;
use crossbeam;

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
        // Borrow parts of `self` before entering the thread binding scope.
        let tx = Arc::new(&self.tx);
        let rx = Arc::new(&self.rx);
        let task = Arc::new(Mutex::new(&mut self.task));

        crossbeam::scope(|scope| {
            // Make a further copy of `task` for the thread stack.
            let task1 = task.clone();

            // Local comms receive loop thread.
            scope.spawn(move || {
                loop {
                    // Receive a message from the manager thread.
                    let message = rx.recv().unwrap();
                    // Forward the message to the remote node.
                    task1.lock().unwrap().send_message(message).unwrap();
                }
            });

            // Remote comms receive loop.
            loop {
                match task.lock().unwrap().receive_message() {
                    Ok(message) => // self.on_message_received(message),
                        tx.send(message).unwrap(),
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

    /// Handler of a received message.
    fn on_message_received(&mut self, message: Message<T>) {
        // Forward the message to the manager thread.
        self.tx.send(message).unwrap();
    }
}
