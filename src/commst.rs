//! Comms task structure. A comms task communicates with a remote node through a
//! socket. Local communication with coordinating threads is made via
//! `spmc::channel()` and `mpsc::channel()`.
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use crossbeam;
#[macro_use]
use crossbeam_channel as channel;

use proto::Message;
use task;

/// A communication task connects a remote node to the thread that manages the
/// consensus algorithm.
pub struct CommsTask<'a, 'b, 'c, T: 'a + 'c + Send + Sync +
                     From<Vec<u8>> + Into<Vec<u8>>>
where Vec<u8>: From<T>
{
    /// The transmit side of the multiple producer channel from comms threads.
    tx: &'a channel::Sender<Message<T>>,
    /// The receive side of the multiple consumer channel to comms threads.
    rx: &'a channel::Receiver<Message<T>>,
    /// The receive side of the private channel to the comms thread.
    rx_priv: &'c channel::Receiver<Message<T>>,
    /// The socket IO task.
    task: task::Task<'b>,
}

impl<'a, 'b, 'c, T: Debug + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>>
    CommsTask<'a, 'b, 'c, T>
where Vec<u8>: From<T>
{
    pub fn new(tx: &'a channel::Sender<Message<T>>,
               rx: &'a channel::Receiver<Message<T>>,
               rx_priv: &'c channel::Receiver<Message<T>>,
               stream: &'b ::std::net::TcpStream) -> Self {
        CommsTask {
            tx: tx,
            rx: rx,
            rx_priv: rx_priv,
            task: task::Task::new(stream)
        }
    }

    /// The main socket IO loop and an asynchronous thread responding to manager
    /// thread requests.
    pub fn run(&mut self) {
        // Borrow parts of `self` before entering the thread binding scope.
        let tx = Arc::new(self.tx);
        let rx = Arc::new(self.rx);
        let rx_priv = Arc::new(self.rx_priv);
        let task = Arc::new(Mutex::new(&mut self.task));

        crossbeam::scope(|scope| {
            // Make a further copy of `task` for the thread stack.
            let task1 = task.clone();

            // Local comms receive loop thread.
            scope.spawn(move || {
                // Unfolded application of `select_loop!`
                let mut sel = channel::Select::new();
                loop {
                    // Receive a multicast message from the manager thread.
                    if let Ok(message) = sel.recv(&rx) {
                        // Forward the message to the remote node.
                        task1.lock().unwrap().send_message(message).unwrap();
                        // Rule: If a selection case fires, the loop must be
                        // broken.
                        break;
                    }
                    // Receive a private message from the manager thread.
                    if let Ok(message) = sel.recv(&rx_priv) {
                        // Forward the message to the remote node.
                        task1.lock().unwrap().send_message(message).unwrap();
                        // Rule: If a selection case fires, the loop must be
                        // broken.
                        break;
                    }
                }
            });

            // Remote comms receive loop.
            loop {
                match task.lock().unwrap().receive_message() {
                    Ok(message) =>
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
}
