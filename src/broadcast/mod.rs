//! Reliable broadcast algorithm.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use spmc;
use std::thread;
use proto::*;
use std::marker::{Send, Sync};
use merkle::*;

pub struct Stage<T: Send + Sync> {
    /// The transmit side of the multiple consumer channel to comms threads.
    pub tx: Arc<Mutex<spmc::Sender<Message<T>>>>,
    /// The receive side of the multiple producer channel from comms threads.
    pub rx: Arc<Mutex<mpsc::Receiver<Message<T>>>>,
    /// Messages of type Value received so far, keyed with the root hash for
    /// easy access.
    pub values: HashMap<Vec<u8>, Proof<T>>,
    /// Messages of type Echo received so far, keyed with the root hash for
    /// easy access.
    pub echos: HashMap<Vec<u8>, Proof<T>>,
    /// Messages of type Ready received so far. That is, the root hashes in
    /// those messages.
    pub readys: HashSet<Vec<u8>>
}

impl<T: Send + Sync> Stage<T> {
    pub fn new(tx: Arc<Mutex<spmc::Sender<Message<T>>>>,
               rx: Arc<Mutex<mpsc::Receiver<Message<T>>>>) -> Self {
        Stage {
            tx: tx,
            rx: rx,
            values: Default::default(),
            echos: Default::default(),
            readys: Default::default()
        }
    }

    /// Broadcast stage main loop returning the computed values in case of
    /// success, and an error in case of failure.
    pub fn run(&self) -> Result<Vec<T>, ()> {
        let mut aborted = false;
        let mut decoded = false;

        // Manager thread. rx cannot be cloned due to its type constraint but
        // can be used inside a thread with the help of an `Arc` (`Rc` wouldn't
        // work for the same reason).
        let rx = Arc::new(Mutex::new(self.rx));
        let manager = thread::spawn(move || {
            while !aborted && !decoded {
                // TODO
            }
        });

        manager.join().unwrap();
        // TODO
        Err(())
    }
}
