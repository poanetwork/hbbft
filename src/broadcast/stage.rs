//! Broadcast stage of the consensus algorithm.
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{channel, Sender};
use std::sync::Mutex;
use merkle::*;
use proto::*;

pub struct Stage<T> {
    /// Tx channels to communicate with all tasks.
    pub senders: Vec<Sender<Message<T>>>,
    /// Messages of type Value received so far, keyed with the root hash for
    /// easy access.
    pub values: Mutex<HashMap<Vec<u8>, Proof<T>>>,
    /// Messages of type Echo received so far, keyed with the root hash for
    /// easy access.
    pub echos: Mutex<HashMap<Vec<u8>, Proof<T>>>,
    /// Messages of type Ready received so far. That is, the root hashes in
    /// those messages.
    pub readys: Mutex<HashSet<Vec<u8>>>
}

impl<T> Stage<T> {
    pub fn new(senders: Vec<Sender<Message<T>>>) -> Self {
        Stage {
            senders: senders,
            values: Default::default(),
            echos: Default::default(),
            readys: Default::default()
        }
    }
}
