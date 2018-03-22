//! Reliable broadcast algorithm.
use std::fmt::Debug;
use std::hash::Hash;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use spmc;
use crossbeam;
use proto::*;
use std::marker::{Send, Sync};
use merkle::*;
use reed_solomon_erasure::*;

// Temporary placeholders for the number of participants and the maximum
// envisaged number of faulty nodes. Only one is required since N >= 3f +
// 1. There are at least two options for where should N and f come from:
//
// - start-up parameters
//
// - initial socket setup phase in node.rs
//
const PLACEHOLDER_N: usize = 10;
const PLACEHOLDER_F: usize = 3;

pub struct Stage<T: Send + Sync> {
    /// The transmit side of the multiple consumer channel to comms threads.
    pub tx: Arc<Mutex<spmc::Sender<Message<T>>>>,
    /// The receive side of the multiple producer channel from comms threads.
    pub rx: Arc<Mutex<mpsc::Receiver<Message<T>>>>,
    /// Messages of type Value received so far.
    pub values: HashSet<Proof<T>>,
    /// Messages of type Echo received so far.
    pub echos: HashSet<Proof<T>>,
    /// Messages of type Ready received so far. That is, the root hashes in
    /// those messages.
    pub readys: HashSet<Vec<u8>>
}

impl<T: Clone + Debug + Eq + Hash + Send + Sync + Into<Vec<u8>>> Stage<T> {
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
    pub fn run(&mut self) -> Result<Vec<T>, ()> {
        // Manager thread.
        //
        // rx cannot be cloned due to its type constraint but can be used
        // inside a thread with the help of an `Arc` (`Rc` wouldn't
        // work for the same reason).
        let rx = self.rx.clone();
        let tx = self.tx.clone();
        let values = Arc::new(Mutex::new(self.values.to_owned()));
        let echos = Arc::new(Mutex::new(self.echos.to_owned()));
        crossbeam::scope(|scope| {
            scope.spawn(move || {
                inner_run(tx, rx, values, echos);
            });
        });
        // TODO
        Err(())
    }
}

fn inner_run<T>(tx: Arc<Mutex<spmc::Sender<Message<T>>>>,
                rx: Arc<Mutex<mpsc::Receiver<Message<T>>>>,
                values: Arc<Mutex<HashSet<Proof<T>>>>,
                echos: Arc<Mutex<HashSet<Proof<T>>>>)
where T: Clone + Debug + Eq + Hash + Send + Sync + Into<Vec<u8>>
{
    // TODO: handle exit conditions
    loop {
        // Receive a message from the socket IO task.
        let message = rx.lock().unwrap().recv().unwrap();
        if let Message::Broadcast(message) = message {
            match message {
                // A value received. Record the value and multicast an echo.
                //
                // TODO: determine if the paper treats multicast as reflexive and
                // add an echo to this node if it does.
                BroadcastMessage::Value(p) => {
                    values.lock().unwrap().insert(p.clone());
                    tx.lock().unwrap()
                        .send(Message::Broadcast(
                            BroadcastMessage::Echo(p)))
                        .unwrap()
                },

                // An echo received. Verify the proof it contains.
                BroadcastMessage::Echo(p) => {
                    let root_hash = p.root_hash.clone();
                    //let echos = echos.lock().unwrap();
                    if p.validate(root_hash.as_slice()) {
                        echos.lock().unwrap().insert(p.clone());

                        // Upon receiving valid echos for the same root hash
                        // from N - f distinct parties, try to interpolate the
                        // Merkle tree.
                        //
                        // TODO: eliminate this iteration
                        let mut parties = 0;
                        for echo in echos.lock().unwrap().iter() {
                            if echo.root_hash == root_hash {
                                parties += 1;
                            }
                        }

                        if parties >= PLACEHOLDER_N - PLACEHOLDER_F {
                            // Try to interpolate the Merkle tree using the
                            // Reed-Solomon erasure coding scheme
                            //
                            // TODO: indicate the missing leaves with None

                            let mut leaves: Vec<Option<Box<[u8]>>> = Vec::new();
                            // TODO: optimise this loop out as well
                            for echo in
                                echos.lock().unwrap().iter()
                            {
                                if echo.root_hash == root_hash {
                                    leaves.push(Some(
                                        (Box::from(echo.value.clone().into()))));
                                }
                            }
                            let coding = ReedSolomon::new(
                                PLACEHOLDER_N - 2 * PLACEHOLDER_F,
                                2 * PLACEHOLDER_F).unwrap();
                            coding.reconstruct_shards(leaves.as_mut_slice())
                                .unwrap();
                        }
                        // TODO
                    }
                },
                _ => unimplemented!()
            }
        }
        else {
            error!("Incorrect message from the socket: {:?}",
                   message);
        }
    }
}
