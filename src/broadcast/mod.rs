//! Reliable broadcast algorithm.
use std::fmt::Debug;
use std::hash::Hash;
use std::collections::{HashSet, HashMap};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use spmc;
use crossbeam;
use proto::*;
use std::marker::{Send, Sync};
use merkle::MerkleTree;
use merkle::proof::{Proof, Lemma, Positioned};
use reed_solomon_erasure::ReedSolomon;

/// Temporary placeholders for the number of participants and the maximum
/// envisaged number of faulty nodes. Only one is required since N >= 3f +
/// 1. There are at least two options for where should N and f come from:
///
/// - start-up parameters
///
/// - initial socket setup phase in node.rs
///
const PLACEHOLDER_N: usize = 8;
const PLACEHOLDER_F: usize = 2;

/// Broadcast stage. See the TODO note below!
///
/// TODO: The ACS algorithm will require multiple broadcast instances running
/// asynchronously, see Figure 4 in the HBBFT paper. So, it's likely that the
/// broadcast *stage* has to be replaced with N asynchronous threads, each
/// responding to values from one particular remote node. The paper doesn't make
/// it clear though how other messages - Echo and Ready - are distributed over
/// the instances. Also it appears that the sender of a message has to become
/// part of the message for this to work.
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
    pub readys: HashMap<Vec<u8>, usize>,
    /// Value to be broadcast
    pub broadcast_value: Option<T>
}

impl<T: Clone + Debug + Eq + Hash + Send + Sync + Into<Vec<u8>>
     + From<Vec<u8>> + AsRef<[u8]>>
    Stage<T>
where Vec<u8>: From<T>
{
    pub fn new(tx: Arc<Mutex<spmc::Sender<Message<T>>>>,
               rx: Arc<Mutex<mpsc::Receiver<Message<T>>>>,
               broadcast_value: Option<T>) -> Self
    {
        Stage {
            tx: tx,
            rx: rx,
            values: Default::default(),
            echos: Default::default(),
            readys: Default::default(),
            broadcast_value: broadcast_value
        }
    }

    /// Broadcast stage task returning the computed values in case of success,
    /// and an error in case of failure.
    ///
    /// TODO: Detailed error status.
    pub fn run(&mut self) -> Result<T, ()> {
        // Broadcast state machine thread.
        //
        // rx cannot be cloned due to its type constraint but can be used inside
        // a thread with the help of an `Arc` (`Rc` wouldn't work for the same
        // reason). A `Mutex` is used to grant write access.
        let rx = self.rx.to_owned();
        let tx = self.tx.to_owned();
        let values = Arc::new(Mutex::new(self.values.to_owned()));
        let echos = Arc::new(Mutex::new(self.echos.to_owned()));
        let readys = Arc::new(Mutex::new(self.readys.to_owned()));
        let final_value: Option<T> = None;
        let final_value_r = Arc::new(Mutex::new(None));
        let bvalue = self.broadcast_value.to_owned();

        crossbeam::scope(|scope| {
            scope.spawn(move || {
                *final_value_r.lock().unwrap() =
                    inner_run(tx, rx, values, echos, readys, bvalue);
            });
        });

        match final_value {
            None => Err(()),
            Some(v) => Ok(v)
        }
    }
}

/// The main loop of the broadcast task.
fn inner_run<T>(tx: Arc<Mutex<spmc::Sender<Message<T>>>>,
                rx: Arc<Mutex<mpsc::Receiver<Message<T>>>>,
                values: Arc<Mutex<HashSet<Proof<T>>>>,
                echos: Arc<Mutex<HashSet<Proof<T>>>>,
                readys: Arc<Mutex<HashMap<Vec<u8>, usize>>>,
                broadcast_value: Option<T>) -> Option<T>
where T: Clone + Debug + Eq + Hash + Send + Sync + Into<Vec<u8>>
    + From<Vec<u8>> + AsRef<[u8]>
    , Vec<u8>: From<T>
{
    // return value
    let reconstructed_value: Option<T> = None;
    // Ready sent flags
    let mut ready_sent: HashSet<Vec<u8>> = Default::default();
    // Erasure coding scheme: N - 2f value shards and 2f parity shards
    let parity_shard_num = 2 * PLACEHOLDER_F;
    let data_shard_num = PLACEHOLDER_N - parity_shard_num;
    let coding = ReedSolomon::new(data_shard_num, parity_shard_num).unwrap();

    // Split the value into chunks/shards, encode them with erasure codes.
    // Assemble a Merkle tree from data and parity shards. Take all proofs from
    // this tree and send them, each to its own node.
    //
    // FIXME: Does the node send a proof to itself?
    if let Some(v) = broadcast_value {
        let mut v: Vec<u8> = Vec::from(v).to_owned();

        // Pad the value vector with zeros to allow for shards of equal sizes.
        let shard_pad_len = v.len() % data_shard_num;
        for _i in 0..shard_pad_len {
            v.push(0);
        }
        // Size of a Merkle tree leaf value, in bytes.
        // Now the vector length is evenly divisible by the number of shards.
        let shard_len = v.len() / data_shard_num;
        // Pad the parity shards with zeros.
        for _i in 0 .. shard_len * parity_shard_num {
            v.push(0);
        }

        // Divide the vector into chunks/shards.
        let shards_iter = v.chunks_mut(shard_len);
        // Convert the iterator over slices into a vector of slices.
        let mut shards: Vec<&mut [u8]> = Vec::new();
        for s in shards_iter {
            shards.push(s);
        }

        // Construct the parity chunks/shards
        coding.encode(shards.as_mut_slice()).unwrap();

        // Convert shards back to type `T` for proof generation.
        let mut shards_T: Vec<T> = Vec::new();
        for s in shards.iter() {
            let s = Vec::into(s.to_vec());
            shards_T.push(s);
        }

        // Convert the Merkle tree into a partial binary tree for later
        // deconstruction into compound branches.
        let mtree = MerkleTree::from_vec(&::ring::digest::SHA256, shards_T);

        // Send each proof to a node.
        //
        // FIXME: use a single consumer TX channel.
        for leaf_value in mtree.iter().cloned() {
            let proof = mtree.gen_proof(leaf_value);
            if let Some(proof) = proof {
                tx.lock().unwrap().send(Message::Broadcast(
                    BroadcastMessage::Value(proof))).unwrap();
            }
        }
    }

    // TODO: handle exit conditions
    while reconstructed_value == None {
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
                        let mut echo_n = 0;
                        for echo in echos.lock().unwrap().iter() {
                            if echo.root_hash == root_hash {
                                echo_n += 1;
                            }
                        }

                        if echo_n >= PLACEHOLDER_N - PLACEHOLDER_F {
                            // Try to interpolate the Merkle tree using the
                            // Reed-Solomon erasure coding scheme.
                            //
                            // FIXME: indicate the missing leaves with None

                            let mut leaves: Vec<Option<Box<[u8]>>> = Vec::new();
                            // TODO: optimise this loop out as well
                            for echo in
                                echos.lock().unwrap().iter()
                            {
                                if echo.root_hash == root_hash {
                                    leaves.push(Some(
                                        Box::from(echo.value.clone().into())));
                                }
                            }
                            coding.reconstruct_shards(leaves.as_mut_slice())
                                .unwrap();

                            // FIXME: Recompute Merkle tree root.

                            // if Ready has not yet been sent, multicast Ready
                            if let None = ready_sent.get(&root_hash) {
                                ready_sent.insert(root_hash.clone());
                                tx.lock().unwrap().send(Message::Broadcast(
                                    BroadcastMessage::Ready(root_hash)))
                                    .unwrap();
                            }
                        }
                    }
                },

                BroadcastMessage::Ready(ref h) => {
                    // Number of times Ready(h) was received.
                    let ready_n;
                    if let Some(n) = readys.lock().unwrap().get_mut(h) {
                        *n = *n + 1;
                        ready_n = *n;
                    }
                    else {
                        //
                        readys.lock().unwrap().insert(h.clone(), 1);
                        ready_n = 1;
                    }

                    // Upon receiving f + 1 matching Ready(h) messages, if Ready
                    // has not yet been sent, multicast Ready(h).
                    if (ready_n == PLACEHOLDER_F + 1) &&
                        (ready_sent.get(h) == None)
                    {
                        tx.lock().unwrap().send(Message::Broadcast(
                            BroadcastMessage::Ready(h.to_vec()))).unwrap();
                    }

                    // Upon receiving 2f + 1 matching Ready(h) messages, wait
                    // for N − 2f Echo messages, then decode v.
                    if (ready_n > 2 * PLACEHOLDER_F) &&
                        (reconstructed_value == None) &&
                        (echos.lock().unwrap().len() >=
                         PLACEHOLDER_N - 2 * PLACEHOLDER_F)
                    {
                        // FIXME: decode v
                    }
                }
            }
        }
        else {
            error!("Incorrect message from the socket: {:?}",
                   message);
        }
    }
    return reconstructed_value;
}

/// An additional path conversion operation on `Lemma` to allow reconstruction
/// of erasure-coded `Proof` from `Lemma`s. The output path, when read from left
/// to right, goes from leaf to root (LSB order).
pub fn lemma_to_path(lemma: &Lemma) -> Vec<bool> {
    match lemma.sub_lemma {
        None => {
            match lemma.sibling_hash {
                // lemma terminates with no leaf
                None => vec![],
                // the leaf is on the right
                Some(Positioned::Left(_)) => vec![true],
                // the leaf is on the left
                Some(Positioned::Right(_)) => vec![false],
            }
        }
        Some(ref l) => {
            let mut p = lemma_to_path(l.as_ref());

            match lemma.sibling_hash {
                // lemma terminates
                None => (),
                // lemma branches out to the right
                Some(Positioned::Left(_)) => p.push(true),
                // lemma branches out to the left
                Some(Positioned::Right(_)) => p.push(false),
            }
            p
        }
    }
}

/// Further conversion of a binary tree path into an array index.
pub fn path_to_index(mut path: Vec<bool>) -> usize {
    let mut idx = 0;
    // Convert to the MSB order.
    path.reverse();

    for &dir in path.iter() {
        if dir == false {
            idx = idx << 1;
        }
        else {
            idx = (idx << 1) | 1;
        }
    }
    idx
}
