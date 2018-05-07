//! Reliable broadcast algorithm instance.
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::iter;
use std::marker::{Send, Sync};
use std::sync::{RwLock, RwLockWriteGuard};

use crossbeam_channel::{Receiver, RecvError, Sender, SendError};
use merkle::{Hashable, MerkleTree};
use merkle::proof::{Lemma, Positioned, Proof};
use reed_solomon_erasure::{self as rse, ReedSolomon};

use messaging::{SourcedMessage, Target, TargetedMessage};
use proto::{BroadcastMessage, HexBytes, Message};

// TODO: Make this a generic argument of `Broadcast`.
type ProposedValue = Vec<u8>;

type MessageQueue<NodeUid> = VecDeque<TargetedBroadcastMessage<NodeUid>>;

/// A `BroadcastMessage` to be sent out, together with a target.
#[derive(Clone, Debug)]
pub struct TargetedBroadcastMessage<NodeUid> {
    pub target: BroadcastTarget<NodeUid>,
    pub message: BroadcastMessage<ProposedValue>,
}

impl TargetedBroadcastMessage<usize> {
    pub fn into_targeted_message(self) -> TargetedMessage<ProposedValue> {
        TargetedMessage {
            target: match self.target {
                BroadcastTarget::All => Target::All,
                BroadcastTarget::Node(node) => Target::Node(node),
            },
            message: Message::Broadcast(self.message),
        }
    }
}

/// A target node for a `BroadcastMessage`.
#[derive(Clone, Debug)]
pub enum BroadcastTarget<NodeUid> {
    All,
    Node(NodeUid),
}

struct BroadcastState {
    root_hash: Option<Vec<u8>>,
    leaf_values: Vec<Option<Box<[u8]>>>,
    leaf_values_num: usize,
    echo_num: usize,
    readys: HashMap<Vec<u8>, usize>,
    ready_sent: bool,
    ready_to_decode: bool,
    has_output: bool,
}

/// Reliable Broadcast algorithm instance.
pub struct Broadcast<NodeUid: Eq + Hash> {
    /// The UID of this node.
    our_id: NodeUid,
    /// The UID of the sending node.
    proposer_id: NodeUid,
    /// UIDs of all nodes for iteration purposes.
    all_uids: HashSet<NodeUid>,
    num_nodes: usize,
    num_faulty_nodes: usize,
    data_shard_num: usize,
    coding: ReedSolomon,
    /// All the mutable state is confined to the `state` field. This allows to
    /// mutate state even when the broadcast instance is referred to by an
    /// immutable reference.
    state: RwLock<BroadcastState>,
}

impl<NodeUid: Eq + Hash + Debug + Clone> Broadcast<NodeUid> {
    /// Creates a new broadcast instance to be used by node `our_id` which expects a value proposal
    /// from node `proposer_id`.
    pub fn new(
        our_id: NodeUid,
        proposer_id: NodeUid,
        all_uids: HashSet<NodeUid>,
    ) -> Result<Self, Error> {
        let num_nodes = all_uids.len();
        let num_faulty_nodes = (num_nodes - 1) / 3;
        let parity_shard_num = 2 * num_faulty_nodes;
        let data_shard_num = num_nodes - parity_shard_num;
        let coding = ReedSolomon::new(data_shard_num, parity_shard_num)?;

        Ok(Broadcast {
            our_id,
            proposer_id,
            all_uids,
            num_nodes,
            num_faulty_nodes,
            data_shard_num,
            coding,
            state: RwLock::new(BroadcastState {
                root_hash: None,
                leaf_values: vec![None; num_nodes],
                leaf_values_num: 0,
                echo_num: 0,
                readys: HashMap::new(),
                ready_sent: false,
                ready_to_decode: false,
                has_output: false,
            }),
        })
    }

    /// Processes the proposed value input by broadcasting it.
    pub fn propose_value(&self, value: ProposedValue) -> Result<MessageQueue<NodeUid>, Error> {
        if self.our_id != self.proposer_id {
            return Err(Error::UnexpectedMessage);
        }
        let mut state = self.state.write().unwrap();
        // Split the value into chunks/shards, encode them with erasure codes.
        // Assemble a Merkle tree from data and parity shards. Take all proofs
        // from this tree and send them, each to its own node.
        self.send_shards(value).map(|(proof, remote_messages)| {
            // Record the first proof as if it were sent by the node to itself.
            let h = proof.root_hash.clone();
            // Save the leaf value for reconstructing the tree later.
            state.leaf_values[index_of_proof(&proof)] =
                Some(proof.value.clone().into_boxed_slice());
            state.leaf_values_num += 1;
            state.root_hash = Some(h);

            remote_messages
        })
    }

    pub fn our_id(&self) -> &NodeUid {
        &self.our_id
    }

    /// Breaks the input value into shards of equal length and encodes them --
    /// and some extra parity shards -- with a Reed-Solomon erasure coding
    /// scheme. The returned value contains the shard assigned to this
    /// node. That shard doesn't need to be sent anywhere. It gets recorded in
    /// the broadcast instance.
    fn send_shards(
        &self,
        mut value: ProposedValue,
    ) -> Result<(Proof<ProposedValue>, MessageQueue<NodeUid>), Error> {
        let data_shard_num = self.coding.data_shard_count();
        let parity_shard_num = self.coding.parity_shard_count();

        debug!(
            "Data shards: {}, parity shards: {}",
            self.data_shard_num, parity_shard_num
        );
        // Insert the length of `v` so it can be decoded without the padding.
        let payload_len = value.len() as u8;
        value.insert(0, payload_len); // TODO: Handle messages larger than 255 bytes.
        let value_len = value.len();
        // Size of a Merkle tree leaf value, in bytes.
        let shard_len = if value_len % data_shard_num > 0 {
            value_len / data_shard_num + 1
        } else {
            value_len / data_shard_num
        };
        // Pad the last data shard with zeros. Fill the parity shards with
        // zeros.
        value.resize(shard_len * (data_shard_num + parity_shard_num), 0);

        debug!("value_len {}, shard_len {}", value_len, shard_len);

        // Divide the vector into chunks/shards.
        let shards_iter = value.chunks_mut(shard_len);
        // Convert the iterator over slices into a vector of slices.
        let mut shards: Vec<&mut [u8]> = shards_iter.collect();

        debug!("Shards before encoding: {:?}", shards);

        // Construct the parity chunks/shards
        self.coding.encode(&mut shards)?;

        debug!("Shards: {:?}", shards);

        let shards_t: Vec<ProposedValue> = shards.into_iter().map(|s| s.to_vec()).collect();

        // Convert the Merkle tree into a partial binary tree for later
        // deconstruction into compound branches.
        let mtree = MerkleTree::from_vec(&::ring::digest::SHA256, shards_t);

        // Default result in case of `gen_proof` error.
        let mut result = Err(Error::ProofConstructionFailed);
        let mut outgoing = VecDeque::new();

        // Send each proof to a node.
        // TODO: This generates the wrong proof if a leaf occurs more than once. Consider using the
        // `merkle_light` crate instead.
        for (leaf_value, uid) in mtree.iter().zip(self.all_uids.clone()) {
            let proof = mtree
                .gen_proof(leaf_value.to_vec())
                .ok_or(Error::ProofConstructionFailed)?;
            if uid == self.our_id {
                // The proof is addressed to this node.
                result = Ok(proof);
            } else {
                // Rest of the proofs are sent to remote nodes.
                outgoing.push_back(TargetedBroadcastMessage {
                    target: BroadcastTarget::Node(uid),
                    message: BroadcastMessage::Value(proof),
                });
            }
        }

        result.map(|r| (r, outgoing))
    }

    /// Handler of messages received from remote nodes.
    pub fn handle_broadcast_message(
        &self,
        sender_id: &NodeUid,
        message: BroadcastMessage<ProposedValue>,
    ) -> Result<(Option<ProposedValue>, MessageQueue<NodeUid>), Error> {
        let state = self.state.write().unwrap();
        match message {
            BroadcastMessage::Value(p) => self.handle_value(sender_id, p, state),
            BroadcastMessage::Echo(p) => self.handle_echo(p, state),
            BroadcastMessage::Ready(hash) => self.handle_ready(hash, state),
        }
    }

    /// Handles a received echo and verifies the proof it contains.
    fn handle_value(
        &self,
        sender_id: &NodeUid,
        p: Proof<ProposedValue>,
        mut state: RwLockWriteGuard<BroadcastState>,
    ) -> Result<(Option<ProposedValue>, MessageQueue<NodeUid>), Error> {
        if *sender_id != self.proposer_id {
            return Ok((None, VecDeque::new()));
        }
        // Initialize the root hash if not already initialised.
        if state.root_hash.is_none() {
            state.root_hash = Some(p.root_hash.clone());
            debug!(
                "Node {:?} Value root hash {:?}",
                self.our_id,
                HexBytes(&p.root_hash)
            );
        }

        if state.root_hash.as_ref().map_or(false, |h| p.validate(h)) {
            // TODO: Should messages failing this be echoed at all?
            // Save the leaf value for reconstructing the tree later.
            let idx = index_of_proof(&p);
            state.leaf_values[idx] = Some(p.value.clone().into_boxed_slice());
            state.leaf_values_num += 1;
        }

        // Enqueue a broadcast of an echo of this proof.
        let msgs = VecDeque::from(vec![TargetedBroadcastMessage {
            target: BroadcastTarget::All,
            message: BroadcastMessage::Echo(p.clone()),
        }]);
        let (output, echo_msgs) = self.handle_echo(p, state)?;
        Ok((output, msgs.into_iter().chain(echo_msgs).collect()))
    }

    /// Handles a received echo and verifies the proof it contains.
    fn handle_echo(
        &self,
        p: Proof<ProposedValue>,
        mut state: RwLockWriteGuard<BroadcastState>,
    ) -> Result<(Option<ProposedValue>, MessageQueue<NodeUid>), Error> {
        if state.root_hash.is_none() {
            state.root_hash = Some(p.root_hash.clone());
            debug!(
                "Node {:?} Echo root hash {:?}",
                self.our_id, state.root_hash
            );
        }

        // Call validate with the root hash as argument.
        let h = if let Some(h) = state.root_hash.clone() {
            h
        } else {
            error!("Broadcast/{:?} root hash not initialised", self.our_id);
            return Ok((None, VecDeque::new()));
        };

        if !p.validate(h.as_slice()) {
            debug!("Broadcast/{:?} cannot validate Echo {:?}", self.our_id, p);
            return Ok((None, VecDeque::new()));
        }

        state.echo_num += 1;
        // Save the leaf value for reconstructing the tree later.
        let idx = index_of_proof(&p);
        state.leaf_values[idx] = Some(p.value.into_boxed_slice());
        state.leaf_values_num += 1;

        // Upon receiving 2f + 1 matching READY(h)
        // messages, wait for N − 2 f ECHO messages,
        // then decode v. Return the decoded v to ACS.
        if state.leaf_values_num < self.num_nodes - self.num_faulty_nodes {
            return Ok((None, VecDeque::new()));
        }

        // TODO: Only decode once. Don't repeat for every ECHO message.
        let value = decode_from_shards(
            &mut state.leaf_values,
            &self.coding,
            self.data_shard_num,
            &h,
        )?;

        if state.ready_to_decode && !state.has_output {
            state.has_output = true;
            return Ok((Some(value), VecDeque::new()));
        }

        // if Ready has not yet been sent, multicast Ready
        if state.ready_sent {
            return Ok((None, VecDeque::new()));
        }

        state.ready_sent = true;
        let msg = TargetedBroadcastMessage {
            target: BroadcastTarget::All,
            message: BroadcastMessage::Ready(h.clone()),
        };
        let (output, ready_msgs) = self.handle_ready(h, state)?;
        Ok((output, iter::once(msg).chain(ready_msgs).collect()))
    }

    fn handle_ready(
        &self,
        hash: Vec<u8>,
        mut state: RwLockWriteGuard<BroadcastState>,
    ) -> Result<(Option<ProposedValue>, MessageQueue<NodeUid>), Error> {
        // Update the number Ready has been received with this hash.
        // TODO: Don't accept multiple ready messages from the same node.
        *state.readys.entry(hash).or_insert(1) += 1;

        // Check that the root hash matches.
        let h = if let Some(h) = state.root_hash.clone() {
            h
        } else {
            return Ok((None, VecDeque::new()));
        };

        let ready_num = *state.readys.get(&h).unwrap_or(&0);
        let mut outgoing = VecDeque::new();

        // Upon receiving f + 1 matching Ready(h) messages, if Ready
        // has not yet been sent, multicast Ready(h).
        if (ready_num == self.num_faulty_nodes + 1) && !state.ready_sent {
            // Enqueue a broadcast of a ready message.
            outgoing.push_back(TargetedBroadcastMessage {
                target: BroadcastTarget::All,
                message: BroadcastMessage::Ready(h.to_vec()),
            });
        }

        let mut output = None;

        // Upon receiving 2f + 1 matching Ready(h) messages, wait
        // for N − 2f Echo messages, then decode v.
        if ready_num > 2 * self.num_faulty_nodes {
            // Wait for N - 2f Echo messages, then decode v.
            if state.echo_num >= self.num_nodes - 2 * self.num_faulty_nodes {
                let value = decode_from_shards(
                    &mut state.leaf_values,
                    &self.coding,
                    self.data_shard_num,
                    &h,
                )?;

                if !state.has_output {
                    output = Some(value);
                    state.has_output = true;
                }
            } else {
                state.ready_to_decode = true;
            }
        }

        Ok((output, outgoing))
    }
}

/// Broadcast algorithm instance.
///
/// The ACS algorithm requires multiple broadcast instances running
/// asynchronously, see Figure 4 in the HBBFT paper. Those are N asynchronous
/// coroutines, each responding to values from one particular remote node. The
/// paper doesn't make it clear though how other messages - Echo and Ready - are
/// distributed over the instances. Also it appears that the sender of a message
/// might become part of the message for this to work.
pub struct Instance<'a, T: 'a + Clone + Debug + Send + Sync> {
    /// The transmit side of the channel to comms threads.
    tx: &'a Sender<TargetedMessage<ProposedValue>>,
    /// The receive side of the channel from comms threads.
    rx: &'a Receiver<SourcedMessage<ProposedValue>>,
    /// The broadcast algorithm instance.
    broadcast: Broadcast<usize>,
    /// Value to be broadcast.
    broadcast_value: Option<T>,
}

impl<'a, T: Clone + Debug + Hashable + Send + Sync + Into<Vec<u8>> + From<Vec<u8>>>
    Instance<'a, T>
{
    pub fn new(
        tx: &'a Sender<TargetedMessage<ProposedValue>>,
        rx: &'a Receiver<SourcedMessage<ProposedValue>>,
        broadcast_value: Option<T>,
        num_nodes: usize,
        proposer_index: usize,
    ) -> Self {
        let all_indexes = (0..num_nodes).collect();
        let broadcast = Broadcast::new(0, proposer_index, all_indexes)
            .expect("failed to instantiate broadcast");
        Instance {
            tx,
            rx,
            broadcast,
            broadcast_value,
        }
    }

    /// Broadcast stage task returning the computed values in case of success,
    /// and an error in case of failure.
    pub fn run(self) -> Result<T, Error> {
        // Broadcast state machine thread.
        let bvalue: Option<ProposedValue> = self.broadcast_value.map(|v| v.into());
        inner_run(self.tx, self.rx, bvalue, &self.broadcast).map(ProposedValue::into)
    }
}

/// Errors returned by the broadcast instance.
#[derive(Debug, Clone)]
pub enum Error {
    RootHashMismatch,
    Threading,
    ProofConstructionFailed,
    ReedSolomon(rse::Error),
    SendDeprecated(SendError<TargetedMessage<ProposedValue>>),
    Recv(RecvError),
    UnexpectedMessage,
    NotImplemented,
}

impl From<rse::Error> for Error {
    fn from(err: rse::Error) -> Error {
        Error::ReedSolomon(err)
    }
}

impl From<SendError<TargetedMessage<ProposedValue>>> for Error {
    fn from(err: SendError<TargetedMessage<ProposedValue>>) -> Error {
        Error::SendDeprecated(err)
    }
}

impl From<RecvError> for Error {
    fn from(err: RecvError) -> Error {
        Error::Recv(err)
    }
}

/// The main loop of the broadcast task.
fn inner_run<'a>(
    tx: &'a Sender<TargetedMessage<ProposedValue>>,
    rx: &'a Receiver<SourcedMessage<ProposedValue>>,
    broadcast_value: Option<ProposedValue>,
    broadcast: &Broadcast<usize>,
) -> Result<ProposedValue, Error> {
    if let Some(v) = broadcast_value {
        for msg in broadcast
            .propose_value(v)?
            .into_iter()
            .map(TargetedBroadcastMessage::into_targeted_message)
        {
            tx.send(msg)?;
        }
    }

    // TODO: handle exit conditions
    loop {
        // Receive a message from the socket IO task.
        let message = rx.recv()?;
        if let SourcedMessage {
            source: i,
            message: Message::Broadcast(message),
        } = message
        {
            let (opt_output, msgs) = broadcast.handle_broadcast_message(&i, message)?;
            for msg in msgs.into_iter()
                .map(TargetedBroadcastMessage::into_targeted_message)
            {
                tx.send(msg)?;
            }
            if let Some(output) = opt_output {
                return Ok(output);
            }
        } else {
            error!("Incorrect message from the socket: {:?}", message);
        }
    }
}

fn decode_from_shards<T>(
    leaf_values: &mut [Option<Box<[u8]>>],
    coding: &ReedSolomon,
    data_shard_num: usize,
    root_hash: &[u8],
) -> Result<T, Error>
where
    T: Clone + Debug + Hashable + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>,
{
    // Try to interpolate the Merkle tree using the Reed-Solomon erasure coding scheme.
    coding.reconstruct_shards(leaf_values)?;

    // Recompute the Merkle tree root.

    // Collect shards for tree construction.
    let shards: Vec<ProposedValue> = leaf_values
        .iter()
        .filter_map(|l| l.as_ref().map(|v| v.to_vec()))
        .collect();
    // Construct the Merkle tree.
    let mtree = MerkleTree::from_vec(&::ring::digest::SHA256, shards);
    // If the root hash of the reconstructed tree does not match the one
    // received with proofs then abort.
    if &mtree.root_hash()[..] != root_hash {
        // NOTE: The paper does not define the meaning of *abort*. But it is
        // sensible not to continue trying to reconstruct the tree after this
        // point. This instance must have received incorrect shards.
        Err(Error::RootHashMismatch)
    } else {
        // Reconstruct the value from the data shards.
        Ok(glue_shards(mtree, data_shard_num))
    }
}

/// Concatenates the first `n` leaf values of a Merkle tree `m` in one value of
/// type `T`. This is useful for reconstructing the data value held in the tree
/// and forgetting the leaves that contain parity information.
fn glue_shards<T>(m: MerkleTree<ProposedValue>, n: usize) -> T
where
    T: From<Vec<u8>> + Into<Vec<u8>>,
{
    let t: Vec<u8> = m.into_iter().take(n).flat_map(|s| s).collect();
    let payload_len = t[0] as usize;
    debug!("Glued data shards {:?}", &t[1..(payload_len + 1)]);

    Vec::into(t[1..(payload_len + 1)].to_vec())
}

/// An additional path conversion operation on `Lemma` to allow reconstruction
/// of erasure-coded `Proof` from `Lemma`s. The output path, when read from left
/// to right, goes from leaf to root (LSB order).
fn path_of_lemma(lemma: &Lemma) -> Vec<bool> {
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
            let mut p = path_of_lemma(l.as_ref());

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
fn index_of_path(mut path: Vec<bool>) -> usize {
    let mut idx = 0;
    // Convert to the MSB order.
    path.reverse();

    for &dir in &path {
        idx <<= 1;
        if dir {
            idx |= 1;
        }
    }
    idx
}

/// Computes the Merkle tree leaf index of a value in a given proof.
// TODO: This currently only works if the number of leaves is a power of two. With the
// `merkle_light` crate, it might not even be needed, though.
pub fn index_of_proof<T>(p: &Proof<T>) -> usize {
    index_of_path(path_of_lemma(&p.lemma))
}
