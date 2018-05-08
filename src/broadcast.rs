use crossbeam_channel::{Receiver, RecvError, SendError, Sender};
use merkle::proof::{Lemma, Positioned, Proof};
use merkle::{Hashable, MerkleTree};
use proto::*;
use reed_solomon_erasure as rse;
use reed_solomon_erasure::ReedSolomon;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug};
use std::hash::Hash;
use std::iter;
use std::marker::{Send, Sync};
use std::sync::{RwLock, RwLockWriteGuard};

use messaging::{SourcedMessage, Target, TargetedMessage};

// TODO: Make this a generic argument of `Broadcast`.
type ProposedValue = Vec<u8>;

type MessageQueue<NodeUid> = VecDeque<TargetedBroadcastMessage<NodeUid>>;

/// The three kinds of message sent during the reliable broadcast stage of the
/// consensus algorithm.
#[derive(Clone, PartialEq)]
pub enum BroadcastMessage<T: Send + Sync> {
    Value(Proof<T>),
    Echo(Proof<T>),
    Ready(Vec<u8>),
}

impl BroadcastMessage<ProposedValue> {
    fn target_all<NodeUid>(self) -> TargetedBroadcastMessage<NodeUid> {
        TargetedBroadcastMessage {
            target: BroadcastTarget::All,
            message: self,
        }
    }

    fn target_node<NodeUid>(self, id: NodeUid) -> TargetedBroadcastMessage<NodeUid> {
        TargetedBroadcastMessage {
            target: BroadcastTarget::Node(id),
            message: self,
        }
    }
}

impl<T: Send + Sync + Debug + AsRef<[u8]>> fmt::Debug for BroadcastMessage<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BroadcastMessage::Value(ref v) => write!(f, "Value({:?})", HexProof(&v)),
            BroadcastMessage::Echo(ref v) => write!(f, "Echo({:?})", HexProof(&v)),
            BroadcastMessage::Ready(ref bytes) => write!(f, "Ready({:?})", HexBytes(bytes)),
        }
    }
}

/// A `BroadcastMessage` to be sent out, together with a target.
#[derive(Clone, Debug)]
pub struct TargetedBroadcastMessage<NodeUid> {
    pub target: BroadcastTarget<NodeUid>,
    pub message: BroadcastMessage<ProposedValue>,
}

impl From<TargetedBroadcastMessage<usize>> for TargetedMessage<ProposedValue> {
    fn from(msg: TargetedBroadcastMessage<usize>) -> TargetedMessage<ProposedValue> {
        TargetedMessage {
            target: msg.target.into(),
            message: Message::Broadcast(msg.message),
        }
    }
}

/// A target node for a `BroadcastMessage`.
#[derive(Clone, Debug)]
pub enum BroadcastTarget<NodeUid> {
    All,
    Node(NodeUid),
}

impl From<BroadcastTarget<usize>> for Target {
    fn from(bt: BroadcastTarget<usize>) -> Target {
        match bt {
            BroadcastTarget::All => Target::All,
            BroadcastTarget::Node(node) => Target::Node(node),
        }
    }
}

struct BroadcastState<NodeUid: Eq + Hash + Ord> {
    /// Whether we have already multicas `Echo`.
    echo_sent: bool,
    /// Whether we have already multicast `Ready`.
    ready_sent: bool,
    /// Whether we have already output a value.
    has_output: bool,
    /// The proofs we have received via `Echo` messages, by sender ID.
    echos: BTreeMap<NodeUid, Proof<Vec<u8>>>,
    /// The root hashes we received via `Ready` messages, by sender ID.
    readys: BTreeMap<NodeUid, Vec<u8>>,
}

impl<NodeUid: Eq + Hash + Ord> BroadcastState<NodeUid> {
    /// Returns the number of nodes that have sent us an `Echo` message with this hash.
    fn count_echos(&self, hash: &[u8]) -> usize {
        self.echos
            .values()
            .filter(|p| p.root_hash.as_slice() == hash)
            .count()
    }

    /// Returns the number of nodes that have sent us a `Ready` message with this hash.
    fn count_readys(&self, hash: &[u8]) -> usize {
        self.readys
            .values()
            .filter(|h| h.as_slice() == hash)
            .count()
    }
}

/// Reliable Broadcast algorithm instance.
///
/// The Reliable Broadcast Protocol assumes a network of `N` nodes that send signed messages to
/// each other, with at most `f` of them malicious, where `3 * f < N`. Handling the networking and
/// signing is the responsibility of this crate's user: only when a message has been verified to be
/// "from node i", it can be handed to the `Broadcast` instance. One of the nodes is the "proposer"
/// who sends a value. Under the above conditions, the protocol guarantees that either all or none
/// of the good nodes output a value, and that if the proposer is good, all good nodes output the
/// proposed value.
///
/// The algorithm works as follows:
///
/// * The proposer uses a Reed-Solomon code to split the value into `N` chunks, `f + 1` of which
/// suffice to reconstruct the value. These chunks are put into a Merkle tree, so that with the
/// tree's root hash `h`, branch `bi` and chunk `si`, the `i`-th chunk `si` can be verified by
/// anyone to belong to the Merkle tree with root hash `h`. These values are "proof" number `i`:
/// `pi`.
/// * The proposer sends `Value(pi)` to node `i`. It translates to: "I am the proposer, and `pi`
/// contains the `i`-th share of my value."
/// * Every (good) node that receives `Value(pi)` from the proposer sends it on to everyone else as
/// `Echo(pi)`. An `Echo` translates to: "I have received `pi` directly from the proposer." If the
/// proposer sends another `Value` message, that is ignored.
/// * So every node that has received at least `f + 1` `Echo` messages with the same root
/// hash will be able to decode a value.
/// * Every node that has received `N - f` `Echo`s with the same root hash from different nodes
/// knows that at least `f + 1` _good_ nodes have sent an `Echo` with that hash to everyone, and
/// therefore everyone will eventually receive at least `f + 1` of them. So upon receiving `N - f`
/// `Echo`s, they send a `Ready(h)` to everyone to indicate that. `Ready` translates to: "I know
/// that everyone will eventually be able to decode the value." Moreover, since every good node
/// only ever sends one kind of `Echo` message, this cannot happen for two different root hashes.
/// * Even without enough `Echo` messages, if a node receives `f + 1` `Ready` messages, it knows
/// that at least one _good_ node has sent `Ready`. It therefore also knows that everyone will be
/// able to decode eventually, and multicasts `Ready` itself.
/// * If a node has received `2 * f + 1` `Ready`s (with matching root hash) from different nodes,
/// it knows that at least `f + 1` _good_ nodes have sent it. Therefore, every good node will
/// eventually receive `f + 1`, and multicast it itself. Therefore, every good node will eventually
/// receive `2 * f + 1` `Ready`s, too. _And_ we know at this point that every good node will
/// eventually be able to decode (i.e. receive at least `f + 1` `Echo` messages).
/// * So a node with `2 * f + 1` `Ready`s and `f + 1` `Echos` will decode and _output_ the value,
/// knowing that every other good node will eventually do the same.
pub struct Broadcast<NodeUid: Eq + Hash + Ord> {
    /// The UID of this node.
    our_id: NodeUid,
    /// The UID of the sending node.
    proposer_id: NodeUid,
    /// UIDs of all nodes for iteration purposes.
    all_uids: BTreeSet<NodeUid>,
    num_nodes: usize,
    num_faulty_nodes: usize,
    data_shard_num: usize,
    coding: ReedSolomon,
    /// All the mutable state is confined to the `state` field. This allows to
    /// mutate state even when the broadcast instance is referred to by an
    /// immutable reference.
    state: RwLock<BroadcastState<NodeUid>>,
}

impl<NodeUid: Eq + Hash + Debug + Clone + Ord> Broadcast<NodeUid> {
    /// Creates a new broadcast instance to be used by node `our_id` which expects a value proposal
    /// from node `proposer_id`.
    pub fn new(
        our_id: NodeUid,
        proposer_id: NodeUid,
        all_uids: BTreeSet<NodeUid>,
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
                echo_sent: false,
                ready_sent: false,
                has_output: false,
                echos: BTreeMap::new(),
                readys: BTreeMap::new(),
            }),
        })
    }

    /// Processes the proposed value input by broadcasting it.
    pub fn propose_value(&self, value: ProposedValue) -> Result<MessageQueue<NodeUid>, Error> {
        if self.our_id != self.proposer_id {
            return Err(Error::UnexpectedMessage);
        }
        // Split the value into chunks/shards, encode them with erasure codes.
        // Assemble a Merkle tree from data and parity shards. Take all proofs
        // from this tree and send them, each to its own node.
        let (proof, value_msgs) = self.send_shards(value)?;
        // TODO: We'd actually need to return the output here, if it was only one node. Should that
        // use-case be supported?
        let state = self.state.write().unwrap();
        let (_, echo_msgs) = self.handle_value(&self.our_id, proof, state)?;
        Ok(value_msgs.into_iter().chain(echo_msgs).collect())
    }

    /// Returns this node's ID.
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
    ) -> Result<(Proof<Vec<u8>>, MessageQueue<NodeUid>), Error> {
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

        debug!("Shards before encoding: {:?}", HexList(&shards));

        // Construct the parity chunks/shards
        self.coding.encode(&mut shards)?;

        debug!("Shards: {:?}", HexList(&shards));

        // TODO: `MerkleTree` generates the wrong proof if a leaf occurs more than once, so we
        // prepend an "index byte" to each shard. Consider using the `merkle_light` crate instead.
        let shards_t: Vec<ProposedValue> = shards
            .into_iter()
            .enumerate()
            .map(|(i, s)| iter::once(i as u8).chain(s.iter().cloned()).collect())
            .collect();

        // Convert the Merkle tree into a partial binary tree for later
        // deconstruction into compound branches.
        let mtree = MerkleTree::from_vec(&::ring::digest::SHA256, shards_t);

        // Default result in case of `gen_proof` error.
        let mut result = Err(Error::ProofConstructionFailed);
        let mut outgoing = VecDeque::new();
        assert_eq!(self.num_nodes, mtree.iter().count());

        // Send each proof to a node.
        for (leaf_value, uid) in mtree.iter().zip(&self.all_uids) {
            let proof = mtree
                .gen_proof(leaf_value.to_vec())
                .ok_or(Error::ProofConstructionFailed)?;
            if *uid == self.our_id {
                // The proof is addressed to this node.
                result = Ok(proof);
            } else {
                // Rest of the proofs are sent to remote nodes.
                outgoing.push_back(BroadcastMessage::Value(proof).target_node(uid.clone()));
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
        if !self.all_uids.contains(sender_id) {
            return Err(Error::UnknownSender);
        }
        let state = self.state.write().unwrap();
        match message {
            BroadcastMessage::Value(p) => self.handle_value(sender_id, p, state),
            BroadcastMessage::Echo(p) => self.handle_echo(sender_id, p, state),
            BroadcastMessage::Ready(ref hash) => self.handle_ready(sender_id, hash, state),
        }
    }

    /// Handles a received echo and verifies the proof it contains.
    fn handle_value(
        &self,
        sender_id: &NodeUid,
        p: Proof<Vec<u8>>,
        mut state: RwLockWriteGuard<BroadcastState<NodeUid>>,
    ) -> Result<(Option<ProposedValue>, MessageQueue<NodeUid>), Error> {
        // If the sender is not the proposer, this is not the first `Value` or the proof is invalid,
        // ignore.
        if *sender_id != self.proposer_id {
            info!(
                "Node {:?} received Value from {:?} instead of {:?}.",
                self.our_id, sender_id, self.proposer_id
            );
            return Ok((None, VecDeque::new()));
        }
        if state.echo_sent {
            info!("Node {:?} received multiple Values.", self.our_id);
            return Ok((None, VecDeque::new()));
        }
        if !self.validate_proof(&p, &self.our_id) {
            return Ok((None, VecDeque::new()));
        }

        // Otherwise multicast the proof in an `Echo` message, and handle it ourselves.
        state.echo_sent = true;
        let (output, echo_msgs) = self.handle_echo(&self.our_id, p.clone(), state)?;
        let msgs = iter::once(BroadcastMessage::Echo(p).target_all())
            .chain(echo_msgs)
            .collect();

        Ok((output, msgs))
    }

    /// Handles a received `Echo` message.
    fn handle_echo(
        &self,
        sender_id: &NodeUid,
        p: Proof<Vec<u8>>,
        mut state: RwLockWriteGuard<BroadcastState<NodeUid>>,
    ) -> Result<(Option<ProposedValue>, MessageQueue<NodeUid>), Error> {
        // If the proof is invalid or the sender has already sent `Echo`, ignore.
        if state.echos.contains_key(sender_id) {
            info!(
                "Node {:?} received multiple Echos from {:?}.",
                self.our_id, sender_id,
            );
            return Ok((None, VecDeque::new()));
        }
        if !self.validate_proof(&p, sender_id) {
            return Ok((None, VecDeque::new()));
        }

        let hash = p.root_hash.clone();

        // Save the proof for reconstructing the tree later.
        state.echos.insert(sender_id.clone(), p);

        if state.ready_sent || state.count_echos(&hash) < self.num_nodes - self.num_faulty_nodes {
            return Ok((self.get_output(state, &hash)?, VecDeque::new()));
        }

        // Upon receiving `N - f` `Echo`s with this root hash, multicast `Ready`.
        state.ready_sent = true;
        let msg = BroadcastMessage::Ready(hash.clone()).target_all();
        let (output, ready_msgs) = self.handle_ready(&self.our_id, &hash, state)?;
        Ok((output, iter::once(msg).chain(ready_msgs).collect()))
    }

    /// Handles a received `Ready` message.
    fn handle_ready(
        &self,
        sender_id: &NodeUid,
        hash: &[u8],
        mut state: RwLockWriteGuard<BroadcastState<NodeUid>>,
    ) -> Result<(Option<ProposedValue>, MessageQueue<NodeUid>), Error> {
        // If the sender has already sent a `Ready` before, ignore.
        if state.readys.contains_key(sender_id) {
            info!(
                "Node {:?} received multiple Readys from {:?}.",
                self.our_id, sender_id
            );
            return Ok((None, VecDeque::new()));
        }

        state.readys.insert(sender_id.clone(), hash.to_vec());

        // Upon receiving f + 1 matching Ready(h) messages, if Ready
        // has not yet been sent, multicast Ready(h).
        let outgoing = if state.count_readys(hash) == self.num_faulty_nodes + 1 && !state.ready_sent
        {
            // Enqueue a broadcast of a Ready message.
            state.ready_sent = true;
            iter::once(BroadcastMessage::Ready(hash.to_vec()).target_all()).collect()
        } else {
            VecDeque::new()
        };

        Ok((self.get_output(state, hash)?, outgoing))
    }

    /// Checks whether the condition for output are met for this hash, and if so, returns the output
    /// value.
    fn get_output(
        &self,
        mut state: RwLockWriteGuard<BroadcastState<NodeUid>>,
        hash: &[u8],
    ) -> Result<Option<ProposedValue>, Error> {
        if state.has_output || state.count_readys(hash) <= 2 * self.num_faulty_nodes
            || state.count_echos(hash) <= self.num_faulty_nodes
        {
            return Ok(None);
        }

        // Upon receiving 2f + 1 matching Ready(h) messages, wait for N − 2f Echo messages.
        state.has_output = true;
        let mut leaf_values: Vec<Option<Box<[u8]>>> = self.all_uids
            .iter()
            .map(|id| {
                state.echos.get(id).and_then(|p| {
                    if p.root_hash.as_slice() == hash {
                        Some(p.value.clone().into_boxed_slice())
                    } else {
                        None
                    }
                })
            })
            .collect();
        let value = decode_from_shards(&mut leaf_values, &self.coding, self.data_shard_num, hash)?;
        Ok(Some(value))
    }

    /// Returns `i` if `node_id` is the `i`-th ID among all participating nodes.
    fn index_of_node(&self, node_id: &NodeUid) -> Option<usize> {
        self.all_uids.iter().position(|id| id == node_id)
    }

    /// Returns the index of this proof's leave in the Merkle tree.
    fn index_of_proof(&self, proof: &Proof<ProposedValue>) -> usize {
        index_of_lemma(&proof.lemma, self.num_nodes)
    }

    /// Returns `true` if the proof is valid and has the same index as the node ID. Otherwise
    /// logs an info message.
    fn validate_proof(&self, p: &Proof<ProposedValue>, id: &NodeUid) -> bool {
        if !p.validate(&p.root_hash) {
            info!(
                "Node {:?} received invalid proof: {:?}",
                self.our_id,
                HexProof(&p)
            );
            false
        } else if self.index_of_node(id) != Some(p.value[0] as usize)
            || self.index_of_proof(&p) != p.value[0] as usize
        {
            info!(
                "Node {:?} received proof for wrong position: {:?}.",
                self.our_id,
                HexProof(&p)
            );
            false
        } else {
            true
        }
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
        node_ids: BTreeSet<usize>,
        our_id: usize,
        proposer_id: usize,
    ) -> Self {
        let broadcast =
            Broadcast::new(our_id, proposer_id, node_ids).expect("failed to instantiate broadcast");
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
    UnknownSender,
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
            .map(TargetedBroadcastMessage::into)
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
            debug!("{} received from {}: {:?}", broadcast.our_id, i, message);
            let (opt_output, msgs) = broadcast.handle_broadcast_message(&i, message)?;
            for msg in &msgs {
                debug!(
                    "{} sending to {:?}: {:?}",
                    broadcast.our_id, msg.target, msg.message
                );
            }
            for msg in msgs.into_iter().map(TargetedBroadcastMessage::into) {
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

    debug!("Reconstructed shards: {:?}", HexList(&shards));

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
    let t: Vec<u8> = m.into_iter()
        .take(n)
        .flat_map(|s| s.into_iter().skip(1)) // Drop the index byte.
        .collect();
    let payload_len = t[0] as usize;
    debug!("Glued data shards {:?}", HexBytes(&t[1..(payload_len + 1)]));

    Vec::into(t[1..(payload_len + 1)].to_vec())
}

/// Computes the Merkle tree leaf index of a value in a given lemma.
pub fn index_of_lemma(lemma: &Lemma, n: usize) -> usize {
    let m = n.next_power_of_two();
    match (lemma.sub_lemma.as_ref(), lemma.sibling_hash.as_ref()) {
        (None, Some(&Positioned::Right(_))) | (None, None) => 0,
        (None, Some(&Positioned::Left(_))) => 1,
        (Some(l), None) => index_of_lemma(l, n),
        (Some(l), Some(&Positioned::Left(_))) => (m >> 1) + index_of_lemma(l, n - (m >> 1)),
        (Some(l), Some(&Positioned::Right(_))) => index_of_lemma(l, m >> 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_index_of_lemma() {
        for &n in &[3, 4, 13, 16, 127, 128, 129, 255] {
            let shards: Vec<[u8; 1]> = (0..n).map(|i| [i as u8]).collect();
            let mtree = MerkleTree::from_vec(&::ring::digest::SHA256, shards);
            for (i, val) in mtree.iter().enumerate() {
                let p = mtree.gen_proof(val.clone()).expect("generate proof");
                let idx = index_of_lemma(&p.lemma, n);
                assert_eq!(i, idx, "Wrong index {} for leaf {}/{}.", idx, i, n);
            }
        }
    }
}
