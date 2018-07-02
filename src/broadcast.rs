//! # Broadcast
//!
//! The Reliable Broadcast Protocol assumes a network of `N` nodes that send signed messages to
//! each other, with at most `f` of them faulty, where `3 * f < N`. Handling the networking and
//! signing is the responsibility of this crate's user; a message is only handed to the Broadcast
//! instance after it has been verified to be "from node i". One of the nodes is the "proposer"
//! who sends a value. It needs to be determined beforehand, and all nodes need to know and agree
//! who it is. Under the above conditions, the protocol guarantees that either all or none
//! of the correct nodes output a value, and that if the proposer is correct, all correct nodes
//! output the proposed value.
//!
//! ## How it works
//!
//! * The proposer uses a Reed-Solomon code to split the value into `N` chunks, `f + 1` of which
//! suffice to reconstruct the value. These chunks are put into a Merkle tree, so that with the
//! tree's root hash `h`, branch `bi` and chunk `si`, the `i`-th chunk `si` can be verified by
//! anyone as belonging to the Merkle tree with root hash `h`. These values are "proof" number `i`:
//! `pi = (h, bi, si)`.
//! * The proposer sends `Value(pi)` to node `i`. It translates to: "I am the proposer, and `pi`
//! contains the `i`-th share of my value."
//! * Every (correct) node that receives `Value(pi)` from the proposer sends it on to everyone else
//! as `Echo(pi)`. An `Echo` translates to: "I have received `pi` directly from the proposer." If
//! the proposer sends another `Value` message it is ignored.
//! * So every node that receives at least `f + 1` `Echo` messages with the same root hash can
//! decode a value.
//! * Every node that has received `N - f` `Echo`s with the same root hash from different nodes
//! knows that at least `f + 1` _correct_ nodes have sent an `Echo` with that hash to everyone, and
//! therefore everyone will eventually receive at least `f + 1` of them. So upon receiving `N - f`
//! `Echo`s, they send a `Ready(h)` to everyone. It translates to: "I know that everyone will
//! eventually be able to decode the value with root hash `h`." Moreover, since every correct node
//! only sends one kind of `Echo` message, there is no danger of receiving `N - f` `Echo`s with two
//! different root hashes.
//! * Even without enough `Echo` messages, if a node receives `f + 1` `Ready` messages, it knows
//! that at least one _correct_ node has sent `Ready`. It therefore also knows that everyone will
//! be able to decode eventually, and multicasts `Ready` itself.
//! * If a node has received `2 * f + 1` `Ready`s (with matching root hash) from different nodes,
//! it knows that at least `f + 1` _correct_ nodes have sent it. Therefore, every correct node will
//! eventually receive `f + 1`, and multicast it itself. Therefore, every correct node will
//! eventually receive `2 * f + 1` `Ready`s, too. _And_ we know at this point that every correct
//! node will eventually be able to decode (i.e. receive at least `f + 1` `Echo` messages).
//! * So a node with `2 * f + 1` `Ready`s and `f + 1` `Echos` will decode and _output_ the value,
//! knowing that every other correct node will eventually do the same.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::{self, Debug};
use std::iter::once;
use std::rc::Rc;

use byteorder::{BigEndian, ByteOrder};
use merkle::{MerkleTree, Proof};
use reed_solomon_erasure as rse;
use reed_solomon_erasure::ReedSolomon;
use ring::digest;

use fmt::{HexBytes, HexList, HexProof};
use messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};

error_chain!{
    types {
        Error, ErrorKind, ResultExt, BroadcastResult;
    }

    foreign_links {
        ReedSolomon(rse::Error);
    }

    errors {
        InstanceCannotPropose
        NotImplemented
        ProofConstructionFailed
        RootHashMismatch
        Threading
        UnknownSender
    }
}

/// The three kinds of message sent during the reliable broadcast stage of the
/// consensus algorithm.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum BroadcastMessage {
    Value(Proof<Vec<u8>>),
    Echo(Proof<Vec<u8>>),
    Ready(Vec<u8>),
}

impl Debug for BroadcastMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BroadcastMessage::Value(ref v) => write!(f, "Value({:?})", HexProof(&v)),
            BroadcastMessage::Echo(ref v) => write!(f, "Echo({:?})", HexProof(&v)),
            BroadcastMessage::Ready(ref bytes) => write!(f, "Ready({:?})", HexBytes(bytes)),
        }
    }
}

/// Reliable Broadcast algorithm instance.
pub struct Broadcast<NodeUid> {
    /// Shared network data.
    netinfo: Rc<NetworkInfo<NodeUid>>,
    /// The UID of the sending node.
    proposer_id: NodeUid,
    data_shard_num: usize,
    coding: Coding,
    /// Whether we have already multicast `Echo`.
    echo_sent: bool,
    /// Whether we have already multicast `Ready`.
    ready_sent: bool,
    /// Whether we have already output a value.
    decided: bool,
    /// The proofs we have received via `Echo` messages, by sender ID.
    echos: BTreeMap<NodeUid, Proof<Vec<u8>>>,
    /// The root hashes we received via `Ready` messages, by sender ID.
    readys: BTreeMap<NodeUid, Vec<u8>>,
    /// The outgoing message queue.
    messages: VecDeque<TargetedMessage<BroadcastMessage, NodeUid>>,
    /// The output, if any.
    output: Option<Vec<u8>>,
}

impl<NodeUid: Debug + Clone + Ord> DistAlgorithm for Broadcast<NodeUid> {
    type NodeUid = NodeUid;
    // TODO: Allow anything serializable and deserializable, i.e. make this a type parameter
    // T: Serialize + DeserializeOwned
    type Input = Vec<u8>;
    type Output = Self::Input;
    type Message = BroadcastMessage;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> BroadcastResult<()> {
        if *self.netinfo.our_uid() != self.proposer_id {
            return Err(ErrorKind::InstanceCannotPropose.into());
        }
        // Split the value into chunks/shards, encode them with erasure codes.
        // Assemble a Merkle tree from data and parity shards. Take all proofs
        // from this tree and send them, each to its own node.
        let proof = self.send_shards(input)?;
        let our_uid = &self.netinfo.our_uid().clone();
        self.handle_value(our_uid, proof)
    }

    fn handle_message(
        &mut self,
        sender_id: &NodeUid,
        message: Self::Message,
    ) -> BroadcastResult<()> {
        if !self.netinfo.all_uids().contains(sender_id) {
            return Err(ErrorKind::UnknownSender.into());
        }
        match message {
            BroadcastMessage::Value(p) => self.handle_value(sender_id, p),
            BroadcastMessage::Echo(p) => self.handle_echo(sender_id, p),
            BroadcastMessage::Ready(ref hash) => self.handle_ready(sender_id, hash),
        }
    }

    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, NodeUid>> {
        self.messages.pop_front()
    }

    fn next_output(&mut self) -> Option<Self::Output> {
        self.output.take()
    }

    fn terminated(&self) -> bool {
        self.decided
    }

    fn our_id(&self) -> &NodeUid {
        self.netinfo.our_uid()
    }
}

impl<NodeUid: Debug + Clone + Ord> Broadcast<NodeUid> {
    /// Creates a new broadcast instance to be used by node `our_id` which expects a value proposal
    /// from node `proposer_id`.
    pub fn new(netinfo: Rc<NetworkInfo<NodeUid>>, proposer_id: NodeUid) -> BroadcastResult<Self> {
        let parity_shard_num = 2 * netinfo.num_faulty();
        let data_shard_num = netinfo.num_nodes() - parity_shard_num;
        let coding = Coding::new(data_shard_num, parity_shard_num)?;

        Ok(Broadcast {
            netinfo,
            proposer_id,
            data_shard_num,
            coding,
            echo_sent: false,
            ready_sent: false,
            decided: false,
            echos: BTreeMap::new(),
            readys: BTreeMap::new(),
            messages: VecDeque::new(),
            output: None,
        })
    }

    /// Breaks the input value into shards of equal length and encodes them --
    /// and some extra parity shards -- with a Reed-Solomon erasure coding
    /// scheme. The returned value contains the shard assigned to this
    /// node. That shard doesn't need to be sent anywhere. It gets recorded in
    /// the broadcast instance.
    fn send_shards(&mut self, mut value: Vec<u8>) -> BroadcastResult<Proof<Vec<u8>>> {
        let data_shard_num = self.coding.data_shard_count();
        let parity_shard_num = self.coding.parity_shard_count();

        debug!(
            "Data shards: {}, parity shards: {}",
            self.data_shard_num, parity_shard_num
        );
        // Insert the length of `v` so it can be decoded without the padding.
        let payload_len = value.len() as u32;
        value.splice(0..0, 0..4); // Insert four bytes at the beginning.
        BigEndian::write_u32(&mut value[..4], payload_len); // Write the size.
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
        self.coding
            .encode(&mut shards)
            .expect("the size and number of shards is correct");

        debug!("Shards: {:?}", HexList(&shards));

        // TODO: `MerkleTree` generates the wrong proof if a leaf occurs more than once, so we
        // prepend an "index byte" to each shard. Consider using the `merkle_light` crate instead.
        let shards_t: Vec<Vec<u8>> = shards
            .into_iter()
            .enumerate()
            .map(|(i, s)| once(i as u8).chain(s.iter().cloned()).collect())
            .collect();

        // Convert the Merkle tree into a partial binary tree for later
        // deconstruction into compound branches.
        let mtree = MerkleTree::from_vec(&digest::SHA256, shards_t);

        // Default result in case of `gen_proof` error.
        let mut result = Err(ErrorKind::ProofConstructionFailed.into());
        assert_eq!(self.netinfo.num_nodes(), mtree.iter().count());

        // Send each proof to a node.
        for (leaf_value, uid) in mtree.iter().zip(self.netinfo.all_uids()) {
            let proof = mtree
                .gen_proof(leaf_value.to_vec())
                .ok_or(ErrorKind::ProofConstructionFailed)?;
            if *uid == *self.netinfo.our_uid() {
                // The proof is addressed to this node.
                result = Ok(proof);
            } else {
                // Rest of the proofs are sent to remote nodes.
                let msg = Target::Node(uid.clone()).message(BroadcastMessage::Value(proof));
                self.messages.push_back(msg);
            }
        }

        result
    }

    /// Handles a received echo and verifies the proof it contains.
    fn handle_value(&mut self, sender_id: &NodeUid, p: Proof<Vec<u8>>) -> BroadcastResult<()> {
        // If the sender is not the proposer, this is not the first `Value` or the proof is invalid,
        // ignore.
        if *sender_id != self.proposer_id {
            info!(
                "Node {:?} received Value from {:?} instead of {:?}.",
                self.netinfo.our_uid(),
                sender_id,
                self.proposer_id
            );
            return Ok(());
        }
        if self.echo_sent {
            info!(
                "Node {:?} received multiple Values.",
                self.netinfo.our_uid()
            );
            return Ok(());
        }
        if !self.validate_proof(&p, &self.netinfo.our_uid()) {
            return Ok(());
        }

        // Otherwise multicast the proof in an `Echo` message, and handle it ourselves.
        self.send_echo(p)
    }

    /// Handles a received `Echo` message.
    fn handle_echo(&mut self, sender_id: &NodeUid, p: Proof<Vec<u8>>) -> BroadcastResult<()> {
        // If the proof is invalid or the sender has already sent `Echo`, ignore.
        if self.echos.contains_key(sender_id) {
            info!(
                "Node {:?} received multiple Echos from {:?}.",
                self.netinfo.our_uid(),
                sender_id,
            );
            return Ok(());
        }
        if !self.validate_proof(&p, sender_id) {
            return Ok(());
        }

        let hash = p.root_hash.clone();

        // Save the proof for reconstructing the tree later.
        self.echos.insert(sender_id.clone(), p);

        if self.ready_sent
            || self.count_echos(&hash) < self.netinfo.num_nodes() - self.netinfo.num_faulty()
        {
            return self.compute_output(&hash);
        }

        // Upon receiving `N - f` `Echo`s with this root hash, multicast `Ready`.
        self.send_ready(&hash)
    }

    /// Handles a received `Ready` message.
    fn handle_ready(&mut self, sender_id: &NodeUid, hash: &[u8]) -> BroadcastResult<()> {
        // If the sender has already sent a `Ready` before, ignore.
        if self.readys.contains_key(sender_id) {
            info!(
                "Node {:?} received multiple Readys from {:?}.",
                self.netinfo.our_uid(),
                sender_id
            );
            return Ok(());
        }

        self.readys.insert(sender_id.clone(), hash.to_vec());

        // Upon receiving f + 1 matching Ready(h) messages, if Ready
        // has not yet been sent, multicast Ready(h).
        if self.count_readys(hash) == self.netinfo.num_faulty() + 1 && !self.ready_sent {
            // Enqueue a broadcast of a Ready message.
            self.send_ready(hash)?;
        }
        self.compute_output(hash)
    }

    /// Sends an `Echo` message and handles it. Does nothing if we are only an observer.
    fn send_echo(&mut self, p: Proof<Vec<u8>>) -> BroadcastResult<()> {
        self.echo_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(());
        }
        let echo_msg = Target::All.message(BroadcastMessage::Echo(p.clone()));
        self.messages.push_back(echo_msg);
        let our_uid = &self.netinfo.our_uid().clone();
        self.handle_echo(our_uid, p)
    }

    /// Sends a `Ready` message and handles it. Does nothing if we are only an observer.
    fn send_ready(&mut self, hash: &[u8]) -> BroadcastResult<()> {
        self.ready_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(());
        }
        let ready_msg = Target::All.message(BroadcastMessage::Ready(hash.to_vec()));
        self.messages.push_back(ready_msg);
        let our_uid = &self.netinfo.our_uid().clone();
        self.handle_ready(our_uid, hash)
    }

    /// Checks whether the condition for output are met for this hash, and if so, sets the output
    /// value.
    fn compute_output(&mut self, hash: &[u8]) -> BroadcastResult<()> {
        if self.decided
            || self.count_readys(hash) <= 2 * self.netinfo.num_faulty()
            || self.count_echos(hash) <= self.netinfo.num_faulty()
        {
            return Ok(());
        }

        // Upon receiving 2f + 1 matching Ready(h) messages, wait for N − 2f Echo messages.
        let mut leaf_values: Vec<Option<Box<[u8]>>> = self
            .netinfo
            .all_uids()
            .iter()
            .map(|id| {
                self.echos.get(id).and_then(|p| {
                    if p.root_hash.as_slice() == hash {
                        Some(p.value.clone().into_boxed_slice())
                    } else {
                        None
                    }
                })
            })
            .collect();
        let value = decode_from_shards(&mut leaf_values, &self.coding, self.data_shard_num, hash);
        self.decided = value.is_some();
        self.output = value;
        Ok(())
    }

    /// Returns `i` if `node_id` is the `i`-th ID among all participating nodes.
    fn index_of_node(&self, node_id: &NodeUid) -> Option<usize> {
        self.netinfo.all_uids().iter().position(|id| id == node_id)
    }

    /// Returns `true` if the proof is valid and has the same index as the node ID. Otherwise
    /// logs an info message.
    fn validate_proof(&self, p: &Proof<Vec<u8>>, id: &NodeUid) -> bool {
        if !p.validate(&p.root_hash) {
            info!(
                "Node {:?} received invalid proof: {:?}",
                self.netinfo.our_uid(),
                HexProof(&p)
            );
            false
        } else if self.index_of_node(id) != Some(p.value[0] as usize)
            || p.index(self.netinfo.num_nodes()) != p.value[0] as usize
        {
            info!(
                "Node {:?} received proof for wrong position: {:?}.",
                self.netinfo.our_uid(),
                HexProof(&p)
            );
            false
        } else {
            true
        }
    }

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

/// A wrapper for `ReedSolomon` that doesn't panic if there are no parity shards.
enum Coding {
    /// A `ReedSolomon` instance with at least one parity shard.
    ReedSolomon(Box<ReedSolomon>),
    /// A no-op replacement that doesn't encode or decode anything.
    Trivial(usize),
}

impl Coding {
    /// Creates a new `Coding` instance with the given number of shards.
    fn new(data_shard_num: usize, parity_shard_num: usize) -> BroadcastResult<Self> {
        Ok(if parity_shard_num > 0 {
            let rs = ReedSolomon::new(data_shard_num, parity_shard_num)?;
            Coding::ReedSolomon(Box::new(rs))
        } else {
            Coding::Trivial(data_shard_num)
        })
    }

    /// Returns the number of data shards.
    fn data_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.data_shard_count(),
            Coding::Trivial(dsc) => dsc,
        }
    }

    /// Returns the number of parity shards.
    fn parity_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.parity_shard_count(),
            Coding::Trivial(_) => 0,
        }
    }

    /// Constructs (and overwrites) the parity shards.
    fn encode(&self, slices: &mut [&mut [u8]]) -> BroadcastResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.encode(slices)?,
            Coding::Trivial(_) => (),
        }
        Ok(())
    }

    /// If enough shards are present, reconstructs the missing ones.
    fn reconstruct_shards(&self, shards: &mut [Option<Box<[u8]>>]) -> BroadcastResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.reconstruct_shards(shards)?,
            Coding::Trivial(_) => {
                if shards.iter().any(Option::is_none) {
                    return Err(rse::Error::TooFewShardsPresent.into());
                }
            }
        }
        Ok(())
    }
}

fn decode_from_shards(
    leaf_values: &mut [Option<Box<[u8]>>],
    coding: &Coding,
    data_shard_num: usize,
    root_hash: &[u8],
) -> Option<Vec<u8>> {
    // Try to interpolate the Merkle tree using the Reed-Solomon erasure coding scheme.
    if let Err(err) = coding.reconstruct_shards(leaf_values) {
        debug!("Shard reconstruction failed: {:?}", err); // Faulty proposer
        return None;
    }

    // Recompute the Merkle tree root.

    // Collect shards for tree construction.
    let shards: Vec<Vec<u8>> = leaf_values
        .iter()
        .filter_map(|l| l.as_ref().map(|v| v.to_vec()))
        .collect();

    debug!("Reconstructed shards: {:?}", HexList(&shards));

    // Construct the Merkle tree.
    let mtree = MerkleTree::from_vec(&digest::SHA256, shards);
    // If the root hash of the reconstructed tree does not match the one
    // received with proofs then abort.
    if &mtree.root_hash()[..] != root_hash {
        None // The proposer is faulty.
    } else {
        // Reconstruct the value from the data shards.
        glue_shards(mtree, data_shard_num)
    }
}

/// Concatenates the first `n` leaf values of a Merkle tree `m` in one value of
/// type `T`. This is useful for reconstructing the data value held in the tree
/// and forgetting the leaves that contain parity information.
fn glue_shards(m: MerkleTree<Vec<u8>>, n: usize) -> Option<Vec<u8>> {
    // Create an iterator over the shard payload, drop the index bytes.
    let mut bytes = m.into_iter().take(n).flat_map(|s| s.into_iter().skip(1));
    let payload_len = match (bytes.next(), bytes.next(), bytes.next(), bytes.next()) {
        (Some(b0), Some(b1), Some(b2), Some(b3)) => BigEndian::read_u32(&[b0, b1, b2, b3]) as usize,
        _ => return None, // The proposing node is faulty: no payload size.
    };
    let payload: Vec<u8> = bytes.take(payload_len).collect();
    debug!("Glued data shards {:?}", HexBytes(&payload));
    Some(payload)
}
