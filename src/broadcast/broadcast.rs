use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::{fmt, result};

use byteorder::{BigEndian, ByteOrder};
use hex_fmt::{HexFmt, HexList};
use log::{debug, warn};
use rand::Rng;
use reed_solomon_erasure as rse;
use reed_solomon_erasure::ReedSolomon;

use super::merkle::{Digest, MerkleTree, Proof};
use super::message::HexProof;
use super::{Error, FaultKind, Message, Result};
use crate::fault_log::Fault;
use crate::{ConsensusProtocol, NetworkInfo, NodeIdT, Target};

type RseResult<T> = result::Result<T, rse::Error>;

/// Broadcast algorithm instance.
#[derive(Debug)]
pub struct Broadcast<N> {
    /// Shared network data.
    netinfo: Arc<NetworkInfo<N>>,
    /// The ID of the sending node.
    proposer_id: N,
    /// The Reed-Solomon erasure coding configuration.
    coding: Coding,
    /// If we are the proposer: whether we have already sent the `Value` messages with the shards.
    value_sent: bool,
    /// Whether we have already sent `Echo` to all nodes who haven't sent `CanDecode`.
    echo_sent: bool,
    /// Whether we have already multicast `Ready`.
    ready_sent: bool,
    /// Whether we have already sent `EchoHash` to the right nodes.
    echo_hash_sent: bool,
    /// Whether we have already sent `CanDecode`.
    can_decode_sent: bool,
    /// Whether we have already output a value.
    decided: bool,
    /// Number of faulty nodes to optimize performance for.
    fault_estimate: usize,
    /// The hashes and proofs we have received via `Echo` and `EchoHash` messages, by sender ID.
    echos: BTreeMap<N, EchoContent>,
    /// The hashes we have received from nodes via `CanDecode` messages, by hash.
    /// A node can receive conflicting `CanDecode`s from the same node.
    can_decodes: BTreeMap<Digest, BTreeSet<N>>,
    /// The root hashes we received via `Ready` messages, by sender ID.
    readys: BTreeMap<N, Vec<u8>>,
}

/// A `Broadcast` step, containing at most one output.
pub type Step<N> = crate::CpStep<Broadcast<N>>;

impl<N: NodeIdT> ConsensusProtocol for Broadcast<N> {
    type NodeId = N;
    type Input = Vec<u8>;
    type Output = Self::Input;
    type Message = Message;
    type Error = Error;
    type FaultKind = FaultKind;

    fn handle_input<R: Rng>(&mut self, input: Self::Input, _rng: &mut R) -> Result<Step<N>> {
        self.broadcast(input)
    }

    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &Self::NodeId,
        message: Message,
        _rng: &mut R,
    ) -> Result<Step<N>> {
        self.handle_message(sender_id, message)
    }

    fn terminated(&self) -> bool {
        self.decided
    }

    fn our_id(&self) -> &N {
        self.netinfo.our_id()
    }
}

impl<N: NodeIdT> Broadcast<N> {
    /// Creates a new broadcast instance to be used by node `our_id` which expects a value proposal
    /// from node `proposer_id`.
    pub fn new(netinfo: Arc<NetworkInfo<N>>, proposer_id: N) -> Result<Self> {
        let parity_shard_num = 2 * netinfo.num_faulty();
        let data_shard_num = netinfo.num_nodes() - parity_shard_num;
        let coding =
            Coding::new(data_shard_num, parity_shard_num).map_err(|_| Error::InvalidNodeCount)?;
        let fault_estimate = netinfo.num_faulty();

        Ok(Broadcast {
            netinfo,
            proposer_id,
            coding,
            value_sent: false,
            echo_sent: false,
            ready_sent: false,
            echo_hash_sent: false,
            can_decode_sent: false,
            decided: false,
            fault_estimate,
            echos: BTreeMap::new(),
            can_decodes: BTreeMap::new(),
            readys: BTreeMap::new(),
        })
    }

    /// Initiates the broadcast. This must only be called in the proposer node.
    pub fn broadcast(&mut self, input: Vec<u8>) -> Result<Step<N>> {
        if *self.our_id() != self.proposer_id {
            return Err(Error::InstanceCannotPropose);
        }
        if self.value_sent {
            return Err(Error::MultipleInputs);
        }
        self.value_sent = true;
        // Split the value into chunks/shards, encode them with erasure codes.
        // Assemble a Merkle tree from data and parity shards. Take all proofs
        // from this tree and send them, each to its own node.
        let (proof, step) = self.send_shards(input)?;
        let our_id = &self.our_id().clone();
        Ok(step.join(self.handle_value(our_id, proof)?))
    }

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message(&mut self, sender_id: &N, message: Message) -> Result<Step<N>> {
        if !self.netinfo.is_node_validator(sender_id) {
            return Err(Error::UnknownSender);
        }
        match message {
            Message::Value(p) => self.handle_value(sender_id, p),
            Message::Echo(p) => self.handle_echo(sender_id, p),
            Message::Ready(ref hash) => self.handle_ready(sender_id, hash),
            Message::CanDecode(ref hash) => self.handle_can_decode(sender_id, hash),
            Message::EchoHash(ref hash) => self.handle_echo_hash(sender_id, hash),
        }
    }

    /// Returns the proposer's node ID.
    pub fn proposer_id(&self) -> &N {
        &self.proposer_id
    }

    /// Breaks the input value into shards of equal length and encodes them --
    /// and some extra parity shards -- with a Reed-Solomon erasure coding
    /// scheme. The returned value contains the shard assigned to this
    /// node. That shard doesn't need to be sent anywhere. It gets recorded in
    /// the broadcast instance.
    fn send_shards(&mut self, mut value: Vec<u8>) -> Result<(Proof<Vec<u8>>, Step<N>)> {
        let data_shard_num = self.coding.data_shard_count();
        let parity_shard_num = self.coding.parity_shard_count();

        // Insert the length of `v` so it can be decoded without the padding.
        let payload_len = value.len() as u32;
        value.splice(0..0, 0..4); // Insert four bytes at the beginning.
        BigEndian::write_u32(&mut value[..4], payload_len); // Write the size.
        let value_len = value.len(); // This is at least 4 now, due to the payload length.

        // Size of a Merkle tree leaf value: the value size divided by the number of data shards,
        // and rounded up, so that the full value always fits in the data shards. Always at least 1.
        let shard_len = (value_len + data_shard_num - 1) / data_shard_num;
        // Pad the last data shard with zeros. Fill the parity shards with zeros.
        value.resize(shard_len * (data_shard_num + parity_shard_num), 0);

        // Divide the vector into chunks/shards.
        let shards_iter = value.chunks_mut(shard_len);
        // Convert the iterator over slices into a vector of slices.
        let mut shards: Vec<&mut [u8]> = shards_iter.collect();

        // Construct the parity chunks/shards. This only fails if a shard is empty or the shards
        // have different sizes. Our shards all have size `shard_len`, which is at least 1.
        self.coding.encode(&mut shards).expect("wrong shard size");

        debug!(
            "{}: Value: {} bytes, {} per shard. Shards: {:0.10}",
            self,
            value_len,
            shard_len,
            HexList(&shards)
        );

        // Create a Merkle tree from the shards.
        let mtree = MerkleTree::from_vec(shards.into_iter().map(|shard| shard.to_vec()).collect());

        // Default result in case of `proof` error.
        let mut result = Err(Error::ProofConstructionFailed);
        assert_eq!(self.netinfo.num_nodes(), mtree.values().len());

        let mut step = Step::default();
        // Send each proof to a node.
        for (index, id) in self.netinfo.all_ids().enumerate() {
            let proof = mtree.proof(index).ok_or(Error::ProofConstructionFailed)?;
            if *id == *self.our_id() {
                // The proof is addressed to this node.
                result = Ok(proof);
            } else {
                // Rest of the proofs are sent to remote nodes.
                let msg = Target::Node(id.clone()).message(Message::Value(proof));
                step.messages.push(msg);
            }
        }

        result.map(|proof| (proof, step))
    }

    /// Handles a received echo and verifies the proof it contains.
    fn handle_value(&mut self, sender_id: &N, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        // If the sender is not the proposer or if this is not the first `Value`, ignore.
        if *sender_id != self.proposer_id {
            let fault_kind = FaultKind::ReceivedValueFromNonProposer;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }

        match self.echos.get(self.our_id()) {
            // Multiple values from proposer.
            Some(val) if val.hash() != p.root_hash() => {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleValues).into())
            }
            // Already received proof.
            Some(EchoContent::Full(proof)) if *proof == p => {
                warn!(
                    "Node {:?} received Value({:?}) multiple times from {:?}.",
                    self.our_id(),
                    HexProof(&p),
                    sender_id
                );
                return Ok(Step::default());
            }
            _ => (),
        };

        // If the proof is invalid, log the faulty node behavior and ignore.
        if !self.validate_proof(&p, &self.our_id()) {
            return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidProof).into());
        }

        // Send the proof in an `Echo` message to left nodes
        // and `EchoHash` message to right nodes and handle the response.
        let echo_hash_steps = self.send_echo_hash(p.root_hash())?;
        let echo_steps = self.send_echo_left(p)?;
        Ok(echo_steps.join(echo_hash_steps))
    }

    /// Handles a received `Echo` message.
    fn handle_echo(&mut self, sender_id: &N, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        // If the sender has already sent `Echo`, ignore.
        if let Some(EchoContent::Full(old_p)) = self.echos.get(sender_id) {
            if *old_p == p {
                warn!(
                    "Node {:?} received Echo({:?}) multiple times from {:?}.",
                    self.our_id(),
                    HexProof(&p),
                    sender_id,
                );
                return Ok(Step::default());
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleEchos).into());
            }
        }

        // Case where we have received an earlier `EchoHash`
        // message from sender_id with different root_hash.
        if let Some(EchoContent::Hash(hash)) = self.echos.get(sender_id) {
            if hash != p.root_hash() {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleEchos).into());
            }
        }

        // If the proof is invalid, log the faulty-node behavior, and ignore.
        if !self.validate_proof(&p, sender_id) {
            return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidProof).into());
        }

        let hash = *p.root_hash();

        // Save the proof for reconstructing the tree later.
        self.echos.insert(sender_id.clone(), EchoContent::Full(p));

        let mut step = Step::default();

        // Upon receiving `N - 2f` `Echo`s with this root hash, send `CanDecode`
        if !self.can_decode_sent && self.count_echos_full(&hash) >= self.coding.data_shard_count() {
            step.extend(self.send_can_decode(&hash)?);
        }

        // Upon receiving `N - f` `Echo`s with this root hash, multicast `Ready`.
        if !self.ready_sent && self.count_echos(&hash) >= self.netinfo.num_correct() {
            step.extend(self.send_ready(&hash)?);
        }

        // Computes output if we have required number of `Echo`s and `Ready`s
        // Else returns Step::default()
        if self.ready_sent {
            step.extend(self.compute_output(&hash)?);
        }
        Ok(step)
    }

    fn handle_echo_hash(&mut self, sender_id: &N, hash: &Digest) -> Result<Step<N>> {
        // If the sender has already sent `EchoHash`, ignore.
        if let Some(EchoContent::Hash(old_hash)) = self.echos.get(sender_id) {
            if old_hash == hash {
                warn!(
                    "Node {:?} received EchoHash({:?}) multiple times from {:?}.",
                    self.our_id(),
                    hash,
                    sender_id,
                );
                return Ok(Step::default());
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleEchoHashes).into());
            }
        }

        // If the sender has already sent an `Echo` for the same hash, ignore.
        if let Some(EchoContent::Full(p)) = self.echos.get(sender_id) {
            if p.root_hash() == hash {
                return Ok(Step::default());
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleEchoHashes).into());
            }
        }
        // Save the hash for counting later.
        self.echos
            .insert(sender_id.clone(), EchoContent::Hash(*hash));

        if self.ready_sent || self.count_echos(&hash) < self.netinfo.num_correct() {
            return self.compute_output(&hash);
        }
        // Upon receiving `N - f` `Echo`s with this root hash, multicast `Ready`.
        self.send_ready(&hash)
    }

    /// Handles a received `CanDecode` message.
    fn handle_can_decode(&mut self, sender_id: &N, hash: &Digest) -> Result<Step<N>> {
        // Save the hash for counting later. If hash from sender_id already exists, emit a warning.
        if let Some(nodes) = self.can_decodes.get(hash) {
            if nodes.contains(sender_id) {
                warn!(
                    "Node {:?} received same CanDecode({:?}) multiple times from {:?}.",
                    self.our_id(),
                    hash,
                    sender_id,
                );
            }
        }
        self.can_decodes
            .entry(*hash)
            .or_default()
            .insert(sender_id.clone());
        Ok(Step::default())
    }

    /// Handles a received `Ready` message.
    fn handle_ready(&mut self, sender_id: &N, hash: &Digest) -> Result<Step<N>> {
        // If the sender has already sent a `Ready` before, ignore.
        if let Some(old_hash) = self.readys.get(sender_id) {
            if old_hash == hash {
                warn!(
                    "Node {:?} received Ready({:?}) multiple times from {:?}.",
                    self.our_id(),
                    hash,
                    sender_id
                );
                return Ok(Step::default());
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleReadys).into());
            }
        }

        self.readys.insert(sender_id.clone(), hash.to_vec());

        let mut step = Step::default();
        // Upon receiving f + 1 matching Ready(h) messages, if Ready
        // has not yet been sent, multicast Ready(h).
        if self.count_readys(hash) == self.netinfo.num_faulty() + 1 && !self.ready_sent {
            // Enqueue a broadcast of a Ready message.
            step.extend(self.send_ready(hash)?);
        }
        // Upon receiving 2f + 1 matching Ready(h) messages, send full
        // `Echo` message to every node who hasn't sent us a `CanDecode`
        if self.count_readys(hash) == 2 * self.netinfo.num_faulty() + 1 {
            step.extend(self.send_echo_remaining(hash)?);
        }

        Ok(step.join(self.compute_output(hash)?))
    }

    /// Sends `Echo` message to all left nodes and handles it.
    fn send_echo_left(&mut self, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        let echo_msg = Message::Echo(p.clone());
        let mut step = Step::default();
        // `N - 2f + g` node ids to the left of our_id (excluding our_id)
        // after arranging all node ids in a circular list.
        let left = self
            .netinfo
            .all_ids()
            .cycle()
            .skip_while(|x| *x != self.our_id())
            .take(self.netinfo.num_correct() - self.netinfo.num_faulty() + self.fault_estimate)
            .skip(1);
        for id in left {
            let msg = Target::Node(id.clone()).message(echo_msg.clone());
            step.messages.push(msg);
        }
        // Send `Echo` message to all non-validating nodes.
        step.extend(
            Target::AllExcept(self.netinfo.all_ids().cloned().collect::<BTreeSet<_>>())
                .message(echo_msg)
                .into(),
        );
        let our_id = &self.our_id().clone();
        Ok(step.join(self.handle_echo(our_id, p)?))
    }

    /// Sends `Echo` message to remaining nodes who haven't sent `CanDecode`
    fn send_echo_remaining(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.echo_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }

        let p = match self.echos.get(self.our_id()) {
            // Haven't received `Echo`.
            None | Some(EchoContent::Hash(_)) => return Ok(Step::default()),
            // Received `Echo` for different hash.
            Some(EchoContent::Full(p)) if p.root_hash() != hash => return Ok(Step::default()),
            Some(EchoContent::Full(p)) => p.clone(),
        };

        let echo_msg = Message::Echo(p);
        let mut step = Step::default();

        if let Some(senders) = self.can_decodes.get(hash) {
            // Remaining node ids to the right of our_id
            // after arranging all node ids in a circular list.
            let right = self
                .netinfo
                .all_ids()
                .cycle()
                .skip_while(|x| *x != self.our_id())
                .skip(self.netinfo.num_correct() - self.netinfo.num_faulty() + self.fault_estimate)
                .take_while(|x| *x != self.our_id());
            let msgs = right
                .filter(|id| !senders.contains(id))
                .map(|id| Target::Node(id.clone()).message(echo_msg.clone()));
            step.messages.extend(msgs);
        }
        Ok(step)
    }

    /// Sends an `EchoHash` message and handles it. Does nothing if we are only an observer.
    fn send_echo_hash(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.echo_hash_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        let echo_hash_msg = Message::EchoHash(*hash);
        let mut step = Step::default();
        // Remaining node ids to the right of our_id
        // after arranging all node ids in a circular list.
        let right = self
            .netinfo
            .all_ids()
            .cycle()
            .skip_while(|x| *x != self.our_id())
            .skip(self.netinfo.num_correct() - self.netinfo.num_faulty() + self.fault_estimate)
            .take_while(|x| *x != self.our_id());
        for id in right {
            let msg = Target::Node(id.clone()).message(echo_hash_msg.clone());
            step.messages.push(msg);
        }
        let our_id = &self.our_id().clone();
        Ok(step.join(self.handle_echo_hash(our_id, hash)?))
    }

    /// Sends a `CanDecode` message and handles it. Does nothing if we are only an observer.
    fn send_can_decode(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.can_decode_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }

        let can_decode_msg = Message::CanDecode(*hash);
        let mut step = Step::default();

        for id in self.netinfo.all_ids() {
            if let Some(EchoContent::Hash(_)) = self.echos.get(id) {
                let msg = Target::Node(id.clone()).message(can_decode_msg.clone());
                step.messages.push(msg);
            }
        }
        let our_id = &self.our_id().clone();
        Ok(step.join(self.handle_can_decode(our_id, hash)?))
    }

    /// Sends a `Ready` message and handles it. Does nothing if we are only an observer.
    fn send_ready(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.ready_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        let ready_msg = Message::Ready(*hash);
        let step: Step<_> = Target::All.message(ready_msg).into();
        let our_id = &self.our_id().clone();
        Ok(step.join(self.handle_ready(our_id, hash)?))
    }

    /// Checks whether the conditions for output are met for this hash, and if so, sets the output
    /// value.
    fn compute_output(&mut self, hash: &Digest) -> Result<Step<N>> {
        if self.decided
            || self.count_readys(hash) <= 2 * self.netinfo.num_faulty()
            || self.count_echos_full(hash) < self.coding.data_shard_count()
        {
            return Ok(Step::default());
        }

        // Upon receiving 2f + 1 matching Ready(h) messages, wait for N − 2f Echo messages.
        let mut leaf_values: Vec<Option<Box<[u8]>>> = self
            .netinfo
            .all_ids()
            .map(|id| {
                self.echos
                    .get(id)
                    .and_then(EchoContent::proof)
                    .and_then(|p| {
                        if p.root_hash() == hash {
                            Some(p.value().clone().into_boxed_slice())
                        } else {
                            None
                        }
                    })
            })
            .collect();
        if let Some(value) = self.decode_from_shards(&mut leaf_values, hash) {
            self.decided = true;
            Ok(Step::default().with_output(value))
        } else {
            let fault_kind = FaultKind::BroadcastDecoding;
            Ok(Fault::new(self.proposer_id.clone(), fault_kind).into())
        }
    }

    /// Interpolates the missing shards and glues together the data shards to retrieve the value.
    /// This returns `None` if reconstruction failed or the reconstructed shards don't match the
    /// root hash. This can only happen if the proposer provided invalid shards.
    fn decode_from_shards(
        &self,
        leaf_values: &mut [Option<Box<[u8]>>],
        root_hash: &Digest,
    ) -> Option<Vec<u8>> {
        // Try to interpolate the Merkle tree using the Reed-Solomon erasure coding scheme.
        self.coding.reconstruct_shards(leaf_values).ok()?;

        // Collect shards for tree construction.
        let shards: Vec<Vec<u8>> = leaf_values
            .iter()
            .filter_map(|l| l.as_ref().map(|v| v.to_vec()))
            .collect();

        debug!("{}: Reconstructed shards: {:0.10}", self, HexList(&shards));

        // Construct the Merkle tree.
        let mtree = MerkleTree::from_vec(shards);
        // If the root hash of the reconstructed tree does not match the one
        // received with proofs then abort.
        if mtree.root_hash() != root_hash {
            return None; // The proposer is faulty.
        }

        // Reconstruct the value from the data shards:
        // Concatenate the leaf values that are data shards The first four bytes are
        // interpreted as the payload size, and the padding beyond that size is dropped.
        let count = self.coding.data_shard_count();
        let mut bytes = mtree.into_values().into_iter().take(count).flatten();
        let payload_len = match (bytes.next(), bytes.next(), bytes.next(), bytes.next()) {
            (Some(b0), Some(b1), Some(b2), Some(b3)) => {
                BigEndian::read_u32(&[b0, b1, b2, b3]) as usize
            }
            _ => return None, // The proposer is faulty: no payload size.
        };
        let payload: Vec<u8> = bytes.take(payload_len).collect();
        debug!("{}: Glued data shards {:0.10}", self, HexFmt(&payload));
        Some(payload)
    }

    /// Returns `true` if the proof is valid and has the same index as the node ID.
    fn validate_proof(&self, p: &Proof<Vec<u8>>, id: &N) -> bool {
        self.netinfo.node_index(id) == Some(p.index()) && p.validate(self.netinfo.num_nodes())
    }

    /// Returns the number of nodes that have sent us a full `Echo` message with this hash.
    fn count_echos_full(&self, hash: &Digest) -> usize {
        self.echos
            .values()
            .filter_map(EchoContent::proof)
            .filter(|p| p.root_hash() == hash)
            .count()
    }

    /// Returns the number of nodes that have sent us an `Echo` or `EchoHash` message with this hash.
    fn count_echos(&self, hash: &Digest) -> usize {
        self.echos.values().filter(|v| v.hash() == hash).count()
    }

    /// Returns the number of nodes that have sent us a `Ready` message with this hash.
    fn count_readys(&self, hash: &Digest) -> usize {
        self.readys
            .values()
            .filter(|h| h.as_slice() == hash)
            .count()
    }
}

impl<N: NodeIdT> fmt::Display for Broadcast<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> result::Result<(), fmt::Error> {
        write!(f, "{:?} Broadcast({:?})", self.our_id(), self.proposer_id)
    }
}

/// A wrapper for `ReedSolomon` that doesn't panic if there are no parity shards.
#[derive(Debug)]
enum Coding {
    /// A `ReedSolomon` instance with at least one parity shard.
    ReedSolomon(Box<ReedSolomon>),
    /// A no-op replacement that doesn't encode or decode anything.
    Trivial(usize),
}

impl Coding {
    /// Creates a new `Coding` instance with the given number of shards.
    fn new(data_shard_num: usize, parity_shard_num: usize) -> RseResult<Self> {
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
    fn encode(&self, slices: &mut [&mut [u8]]) -> RseResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.encode(slices),
            Coding::Trivial(_) => Ok(()),
        }
    }

    /// If enough shards are present, reconstructs the missing ones.
    fn reconstruct_shards(&self, shards: &mut [Option<Box<[u8]>>]) -> RseResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.reconstruct_shards(shards),
            Coding::Trivial(_) => {
                if shards.iter().all(Option::is_some) {
                    Ok(())
                } else {
                    Err(rse::Error::TooFewShardsPresent)
                }
            }
        }
    }
}

/// Content for `EchoHash` and `Echo` messages.
#[derive(Debug)]
enum EchoContent {
    /// `EchoHash` message.
    Hash(Digest),
    /// `Echo` message
    Full(Proof<Vec<u8>>),
}

impl EchoContent {
    /// Returns hash of the message from either message types.
    pub fn hash(&self) -> &Digest {
        match &self {
            EchoContent::Hash(h) => h,
            EchoContent::Full(p) => p.root_hash(),
        }
    }

    /// Returns Proof if type is Full else returns None.
    pub fn proof(&self) -> Option<&Proof<Vec<u8>>> {
        match &self {
            EchoContent::Hash(_) => None,
            EchoContent::Full(p) => Some(p),
        }
    }
}
