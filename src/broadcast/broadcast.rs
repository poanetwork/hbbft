use std::collections::BTreeMap;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use hex_fmt::{HexFmt, HexList};
use reed_solomon_erasure as rse;
use reed_solomon_erasure::ReedSolomon;

use super::merkle::{Digest, MerkleTree, Proof};
use super::message::HexProof;
use super::{Error, Message, Result};
use fault_log::{Fault, FaultKind};
use {DistAlgorithm, NetworkInfo, NodeIdT, Target};

/// Broadcast algorithm instance.
#[derive(Debug)]
pub struct Broadcast<N> {
    /// Shared network data.
    netinfo: Arc<NetworkInfo<N>>,
    /// The ID of the sending node.
    proposer_id: N,
    data_shard_num: usize,
    coding: Coding,
    /// Whether we have already multicast `Echo`.
    echo_sent: bool,
    /// Whether we have already multicast `Ready`.
    ready_sent: bool,
    /// Whether we have already output a value.
    decided: bool,
    /// The proofs we have received via `Echo` messages, by sender ID.
    echos: BTreeMap<N, Proof<Vec<u8>>>,
    /// The root hashes we received via `Ready` messages, by sender ID.
    readys: BTreeMap<N, Vec<u8>>,
}

pub type Step<N> = ::Step<Broadcast<N>>;

impl<N: NodeIdT> DistAlgorithm for Broadcast<N> {
    type NodeId = N;
    // TODO: Allow anything serializable and deserializable, i.e. make this a type parameter
    // T: Serialize + DeserializeOwned
    type Input = Vec<u8>;
    type Output = Self::Input;
    type Message = Message;
    type Error = Error;

    fn handle_input(&mut self, input: Self::Input) -> Result<Step<N>> {
        if *self.netinfo.our_id() != self.proposer_id {
            return Err(Error::InstanceCannotPropose);
        }
        // Split the value into chunks/shards, encode them with erasure codes.
        // Assemble a Merkle tree from data and parity shards. Take all proofs
        // from this tree and send them, each to its own node.
        let (proof, mut step) = self.send_shards(input)?;
        let our_id = &self.netinfo.our_id().clone();
        step.extend(self.handle_value(our_id, proof)?);
        Ok(step)
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> Result<Step<N>> {
        if !self.netinfo.is_node_validator(sender_id) {
            return Err(Error::UnknownSender);
        }
        match message {
            Message::Value(p) => self.handle_value(sender_id, p),
            Message::Echo(p) => self.handle_echo(sender_id, p),
            Message::Ready(ref hash) => self.handle_ready(sender_id, hash),
        }
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
        })
    }

    /// Breaks the input value into shards of equal length and encodes them --
    /// and some extra parity shards -- with a Reed-Solomon erasure coding
    /// scheme. The returned value contains the shard assigned to this
    /// node. That shard doesn't need to be sent anywhere. It gets recorded in
    /// the broadcast instance.
    fn send_shards(&mut self, mut value: Vec<u8>) -> Result<(Proof<Vec<u8>>, Step<N>)> {
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

        // Create a Merkle tree from the shards.
        let mtree = MerkleTree::from_vec(shards.into_iter().map(|shard| shard.to_vec()).collect());

        // Default result in case of `proof` error.
        let mut result = Err(Error::ProofConstructionFailed);
        assert_eq!(self.netinfo.num_nodes(), mtree.values().len());

        let mut step = Step::default();
        // Send each proof to a node.
        for (index, id) in self.netinfo.all_ids().enumerate() {
            let proof = mtree.proof(index).ok_or(Error::ProofConstructionFailed)?;
            if *id == *self.netinfo.our_id() {
                // The proof is addressed to this node.
                result = Ok(proof);
            } else {
                // Rest of the proofs are sent to remote nodes.
                let msg = Target::Node(id.clone()).message(Message::Value(proof));
                step.messages.push_back(msg);
            }
        }

        result.map(|proof| (proof, step))
    }

    /// Handles a received echo and verifies the proof it contains.
    fn handle_value(&mut self, sender_id: &N, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        // If the sender is not the proposer or if this is not the first `Value`, ignore.
        if *sender_id != self.proposer_id {
            info!(
                "Node {:?} received Value from {:?} instead of {:?}.",
                self.netinfo.our_id(),
                sender_id,
                self.proposer_id
            );
            let fault_kind = FaultKind::ReceivedValueFromNonProposer;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }
        if self.echo_sent {
            info!("Node {:?} received multiple Values.", self.netinfo.our_id());
            // TODO: should receiving two Values from a node be considered
            // a fault? If so, return a `Fault` here. For now, ignore.
            return Ok(Step::default());
        }

        // If the proof is invalid, log the faulty node behavior and ignore.
        if !self.validate_proof(&p, &self.netinfo.our_id()) {
            return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidProof).into());
        }

        // Otherwise multicast the proof in an `Echo` message, and handle it ourselves.
        self.send_echo(p)
    }

    /// Handles a received `Echo` message.
    fn handle_echo(&mut self, sender_id: &N, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        // If the sender has already sent `Echo`, ignore.
        if self.echos.contains_key(sender_id) {
            info!(
                "Node {:?} received multiple Echos from {:?}.",
                self.netinfo.our_id(),
                sender_id,
            );
            return Ok(Step::default());
        }

        // If the proof is invalid, log the faulty-node behavior, and ignore.
        if !self.validate_proof(&p, sender_id) {
            return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidProof).into());
        }

        let hash = *p.root_hash();

        // Save the proof for reconstructing the tree later.
        self.echos.insert(sender_id.clone(), p);

        if self.ready_sent || self.count_echos(&hash) < self.netinfo.num_correct() {
            return self.compute_output(&hash);
        }

        // Upon receiving `N - f` `Echo`s with this root hash, multicast `Ready`.
        self.send_ready(&hash)
    }

    /// Handles a received `Ready` message.
    fn handle_ready(&mut self, sender_id: &N, hash: &Digest) -> Result<Step<N>> {
        // If the sender has already sent a `Ready` before, ignore.
        if self.readys.contains_key(sender_id) {
            info!(
                "Node {:?} received multiple Readys from {:?}.",
                self.netinfo.our_id(),
                sender_id
            );
            return Ok(Step::default());
        }

        self.readys.insert(sender_id.clone(), hash.to_vec());

        let mut step = Step::default();
        // Upon receiving f + 1 matching Ready(h) messages, if Ready
        // has not yet been sent, multicast Ready(h).
        if self.count_readys(hash) == self.netinfo.num_faulty() + 1 && !self.ready_sent {
            // Enqueue a broadcast of a Ready message.
            step.extend(self.send_ready(hash)?);
        }
        step.extend(self.compute_output(hash)?);
        Ok(step)
    }

    /// Sends an `Echo` message and handles it. Does nothing if we are only an observer.
    fn send_echo(&mut self, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        self.echo_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        let echo_msg = Message::Echo(p.clone());
        let mut step: Step<_> = Target::All.message(echo_msg).into();
        let our_id = &self.netinfo.our_id().clone();
        step.extend(self.handle_echo(our_id, p)?);
        Ok(step)
    }

    /// Sends a `Ready` message and handles it. Does nothing if we are only an observer.
    fn send_ready(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.ready_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        let ready_msg = Message::Ready(*hash);
        let mut step: Step<_> = Target::All.message(ready_msg).into();
        let our_id = &self.netinfo.our_id().clone();
        step.extend(self.handle_ready(our_id, hash)?);
        Ok(step)
    }

    /// Checks whether the conditions for output are met for this hash, and if so, sets the output
    /// value.
    fn compute_output(&mut self, hash: &Digest) -> Result<Step<N>> {
        if self.decided
            || self.count_readys(hash) <= 2 * self.netinfo.num_faulty()
            || self.count_echos(hash) < self.coding.data_shard_count()
        {
            return Ok(Step::default());
        }

        // Upon receiving 2f + 1 matching Ready(h) messages, wait for N − 2f Echo messages.
        let mut leaf_values: Vec<Option<Box<[u8]>>> = self
            .netinfo
            .all_ids()
            .map(|id| {
                self.echos.get(id).and_then(|p| {
                    if p.root_hash() == hash {
                        Some(p.value().clone().into_boxed_slice())
                    } else {
                        None
                    }
                })
            }).collect();
        if let Some(value) =
            decode_from_shards(&mut leaf_values, &self.coding, self.data_shard_num, hash)
        {
            self.decided = true;
            Ok(Step::default().with_output(value))
        } else {
            Ok(Step::default())
        }
    }

    /// Returns `true` if the proof is valid and has the same index as the node ID. Otherwise
    /// logs an info message.
    fn validate_proof(&self, p: &Proof<Vec<u8>>, id: &N) -> bool {
        if !p.validate(self.netinfo.num_nodes()) {
            info!(
                "Node {:?} received invalid proof: {:?}",
                self.netinfo.our_id(),
                HexProof(&p)
            );
            false
        } else if self.netinfo.node_index(id) != Some(p.index()) {
            info!(
                "Node {:?} received proof for wrong position: {:?}.",
                self.netinfo.our_id(),
                HexProof(&p)
            );
            false
        } else {
            true
        }
    }

    /// Returns the number of nodes that have sent us an `Echo` message with this hash.
    fn count_echos(&self, hash: &Digest) -> usize {
        self.echos
            .values()
            .filter(|p| p.root_hash() == hash)
            .count()
    }

    /// Returns the number of nodes that have sent us a `Ready` message with this hash.
    fn count_readys(&self, hash: &Digest) -> usize {
        self.readys
            .values()
            .filter(|h| h.as_slice() == hash)
            .count()
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
    fn new(data_shard_num: usize, parity_shard_num: usize) -> Result<Self> {
        Ok(if parity_shard_num > 0 {
            let rs = ReedSolomon::new(data_shard_num, parity_shard_num)
                .map_err(Error::CodingNewReedSolomon)?;
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
    fn encode(&self, slices: &mut [&mut [u8]]) -> Result<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => {
                rs.encode(slices).map_err(Error::CodingEncodeReedSolomon)?
            }
            Coding::Trivial(_) => (),
        }
        Ok(())
    }

    /// If enough shards are present, reconstructs the missing ones.
    fn reconstruct_shards(&self, shards: &mut [Option<Box<[u8]>>]) -> Result<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs
                .reconstruct_shards(shards)
                .map_err(Error::CodingReconstructShardsReedSolomon)?,
            Coding::Trivial(_) => {
                if shards.iter().any(Option::is_none) {
                    return Err(Error::CodingReconstructShardsTrivialReedSolomon(
                        rse::Error::TooFewShardsPresent,
                    ));
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
    root_hash: &Digest,
) -> Option<Vec<u8>> {
    // Try to interpolate the Merkle tree using the Reed-Solomon erasure coding scheme.
    if let Err(err) = coding.reconstruct_shards(leaf_values) {
        error!("Shard reconstruction failed: {:?}", err); // Faulty proposer
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
    let mtree = MerkleTree::from_vec(shards);
    // If the root hash of the reconstructed tree does not match the one
    // received with proofs then abort.
    if mtree.root_hash() != root_hash {
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
    let mut bytes = m.into_values().into_iter().take(n).flatten();
    let payload_len = match (bytes.next(), bytes.next(), bytes.next(), bytes.next()) {
        (Some(b0), Some(b1), Some(b2), Some(b3)) => BigEndian::read_u32(&[b0, b1, b2, b3]) as usize,
        _ => return None, // The proposing node is faulty: no payload size.
    };
    let payload: Vec<u8> = bytes.take(payload_len).collect();
    debug!("Glued data shards {:?}", HexFmt(&payload));
    Some(payload)
}
