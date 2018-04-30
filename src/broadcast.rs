//! Reliable broadcast algorithm instance.
use crossbeam;
use crossbeam_channel::{Receiver, RecvError, SendError, Sender};
use merkle::proof::{Lemma, Positioned, Proof};
use merkle::{Hashable, MerkleTree};
use proto::*;
use reed_solomon_erasure as rse;
use reed_solomon_erasure::ReedSolomon;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::marker::{Send, Sync};
use std::sync::{Arc, Mutex, RwLock};

use messaging;
use messaging::{AlgoMessage, Algorithm, Handler, LocalMessage, MessageLoopState, NodeUid,
                ProposedValue, QMessage, RemoteMessage, RemoteNode, SourcedMessage, Target,
                TargetedMessage};

struct BroadcastState {
    root_hash: Option<Vec<u8>>,
    leaf_values: Vec<Option<Box<[u8]>>>,
    leaf_values_num: usize,
    echo_num: usize,
    readys: HashMap<Vec<u8>, usize>,
    ready_sent: bool,
    ready_to_decode: bool,
}

/// Reliable Broadcast algorithm instance.
pub struct Broadcast {
    /// The UID of this node.
    uid: NodeUid,
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

impl Broadcast {
    pub fn new(uid: NodeUid, all_uids: HashSet<NodeUid>, num_nodes: usize) -> Result<Self, Error> {
        let num_faulty_nodes = (num_nodes - 1) / 3;
        let parity_shard_num = 2 * num_faulty_nodes;
        let data_shard_num = num_nodes - parity_shard_num;
        let coding = ReedSolomon::new(data_shard_num, parity_shard_num)?;

        Ok(Broadcast {
            uid,
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
            }),
        })
    }

    /// The message-driven interface function for calls from the main message
    /// loop.
    pub fn on_message<E>(&self, m: QMessage, tx: &Sender<QMessage>) -> Result<MessageLoopState, E>
    where
        E: From<Error> + From<messaging::Error>,
    {
        match m {
            QMessage::Local(LocalMessage { message, .. }) => match message {
                AlgoMessage::BroadcastInput(value) => self.on_local_message(&mut value.to_owned()),

                _ => Err(Error::UnexpectedMessage).map_err(E::from),
            },

            QMessage::Remote(RemoteMessage {
                node: RemoteNode::Node(uid),
                message,
            }) => {
                if let Message::Broadcast(b) = message {
                    self.on_remote_message(uid, &b, tx)
                } else {
                    Err(Error::UnexpectedMessage).map_err(E::from)
                }
            }

            _ => Err(Error::UnexpectedMessage).map_err(E::from),
        }
    }

    /// Processes the proposed value input by broadcasting it.
    fn on_local_message<E>(&self, value: &mut ProposedValue) -> Result<MessageLoopState, E>
    where
        E: From<Error> + From<messaging::Error>,
    {
        let mut state = self.state.write().unwrap();
        // Split the value into chunks/shards, encode them with erasure codes.
        // Assemble a Merkle tree from data and parity shards. Take all proofs
        // from this tree and send them, each to its own node.
        self.send_shards(value).map(|(proof, remote_messages)| {
            // Record the first proof as if it were sent by the node to
            // itself.
            let h = proof.root_hash.clone();
            if proof.validate(h.as_slice()) {
                // Save the leaf value for reconstructing the tree later.
                state.leaf_values[index_of_proof(&proof)] =
                    Some(proof.value.clone().into_boxed_slice());
                state.leaf_values_num += 1;
                state.root_hash = Some(h);
            }

            MessageLoopState::Processing(remote_messages)
        })
    }

    /// Breaks the input value into shards of equal length and encodes them --
    /// and some extra parity shards -- with a Reed-Solomon erasure coding
    /// scheme. The returned value contains the shard assigned to this
    /// node. That shard doesn't need to be sent anywhere. It gets recorded in
    /// the broadcast instance.
    fn send_shards<E>(
        &self,
        value: &mut ProposedValue,
    ) -> Result<(Proof<ProposedValue>, VecDeque<RemoteMessage>), E>
    where
        E: From<Error> + From<messaging::Error>,
    {
        let data_shard_num = self.coding.data_shard_count();
        let parity_shard_num = self.coding.parity_shard_count();

        debug!(
            "Data shards: {}, parity shards: {}",
            self.data_shard_num, parity_shard_num
        );
        // Insert the length of `v` so it can be decoded without the padding.
        let payload_len = value.len() as u8;
        value.insert(0, payload_len); // TODO: Handle messages larger than 255
                                      // bytes.
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
        let mut shards: Vec<&mut [u8]> = Vec::new();
        for s in shards_iter {
            shards.push(s);
        }

        debug!("Shards before encoding: {:?}", shards);

        // Construct the parity chunks/shards
        self.coding
            .encode(shards.as_mut_slice())
            .map_err(Error::from)?;

        debug!("Shards: {:?}", shards);

        let shards_t: Vec<ProposedValue> = shards.into_iter().map(|s| s.to_vec()).collect();

        // Convert the Merkle tree into a partial binary tree for later
        // deconstruction into compound branches.
        let mtree = MerkleTree::from_vec(&::ring::digest::SHA256, shards_t);

        // Default result in case of `gen_proof` error.
        let mut result = Err(Error::ProofConstructionFailed);
        let mut outgoing = VecDeque::new();

        // Send each proof to a node.
        for (leaf_value, uid) in mtree.iter().zip(self.all_uids.clone()) {
            let proof = mtree.gen_proof(leaf_value.to_vec());
            if let Some(proof) = proof {
                if uid == self.uid {
                    // The proof is addressed to this node.
                    result = Ok(proof);
                } else {
                    // Rest of the proofs are sent to remote nodes.
                    outgoing.push_back(RemoteMessage {
                        node: RemoteNode::Node(uid),
                        message: Message::Broadcast(BroadcastMessage::Value(proof)),
                    });
                }
            }
        }

        result.map(|r| (r, outgoing)).map_err(E::from)
    }

    /// Handler of messages received from remote nodes.
    fn on_remote_message<E>(
        &self,
        uid: NodeUid,
        message: &BroadcastMessage<ProposedValue>,
        tx: &Sender<QMessage>,
    ) -> Result<MessageLoopState, E>
    where
        E: From<Error> + From<messaging::Error>,
    {
        let mut state = self.state.write().unwrap();
        let no_outgoing = Ok(MessageLoopState::Processing(VecDeque::new()));

        // A value received. Record the value and multicast an echo.
        match message {
            BroadcastMessage::Value(p) => {
                if uid != self.uid {
                    // Ignore value messages from unrelated remote nodes.
                    no_outgoing
                } else {
                    // Initialise the root hash if not already initialised.
                    if state.root_hash.is_none() {
                        state.root_hash = Some(p.root_hash.clone());
                        debug!(
                            "Node {} Value root hash {:?}",
                            self.uid,
                            HexBytes(&p.root_hash)
                        );
                    }

                    if let Some(ref h) = state.root_hash.clone() {
                        if p.validate(h.as_slice()) {
                            // Save the leaf value for reconstructing the tree
                            // later.
                            state.leaf_values[index_of_proof(&p)] =
                                Some(p.value.clone().into_boxed_slice());
                            state.leaf_values_num += 1;
                        }
                    }

                    // Enqueue a broadcast of an echo of this proof.
                    Ok(MessageLoopState::Processing(VecDeque::from(vec![
                        RemoteMessage {
                            node: RemoteNode::All,
                            message: Message::Broadcast(BroadcastMessage::Echo(p.clone())),
                        },
                    ])))
                }
            }

            // An echo received. Verify the proof it contains.
            BroadcastMessage::Echo(p) => {
                if state.root_hash.is_none() && uid == self.uid {
                    state.root_hash = Some(p.root_hash.clone());
                    debug!("Node {} Echo root hash {:?}", self.uid, state.root_hash);
                }

                // Call validate with the root hash as argument.
                if let Some(ref h) = state.root_hash.clone() {
                    if p.validate(h.as_slice()) {
                        state.echo_num += 1;
                        // Save the leaf value for reconstructing the
                        // tree later.
                        state.leaf_values[index_of_proof(&p)] =
                            Some(p.value.clone().into_boxed_slice());
                        state.leaf_values_num += 1;

                        // Upon receiving 2f + 1 matching READY(h)
                        // messages, wait for N − 2 f ECHO messages,
                        // then decode v. Return the decoded v to ACS.
                        if state.ready_to_decode
                            && state.leaf_values_num >= self.num_nodes - 2 * self.num_faulty_nodes
                        {
                            let value = decode_from_shards(
                                &mut state.leaf_values,
                                &self.coding,
                                self.data_shard_num,
                                h,
                            )?;
                            tx.send(QMessage::Local(LocalMessage {
                                dst: Algorithm::CommonSubset,
                                message: AlgoMessage::BroadcastOutput(uid, value),
                            })).map_err(Error::from)?;

                            no_outgoing
                        } else if state.leaf_values_num >= self.num_nodes - self.num_faulty_nodes {
                            let result: Result<ProposedValue, Error> = decode_from_shards(
                                &mut state.leaf_values,
                                &self.coding,
                                self.data_shard_num,
                                h,
                            );
                            match result {
                                Ok(_) => {
                                    // if Ready has not yet been sent, multicast
                                    // Ready
                                    if !state.ready_sent {
                                        state.ready_sent = true;

                                        Ok(MessageLoopState::Processing(VecDeque::from(vec![
                                            RemoteMessage {
                                                node: RemoteNode::All,
                                                message: Message::Broadcast(
                                                    BroadcastMessage::Ready(h.to_owned()),
                                                ),
                                            },
                                        ])))
                                    } else {
                                        no_outgoing
                                    }
                                }
                                Err(e) => Err(E::from(e)),
                            }
                        } else {
                            no_outgoing
                        }
                    } else {
                        debug!("Broadcast/{} cannot validate Echo {:?}", self.uid, p);
                        no_outgoing
                    }
                } else {
                    error!("Broadcast/{} root hash not initialised", self.uid);
                    no_outgoing
                }
            }

            BroadcastMessage::Ready(ref hash) => {
                // Update the number Ready has been received with this hash.
                *state.readys.entry(hash.to_vec()).or_insert(1) += 1;

                // Check that the root hash matches.
                if let Some(ref h) = state.root_hash.clone() {
                    let ready_num = *state.readys.get(h).unwrap_or(&0);
                    let mut outgoing = VecDeque::new();

                    // Upon receiving f + 1 matching Ready(h) messages, if Ready
                    // has not yet been sent, multicast Ready(h).
                    if (ready_num == self.num_faulty_nodes + 1) && !state.ready_sent {
                        // Enqueue a broadcast of a ready message.
                        outgoing.push_back(RemoteMessage {
                            node: RemoteNode::All,
                            message: Message::Broadcast(BroadcastMessage::Ready(h.to_vec())),
                        });
                    }

                    // Upon receiving 2f + 1 matching Ready(h) messages, wait
                    // for N − 2f Echo messages, then decode v.
                    if ready_num > 2 * self.num_faulty_nodes {
                        // Wait for N - 2f Echo messages, then decode v.
                        if state.echo_num >= self.num_nodes - 2 * self.num_faulty_nodes {
                            let value = decode_from_shards(
                                &mut state.leaf_values,
                                &self.coding,
                                self.data_shard_num,
                                h,
                            )?;

                            tx.send(QMessage::Local(LocalMessage {
                                dst: Algorithm::CommonSubset,
                                message: AlgoMessage::BroadcastOutput(self.uid, value),
                            })).map_err(Error::from)?;
                        } else {
                            state.ready_to_decode = true;
                        }
                    }

                    Ok(MessageLoopState::Processing(outgoing))
                } else {
                    no_outgoing
                }
            }
        }
    }
}

impl<'a, E> Handler<E> for Broadcast
where
    E: From<Error> + From<messaging::Error>,
{
    fn handle(&self, m: QMessage, tx: Sender<QMessage>) -> Result<MessageLoopState, E> {
        self.on_message(m, &tx)
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
    /// Value to be broadcast.
    broadcast_value: Option<T>,
    /// This instance's index for identification against its comms task.
    node_index: usize,
    /// Number of nodes participating in broadcast.
    num_nodes: usize,
    /// Maximum allowed number of faulty nodes.
    num_faulty_nodes: usize,
}

impl<'a, T: Clone + Debug + Hashable + Send + Sync + Into<Vec<u8>> + From<Vec<u8>>>
    Instance<'a, T>
{
    pub fn new(
        tx: &'a Sender<TargetedMessage<ProposedValue>>,
        rx: &'a Receiver<SourcedMessage<ProposedValue>>,
        broadcast_value: Option<T>,
        num_nodes: usize,
        node_index: usize,
    ) -> Self {
        Instance {
            tx,
            rx,
            broadcast_value,
            node_index,
            num_nodes,
            num_faulty_nodes: (num_nodes - 1) / 3,
        }
    }

    /// Broadcast stage task returning the computed values in case of success,
    /// and an error in case of failure.
    pub fn run(&mut self) -> Result<T, Error> {
        // Broadcast state machine thread.
        let bvalue = self.broadcast_value.to_owned();
        let result: Result<T, Error>;
        let result_r = Arc::new(Mutex::new(None));
        let result_r_scoped = result_r.clone();

        crossbeam::scope(|scope| {
            scope.spawn(move || {
                *result_r_scoped.lock().unwrap() = Some(inner_run(
                    self.tx,
                    self.rx,
                    bvalue,
                    self.node_index,
                    self.num_nodes,
                    self.num_faulty_nodes,
                ));
            });
        });
        if let Some(ref r) = *result_r.lock().unwrap() {
            result = r.to_owned();
        } else {
            result = Err(Error::Threading);
        }
        result
    }
}

/// Errors returned by the broadcast instance.
#[derive(Debug, Clone)]
pub enum Error {
    RootHashMismatch,
    Threading,
    ProofConstructionFailed,
    ReedSolomon(rse::Error),
    Send(SendError<QMessage>),
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

impl From<SendError<QMessage>> for Error {
    fn from(err: SendError<QMessage>) -> Error {
        Error::Send(err)
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

/// Breaks the input value into shards of equal length and encodes them -- and
/// some extra parity shards -- with a Reed-Solomon erasure coding scheme. The
/// returned value contains the shard assigned to this node. That shard doesn't
/// need to be sent anywhere. It is returned to the broadcast instance and gets
/// recorded immediately.
fn send_shards<'a, T>(
    value: T,
    tx: &'a Sender<TargetedMessage<ProposedValue>>,
    coding: &ReedSolomon,
) -> Result<Proof<ProposedValue>, Error>
where
    T: Clone + Debug + Hashable + Send + Sync + Into<Vec<u8>> + From<Vec<u8>>,
{
    let data_shard_num = coding.data_shard_count();
    let parity_shard_num = coding.parity_shard_count();

    debug!(
        "Data shards: {}, parity shards: {}",
        data_shard_num, parity_shard_num
    );
    let mut v: Vec<u8> = T::into(value);
    // Insert the length of `v` so it can be decoded without the padding.
    let payload_len = v.len() as u8;
    v.insert(0, payload_len); // TODO: Handle messages larger than 255 bytes.
    let value_len = v.len();
    // Size of a Merkle tree leaf value, in bytes.
    let shard_len = if value_len % data_shard_num > 0 {
        value_len / data_shard_num + 1
    } else {
        value_len / data_shard_num
    };
    // Pad the last data shard with zeros. Fill the parity shards with zeros.
    v.resize(shard_len * (data_shard_num + parity_shard_num), 0);

    debug!("value_len {}, shard_len {}", value_len, shard_len);

    // Divide the vector into chunks/shards.
    let shards_iter = v.chunks_mut(shard_len);
    // Convert the iterator over slices into a vector of slices.
    let mut shards: Vec<&mut [u8]> = Vec::new();
    for s in shards_iter {
        shards.push(s);
    }

    debug!("Shards before encoding: {:?}", shards);

    // Construct the parity chunks/shards
    coding.encode(shards.as_mut_slice())?;

    debug!("Shards: {:?}", shards);

    let shards_t: Vec<ProposedValue> = shards.into_iter().map(|s| s.to_vec()).collect();

    // Convert the Merkle tree into a partial binary tree for later
    // deconstruction into compound branches.
    let mtree = MerkleTree::from_vec(&::ring::digest::SHA256, shards_t);

    // Default result in case of `gen_proof` error.
    let mut result = Err(Error::ProofConstructionFailed);

    // Send each proof to a node.
    for (i, leaf_value) in mtree.iter().enumerate() {
        let proof = mtree.gen_proof(leaf_value.to_vec());
        if let Some(proof) = proof {
            if i == 0 {
                // The first proof is addressed to this node.
                result = Ok(proof);
            } else {
                // Rest of the proofs are sent to remote nodes.
                tx.send(TargetedMessage {
                    target: Target::Node(i),
                    message: Message::Broadcast(BroadcastMessage::Value(proof)),
                })?;
            }
        }
    }

    result
}

/// The main loop of the broadcast task.
fn inner_run<'a, T>(
    tx: &'a Sender<TargetedMessage<ProposedValue>>,
    rx: &'a Receiver<SourcedMessage<ProposedValue>>,
    broadcast_value: Option<T>,
    node_index: usize,
    num_nodes: usize,
    num_faulty_nodes: usize,
) -> Result<T, Error>
where
    T: Clone + Debug + Hashable + Send + Sync + Into<Vec<u8>> + From<Vec<u8>>,
{
    // Erasure coding scheme: N - 2f value shards and 2f parity shards
    let parity_shard_num = 2 * num_faulty_nodes;
    let data_shard_num = num_nodes - parity_shard_num;
    let coding = ReedSolomon::new(data_shard_num, parity_shard_num)?;
    // currently known leaf values
    let mut leaf_values: Vec<Option<Box<[u8]>>> = vec![None; num_nodes];
    // Write-once root hash of a tree broadcast from the sender associated with
    // this instance.
    let mut root_hash: Option<Vec<u8>> = None;
    // number of non-None leaf values
    let mut leaf_values_num = 0;

    // Split the value into chunks/shards, encode them with erasure codes.
    // Assemble a Merkle tree from data and parity shards. Take all proofs from
    // this tree and send them, each to its own node.
    if let Some(v) = broadcast_value {
        send_shards(v, tx, &coding).map(|proof| {
            // Record the first proof as if it were sent by the node to
            // itself.
            let h = proof.root_hash.clone();
            if proof.validate(h.as_slice()) {
                // Save the leaf value for reconstructing the tree later.
                leaf_values[index_of_proof(&proof)] = Some(proof.value.clone().into_boxed_slice());
                leaf_values_num += 1;
                root_hash = Some(h);
            }
        })?
    }

    // return value
    let mut result: Option<Result<T, Error>> = None;
    // Number of times Echo was received with the same root hash.
    let mut echo_num = 0;
    // Number of times Ready was received with the same root hash.
    let mut readys: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut ready_sent = false;
    let mut ready_to_decode = false;

    // TODO: handle exit conditions
    while result.is_none() {
        // Receive a message from the socket IO task.
        let message = rx.recv()?;
        if let SourcedMessage {
            source: i,
            message: Message::Broadcast(message),
        } = message
        {
            match message {
                // A value received. Record the value and multicast an echo.
                BroadcastMessage::Value(p) => {
                    if i != node_index {
                        // Ignore value messages from unrelated remote nodes.
                        continue;
                    }

                    if root_hash.is_none() {
                        root_hash = Some(p.root_hash.clone());
                        debug!(
                            "Node {} Value root hash {:?}",
                            node_index,
                            HexBytes(&p.root_hash)
                        );
                    }

                    if let Some(ref h) = root_hash {
                        if p.validate(h.as_slice()) {
                            // Save the leaf value for reconstructing the tree
                            // later.
                            leaf_values[index_of_proof(&p)] =
                                Some(p.value.clone().into_boxed_slice());
                            leaf_values_num += 1;
                        }
                    }
                    // Broadcast an echo of this proof.
                    tx.send(TargetedMessage {
                        target: Target::All,
                        message: Message::Broadcast(BroadcastMessage::Echo(p)),
                    })?
                }

                // An echo received. Verify the proof it contains.
                BroadcastMessage::Echo(p) => {
                    if root_hash.is_none() && i == node_index {
                        root_hash = Some(p.root_hash.clone());
                        debug!("Node {} Echo root hash {:?}", node_index, root_hash);
                    }

                    // call validate with the root hash as argument
                    if let Some(ref h) = root_hash {
                        if p.validate(h.as_slice()) {
                            echo_num += 1;
                            // Save the leaf value for reconstructing the tree
                            // later.
                            leaf_values[index_of_proof(&p)] =
                                Some(p.value.clone().into_boxed_slice());
                            leaf_values_num += 1;

                            // upon receiving 2f + 1 matching READY(h)
                            // messages, wait for N − 2 f ECHO messages, then
                            // decode v
                            if ready_to_decode
                                && leaf_values_num >= num_nodes - 2 * num_faulty_nodes
                            {
                                result = Some(decode_from_shards(
                                    &mut leaf_values,
                                    &coding,
                                    data_shard_num,
                                    h,
                                ));
                            } else if leaf_values_num >= num_nodes - num_faulty_nodes {
                                result = Some(decode_from_shards(
                                    &mut leaf_values,
                                    &coding,
                                    data_shard_num,
                                    h,
                                ));
                                // if Ready has not yet been sent, multicast
                                // Ready
                                if !ready_sent {
                                    ready_sent = true;
                                    tx.send(TargetedMessage {
                                        target: Target::All,
                                        message: Message::Broadcast(BroadcastMessage::Ready(
                                            h.to_owned(),
                                        )),
                                    })?;
                                }
                            }
                        }
                    }
                }

                BroadcastMessage::Ready(ref hash) => {
                    // Update the number Ready has been received with this hash.
                    *readys.entry(hash.to_vec()).or_insert(1) += 1;

                    // Check that the root hash matches.
                    if let Some(ref h) = root_hash {
                        let ready_num: usize = *readys.get(h).unwrap_or(&0);

                        // Upon receiving f + 1 matching Ready(h) messages, if
                        // Ready has not yet been sent, multicast Ready(h).
                        if (ready_num == num_faulty_nodes + 1) && !ready_sent {
                            tx.send(TargetedMessage {
                                target: Target::All,
                                message: Message::Broadcast(BroadcastMessage::Ready(h.to_vec())),
                            })?;
                        }

                        // Upon receiving 2f + 1 matching Ready(h) messages,
                        // wait for N − 2f Echo messages, then decode v.
                        if ready_num > 2 * num_faulty_nodes {
                            // Wait for N - 2f Echo messages, then decode v.
                            if echo_num >= num_nodes - 2 * num_faulty_nodes {
                                result = Some(decode_from_shards(
                                    &mut leaf_values,
                                    &coding,
                                    data_shard_num,
                                    h,
                                ));
                            } else {
                                ready_to_decode = true;
                            }
                        }
                    }
                }
            }
        } else {
            error!("Incorrect message from the socket: {:?}", message);
        }
    }
    // result is not a None, safe to extract value
    result.unwrap()
}

fn decode_from_shards<T>(
    leaf_values: &mut Vec<Option<Box<[u8]>>>,
    coding: &ReedSolomon,
    data_shard_num: usize,
    root_hash: &[u8],
) -> Result<T, Error>
where
    T: Clone + Debug + Hashable + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>,
{
    // Try to interpolate the Merkle tree using the Reed-Solomon erasure coding
    // scheme.
    coding.reconstruct_shards(leaf_values.as_mut_slice())?;

    // Recompute the Merkle tree root.
    //
    // Collect shards for tree construction.
    let mut shards: Vec<ProposedValue> = Vec::new();
    for l in leaf_values.iter() {
        if let Some(ref v) = *l {
            shards.push(v.to_vec());
        }
    }
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
fn index_of_proof(p: &Proof<ProposedValue>) -> usize {
    index_of_path(path_of_lemma(&p.lemma))
}
