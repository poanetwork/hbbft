use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::iter::once;

use failure::Fail;

use crypto::{self, PublicKey, PublicKeySet, PublicKeyShare, SecretKey, SecretKeyShare};
use fault_log::{Fault, FaultLog};
use traits::{Message, NodeIdT};

/// Message sent by a given source.
#[derive(Clone, Debug)]
pub struct SourcedMessage<M, N> {
    pub source: N,
    pub message: M,
}

/// Message destination can be either of the two:
///
/// 1) `All`: all remote nodes.
///
/// 2) `Node(id)`: remote node `id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target<N> {
    All,
    Node(N),
}

impl<N: Ord> Ord for Target<N> {
    fn cmp(&self, other: &Target<N>) -> Ordering {
        match (self, other) {
            (Target::Node(id1), Target::Node(id2)) => id1.cmp(id2),
            (Target::All, Target::All) => Ordering::Equal,
            (Target::All, Target::Node(_)) => Ordering::Greater,
            (Target::Node(_), Target::All) => Ordering::Less,
        }
    }
}

impl<N: PartialEq> PartialOrd for Target<N> {
    fn partial_cmp(&self, other: &Target<N>) -> Option<Ordering> {
        match (self, other) {
            (Target::Node(id1), Target::Node(id2)) => if id1 == id2 {
                Some(Ordering::Equal)
            } else {
                None
            },
            (Target::All, Target::All) => Some(Ordering::Equal),
            (Target::All, Target::Node(_)) => Some(Ordering::Greater),
            (Target::Node(_), Target::All) => Some(Ordering::Less),
        }
    }
}

impl<N> Target<N> {
    /// Returns a `TargetedMessage` with this target, and the given message.
    pub fn message<M>(self, message: M) -> TargetedMessage<M, N> {
        TargetedMessage {
            target: self,
            message,
        }
    }
}

/// Message with a designated target.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetedMessage<M, N> {
    pub target: Target<N>,
    pub message: M,
}

impl<M, N> TargetedMessage<M, N> {
    /// Applies the given transformation of messages, preserving the target.
    pub fn map<T, F: Fn(M) -> T>(self, f: F) -> TargetedMessage<T, N> {
        TargetedMessage {
            target: self.target,
            message: f(self.message),
        }
    }
}

impl<M, N> TargetedMessage<M, N>
where
    N: PartialEq,
{
    /// Tests whether the given target node is contained in the message target.
    pub fn has_target_node(&self, id: N) -> bool {
        Target::Node(id).partial_cmp(&self.target).is_some()
    }
}

/// Result of one step of the local state machine of a distributed algorithm. Such a result should
/// be used and never discarded by the client of the algorithm.
#[must_use = "The algorithm step result must be used."]
#[derive(Debug)]
pub struct Step<D>
where
    D: DistAlgorithm,
    <D as DistAlgorithm>::NodeId: NodeIdT,
{
    pub output: VecDeque<D::Output>,
    pub fault_log: FaultLog<D::NodeId>,
    pub messages: VecDeque<TargetedMessage<D::Message, D::NodeId>>,
}

impl<D> Default for Step<D>
where
    D: DistAlgorithm,
    <D as DistAlgorithm>::NodeId: NodeIdT,
{
    fn default() -> Step<D> {
        Step {
            output: VecDeque::default(),
            fault_log: FaultLog::default(),
            messages: VecDeque::default(),
        }
    }
}

impl<D: DistAlgorithm> Step<D>
where
    <D as DistAlgorithm>::NodeId: NodeIdT,
{
    /// Creates a new `Step` from the given collections.
    pub fn new(
        output: VecDeque<D::Output>,
        fault_log: FaultLog<D::NodeId>,
        messages: VecDeque<TargetedMessage<D::Message, D::NodeId>>,
    ) -> Self {
        Step {
            output,
            fault_log,
            messages,
        }
    }

    /// Returns the same step, with the given additional output.
    pub fn with_output(mut self, output: D::Output) -> Self {
        self.output.push_back(output);
        self
    }

    /// Converts `self` into a step of another type, given conversion methods for output and
    /// messages.
    pub fn map<D2, FO, FM>(self, f_out: FO, f_msg: FM) -> Step<D2>
    where
        D2: DistAlgorithm<NodeId = D::NodeId>,
        FO: Fn(D::Output) -> D2::Output,
        FM: Fn(D::Message) -> D2::Message,
    {
        Step {
            output: self.output.into_iter().map(f_out).collect(),
            fault_log: self.fault_log,
            messages: self.messages.into_iter().map(|tm| tm.map(&f_msg)).collect(),
        }
    }

    /// Extends `self` with `other`s messages and fault logs, and returns `other.output`.
    pub fn extend_with<D2, FM>(&mut self, other: Step<D2>, f_msg: FM) -> VecDeque<D2::Output>
    where
        D2: DistAlgorithm<NodeId = D::NodeId>,
        FM: Fn(D2::Message) -> D::Message,
    {
        self.fault_log.extend(other.fault_log);
        let msgs = other.messages.into_iter().map(|tm| tm.map(&f_msg));
        self.messages.extend(msgs);
        other.output
    }

    /// Adds the outputs, fault logs and messages of `other` to `self`.
    pub fn extend(&mut self, other: Self) {
        self.output.extend(other.output);
        self.fault_log.extend(other.fault_log);
        self.messages.extend(other.messages);
    }

    /// Converts this step into an equivalent step for a different `DistAlgorithm`.
    // This cannot be a `From` impl, because it would conflict with `impl From<T> for T`.
    pub fn convert<D2>(self) -> Step<D2>
    where
        D2: DistAlgorithm<NodeId = D::NodeId, Output = D::Output, Message = D::Message>,
    {
        Step {
            output: self.output,
            fault_log: self.fault_log,
            messages: self.messages,
        }
    }

    /// Returns `true` if there are now messages, faults or outputs.
    pub fn is_empty(&self) -> bool {
        self.output.is_empty() && self.fault_log.is_empty() && self.messages.is_empty()
    }
}

impl<D: DistAlgorithm> From<FaultLog<D::NodeId>> for Step<D> {
    fn from(fault_log: FaultLog<D::NodeId>) -> Self {
        Step {
            fault_log,
            ..Step::default()
        }
    }
}

impl<D: DistAlgorithm> From<Fault<D::NodeId>> for Step<D> {
    fn from(fault: Fault<D::NodeId>) -> Self {
        Step {
            fault_log: fault.into(),
            ..Step::default()
        }
    }
}

impl<D: DistAlgorithm> From<TargetedMessage<D::Message, D::NodeId>> for Step<D> {
    fn from(msg: TargetedMessage<D::Message, D::NodeId>) -> Self {
        Step {
            messages: once(msg).collect(),
            ..Step::default()
        }
    }
}

impl<D, I> From<I> for Step<D>
where
    D: DistAlgorithm,
    I: IntoIterator<Item = TargetedMessage<D::Message, D::NodeId>>,
{
    fn from(msgs: I) -> Self {
        Step {
            messages: msgs.into_iter().collect(),
            ..Step::default()
        }
    }
}

/// A distributed algorithm that defines a message flow.
pub trait DistAlgorithm {
    /// Unique node identifier.
    type NodeId: NodeIdT;
    /// The input provided by the user.
    type Input;
    /// The output type. Some algorithms return an output exactly once, others return multiple
    /// times.
    type Output;
    /// The messages that need to be exchanged between the instances in the participating nodes.
    type Message: Message;
    /// The errors that can occur during execution.
    type Error: Fail;

    /// Handles an input provided by the user, and returns
    fn handle_input(&mut self, input: Self::Input) -> Result<Step<Self>, Self::Error>
    where
        Self: Sized;

    /// Handles a message received from node `sender_id`.
    fn handle_message(
        &mut self,
        sender_id: &Self::NodeId,
        message: Self::Message,
    ) -> Result<Step<Self>, Self::Error>
    where
        Self: Sized;

    /// Returns `true` if execution has completed and this instance can be dropped.
    fn terminated(&self) -> bool;

    /// Returns this node's own ID.
    fn our_id(&self) -> &Self::NodeId;
}

/// Common data shared between algorithms: the nodes' IDs and key shares.
#[derive(Debug, Clone)]
pub struct NetworkInfo<N> {
    our_id: N,
    num_nodes: usize,
    num_faulty: usize,
    is_validator: bool,
    // TODO: Should this be an option? It only makes sense for validators.
    secret_key_share: SecretKeyShare,
    secret_key: SecretKey,
    public_key_set: PublicKeySet,
    public_key_shares: BTreeMap<N, PublicKeyShare>,
    public_keys: BTreeMap<N, PublicKey>,
    node_indices: BTreeMap<N, usize>,
}

impl<N: NodeIdT> NetworkInfo<N> {
    pub fn new(
        our_id: N,
        secret_key_share: SecretKeyShare,
        public_key_set: PublicKeySet,
        secret_key: SecretKey,
        public_keys: BTreeMap<N, PublicKey>,
    ) -> Self {
        let num_nodes = public_keys.len();
        let is_validator = public_keys.contains_key(&our_id);
        let node_indices: BTreeMap<N, usize> = public_keys
            .keys()
            .enumerate()
            .map(|(n, id)| (id.clone(), n))
            .collect();
        let public_key_shares = node_indices
            .iter()
            .map(|(id, idx)| (id.clone(), public_key_set.public_key_share(*idx)))
            .collect();
        NetworkInfo {
            our_id,
            num_nodes,
            num_faulty: (num_nodes - 1) / 3,
            is_validator,
            secret_key_share,
            secret_key,
            public_key_set,
            public_key_shares,
            node_indices,
            public_keys,
        }
    }

    /// The ID of the node the algorithm runs on.
    pub fn our_id(&self) -> &N {
        &self.our_id
    }

    /// ID of all nodes in the network.
    pub fn all_ids(&self) -> impl Iterator<Item = &N> {
        self.public_keys.keys()
    }

    /// The total number _N_ of nodes.
    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    /// The maximum number _f_ of faulty, Byzantine nodes up to which Honey Badger is guaranteed to
    /// be correct.
    pub fn num_faulty(&self) -> usize {
        self.num_faulty
    }

    /// The minimum number _N - f_ of correct nodes with which Honey Badger is guaranteed to be
    /// correct.
    pub fn num_correct(&self) -> usize {
        self.num_nodes - self.num_faulty
    }

    /// Returns our secret key share for threshold cryptography.
    pub fn secret_key_share(&self) -> &SecretKeyShare {
        &self.secret_key_share
    }

    /// Returns our secret key for encryption and signing.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Returns the public key set for threshold cryptography.
    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.public_key_set
    }

    /// Returns the public key share if a node with that ID exists, otherwise `None`.
    pub fn public_key_share(&self, id: &N) -> Option<&PublicKeyShare> {
        self.public_key_shares.get(id)
    }

    /// Returns a map of all node IDs to their public key shares.
    pub fn public_key_share_map(&self) -> &BTreeMap<N, PublicKeyShare> {
        &self.public_key_shares
    }

    /// Returns a map of all node IDs to their public keys.
    pub fn public_key(&self, id: &N) -> Option<&PublicKey> {
        self.public_keys.get(id)
    }

    /// Returns a map of all node IDs to their public keys.
    pub fn public_key_map(&self) -> &BTreeMap<N, PublicKey> {
        &self.public_keys
    }

    /// The index of a node in a canonical numbering of all nodes.
    pub fn node_index(&self, id: &N) -> Option<usize> {
        self.node_indices.get(id).cloned()
    }

    /// Returns the unique ID of the Honey Badger invocation.
    ///
    /// FIXME: Using the public key as the invocation ID either requires agreeing on the keys on
    /// each invocation, or makes it unsafe to reuse keys for different invocations. A better
    /// invocation ID would be one that is distributed to all nodes on each invocation and would be
    /// independent from the public key, so that reusing keys would be safer.
    pub fn invocation_id(&self) -> Vec<u8> {
        self.public_key_set.public_key().to_bytes()
    }

    /// Returns `true` if this node takes part in the consensus itself. If not, it is only an
    /// observer.
    pub fn is_validator(&self) -> bool {
        self.is_validator
    }

    /// Returns `true` if the given node takes part in the consensus itself. If not, it is only an
    /// observer.
    pub fn is_node_validator(&self, id: &N) -> bool {
        self.public_keys.contains_key(id)
    }

    /// Generates a map of matching `NetworkInfo`s for testing.
    pub fn generate_map<I>(ids: I) -> Result<BTreeMap<N, NetworkInfo<N>>, crypto::error::Error>
    where
        I: IntoIterator<Item = N>,
    {
        use rand::{self, Rng};

        use crypto::SecretKeySet;

        let mut rng = rand::thread_rng();

        let all_ids: BTreeSet<N> = ids.into_iter().collect();
        let num_faulty = (all_ids.len() - 1) / 3;

        // Generate the keys for threshold cryptography.
        let sk_set = SecretKeySet::random(num_faulty, &mut rng)?;
        let pk_set = sk_set.public_keys();

        // Generate keys for individually signing and encrypting messages.
        let sec_keys: BTreeMap<_, SecretKey> =
            all_ids.iter().map(|id| (id.clone(), rng.gen())).collect();
        let pub_keys: BTreeMap<_, PublicKey> = sec_keys
            .iter()
            .map(|(id, sk)| (id.clone(), sk.public_key()))
            .collect();

        // Create the corresponding `NetworkInfo` for each node.
        let create_netinfo = |(i, id): (usize, N)| {
            let netinfo = NetworkInfo::new(
                id.clone(),
                sk_set.secret_key_share(i)?,
                pk_set.clone(),
                sec_keys[&id].clone(),
                pub_keys.clone(),
            );
            Ok((id, netinfo))
        };
        all_ids
            .into_iter()
            .enumerate()
            .map(create_netinfo)
            .collect()
    }
}
