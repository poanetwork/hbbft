use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use clear_on_drop::ClearOnDrop;

use crypto::{PublicKey, PublicKeySet, SecretKey};

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

/// A distributed algorithm that defines a message flow.
pub trait DistAlgorithm {
    /// Unique node identifier.
    type NodeUid: Debug + Clone + Ord + Eq;
    /// The input provided by the user.
    type Input;
    /// The output type. Some algorithms return an output exactly once, others return multiple
    /// times.
    type Output;
    /// The messages that need to be exchanged between the instances in the participating nodes.
    type Message: Debug;
    /// The errors that can occur during execution.
    type Error: Debug;

    /// Handles an input provided by the user, and returns
    fn input(&mut self, input: Self::Input) -> Result<(), Self::Error>;

    /// Handles a message received from node `sender_id`.
    fn handle_message(
        &mut self,
        sender_id: &Self::NodeUid,
        message: Self::Message,
    ) -> Result<(), Self::Error>;

    /// Returns a message that needs to be sent to another node.
    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, Self::NodeUid>>;

    /// Returns the algorithm's output.
    fn next_output(&mut self) -> Option<Self::Output>;

    /// Returns `true` if execution has completed and this instance can be dropped.
    fn terminated(&self) -> bool;

    /// Returns this node's own ID.
    fn our_id(&self) -> &Self::NodeUid;

    /// Returns an iterator over the outgoing messages.
    fn message_iter(&mut self) -> MessageIter<Self>
    where
        Self: Sized,
    {
        MessageIter { algorithm: self }
    }

    /// Returns an iterator over the algorithm's outputs.
    fn output_iter(&mut self) -> OutputIter<Self>
    where
        Self: Sized,
    {
        OutputIter { algorithm: self }
    }
}

/// An iterator over a distributed algorithm's outgoing messages.
pub struct MessageIter<'a, D: DistAlgorithm + 'a> {
    algorithm: &'a mut D,
}

impl<'a, D: DistAlgorithm + 'a> Iterator for MessageIter<'a, D> {
    type Item = TargetedMessage<D::Message, D::NodeUid>;

    fn next(&mut self) -> Option<Self::Item> {
        self.algorithm.next_message()
    }
}

/// An iterator over a distributed algorithm's pending outputs.
pub struct OutputIter<'a, D: DistAlgorithm + 'a> {
    algorithm: &'a mut D,
}

impl<'a, D: DistAlgorithm + 'a> Iterator for OutputIter<'a, D> {
    type Item = D::Output;

    fn next(&mut self) -> Option<Self::Item> {
        self.algorithm.next_output()
    }
}

/// Common data shared between algorithms.
///
/// *NOTE* `NetworkInfo` requires its `secret_key` to be heap allocated and
/// wrapped by the `ClearOnDrop` type from the `clear_on_drop` crate. We
/// use this construction to zero out the section of heap memory that is
/// allocated for `secret_key` when the corresponding instance of
/// `NetworkInfo` goes out of scope.
#[derive(Debug, Clone)]
pub struct NetworkInfo<NodeUid> {
    our_uid: NodeUid,
    all_uids: BTreeSet<NodeUid>,
    num_nodes: usize,
    num_faulty: usize,
    is_validator: bool,
    secret_key: ClearOnDrop<Box<SecretKey>>,
    public_key_set: PublicKeySet,
    public_keys: BTreeMap<NodeUid, PublicKey>,
    node_indices: BTreeMap<NodeUid, usize>,
}

impl<NodeUid: Clone + Ord> NetworkInfo<NodeUid> {
    pub fn new(
        our_uid: NodeUid,
        all_uids: BTreeSet<NodeUid>,
        secret_key: ClearOnDrop<Box<SecretKey>>,
        public_key_set: PublicKeySet,
    ) -> Self {
        let num_nodes = all_uids.len();
        let is_validator = all_uids.contains(&our_uid);
        let node_indices: BTreeMap<NodeUid, usize> = all_uids
            .iter()
            .enumerate()
            .map(|(n, id)| (id.clone(), n))
            .collect();
        let public_keys = node_indices
            .iter()
            .map(|(id, idx)| (id.clone(), public_key_set.public_key_share(*idx as u64)))
            .collect();
        NetworkInfo {
            our_uid,
            all_uids,
            num_nodes,
            num_faulty: (num_nodes - 1) / 3,
            is_validator,
            secret_key,
            public_key_set,
            public_keys,
            node_indices,
        }
    }

    /// The ID of the node the algorithm runs on.
    pub fn our_uid(&self) -> &NodeUid {
        &self.our_uid
    }

    /// ID of all nodes in the network.
    pub fn all_uids(&self) -> &BTreeSet<NodeUid> {
        &self.all_uids
    }

    /// The total number of nodes.
    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    /// The maximum number of faulty, Byzantine nodes up to which Honey Badger is guaranteed to be
    /// correct.
    pub fn num_faulty(&self) -> usize {
        self.num_faulty
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.public_key_set
    }

    /// Returns the public key share if a node with that ID exists, otherwise `None`.
    pub fn public_key_share(&self, id: &NodeUid) -> Option<&PublicKey> {
        self.public_keys.get(id)
    }

    /// Returns a map of all node IDs to their public key shares.
    pub fn public_key_map(&self) -> &BTreeMap<NodeUid, PublicKey> {
        &self.public_keys
    }

    /// The index of a node in a canonical numbering of all nodes.
    pub fn node_index(&self, id: &NodeUid) -> Option<&usize> {
        self.node_indices.get(id)
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
}
