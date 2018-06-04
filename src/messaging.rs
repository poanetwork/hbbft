use std::collections::BTreeSet;
use std::fmt::Debug;

use pairing::bls12_381::Bls12;

use crypto::{PublicKeySet, SecretKey};

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
#[derive(Debug)]
pub struct NetworkInfo<NodeUid> {
    our_uid: NodeUid,
    all_uids: BTreeSet<NodeUid>,
    num_nodes: usize,
    num_faulty: usize,
    secret_key: SecretKey<Bls12>,
    public_key_set: PublicKeySet<Bls12>,
}

impl<NodeUid: Ord> NetworkInfo<NodeUid> {
    pub fn new(
        our_uid: NodeUid,
        all_uids: BTreeSet<NodeUid>,
        secret_key: SecretKey<Bls12>,
        public_key_set: PublicKeySet<Bls12>,
    ) -> Self {
        if !all_uids.contains(&our_uid) {
            panic!("Missing own ID");
        }
        let num_nodes = all_uids.len();
        NetworkInfo {
            our_uid,
            all_uids,
            num_nodes,
            num_faulty: (num_nodes - 1) / 3,
            secret_key,
            public_key_set,
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
}
