use std::collections::BTreeSet;
use std::iter;

/// Message sent by a given source.
#[derive(Clone, Debug)]
pub struct SourcedMessage<M, N> {
    /// The ID of the sender.
    pub source: N,
    /// The content of a message.
    pub message: M,
}

/// The intended recipient(s) of a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target<N> {
    /// The message must be sent to the nodes with the given IDs.
    /// It is _not_ automatically sent to observers.
    Nodes(BTreeSet<N>),
    /// The message must be sent to all remote nodes except the passed nodes.
    /// Useful for sending messages to observer nodes that aren't
    /// present in a node's `all_ids()` list.
    AllExcept(BTreeSet<N>),
}

impl<N: Ord> Target<N> {
    /// Creates a new `Target` addressing all peers, including observers.
    pub fn all() -> Self {
        Target::AllExcept(BTreeSet::new())
    }

    /// Creates a new `Target` addressing a single peer.
    pub fn node(node_id: N) -> Self {
        Target::Nodes(iter::once(node_id).collect())
    }

    /// Returns a `TargetedMessage` with this target, and the given message.
    pub fn message<M>(self, message: M) -> TargetedMessage<M, N> {
        TargetedMessage {
            target: self,
            message,
        }
    }

    /// Returns whether `node_id` is included in this target.
    pub fn contains(&self, node_id: &N) -> bool {
        match self {
            Target::Nodes(ids) => ids.contains(node_id),
            Target::AllExcept(ids) => !ids.contains(node_id),
        }
    }
}

/// Message with a designated target.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetedMessage<M, N> {
    /// The node or nodes that this message must be delivered to.
    pub target: Target<N>,
    /// The content of the message that must be serialized and sent to the target.
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
