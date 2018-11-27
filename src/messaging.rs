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
    /// The message must be sent to all remote nodes.
    All,
    /// The message must be sent to the node with the given ID.
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
