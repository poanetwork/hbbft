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
