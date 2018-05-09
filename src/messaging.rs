//! The local message delivery system.
use proto::Message;
use std::fmt::Debug;

/// Message sent by a given source. The sources are consensus nodes indexed 1
/// through N where N is the total number of nodes. Sourced messages are
/// required when it is essential to know the message origin but the set of
/// recepients is unknown without further computation which is irrelevant to the
/// message delivery task.
#[derive(Clone, Debug)]
pub struct SourcedMessage<T: Clone + Debug + Send + Sync + AsRef<[u8]>> {
    pub source: usize,
    pub message: Message<T>,
}

/// Message destination can be either of the two:
///
/// 1) `All`: all nodes if sent to socket tasks, or all local algorithm
/// instances if received from socket tasks.
///
/// 2) `Node(i)`: node i or local algorithm instances with the node index i.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    All,
    Node(usize),
}

/// Message with a designated target.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetedMessage<T: Clone + Debug + Send + Sync + AsRef<[u8]>> {
    pub target: Target,
    pub message: Message<T>,
}

impl<T: Clone + Debug + Send + Sync + AsRef<[u8]>> TargetedMessage<T> {
    /// Initialises a message while checking parameter preconditions.
    pub fn new(target: Target, message: Message<T>) -> Self {
        TargetedMessage { target, message }
    }
}
