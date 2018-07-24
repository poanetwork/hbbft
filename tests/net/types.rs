//! Test network types
//!
//! The test networking code uses newtypes to distinguish the sets from which IDs can be drawn, to
//! avoid overloading variable names with semantics. An alternative to `FaultyMessageIdx` is
//! declaring that all variables prefixed `e_` are indices for faulty messages and other similar.
//! This is more error-prone when programming, but the `fmt::Debug` implementations of `Idx` types
//! reflect this notation.
//!
//! All `Idx` types are assumed to wrap-around in case of errors, i.e. if there are only 10 messages
//! of that particular kind, 12356 indicates the seventh message (with index 6) in the queue.

use std::fmt;

/// Index of a message of any kind, currently scheduled for delivery.
#[derive(Clone, Copy)]
pub struct MessageIdx(pub usize);

impl fmt::Debug for MessageIdx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "m_{}", self.0)
    }
}

/// Index of a message scheduled for delivery that originated from or is addressed to a faulty node.
///
/// Only faulty nodes are counted, i.e. given a queue of `[M, F, M', M'', F']` with `M` being valid
/// messages and `F` being faulty ones, `FaultyMessageIdx(1)` would refer to `F'`.
#[derive(Clone, Copy)]
pub struct FaultyMessageIdx(pub usize);

impl fmt::Debug for FaultyMessageIdx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "e_{}", self.0)
    }
}

/// Index of a node of any kind in the list of nodes.
#[derive(Clone, Copy)]
pub struct NodeIdx(pub usize);

impl fmt::Debug for NodeIdx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "n_{}", self.0)
    }
}

/// Index of a node in the list of faulty nodes.
#[derive(Clone, Copy)]
pub struct FaultyNodeIdx(pub usize);

impl fmt::Debug for FaultyNodeIdx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "f_{}", self.0)
    }
}

/// Network operation.
///
/// Network operations advance the state of the test network, they simulate the passage of time
/// and what happens during.
#[derive(Debug)]
pub enum NetworkOp {
    /// Swaps two messages in the message queue.
    Swap(MessageIdx, MessageIdx),
    /// Drops a message to/from a faulty node from the network.
    DropFaulty(FaultyMessageIdx),
    /// Inject a message from a faulty node in the network.
    InjectFaulty(FaultyNodeIdx, ()),
    /// Replay a message sent by/to a faulty node, changing the target and originating node.
    ReplayFaulty(FaultyMessageIdx, NodeIdx),
    /// Handle the next message in the queue.
    HandleMessage,
    /// Handle input from the input queue of node `n`.
    HandleInput(NodeIdx),
}

/// Network operation list.
///
/// Wraps a list of network operations, mainly to implement custom formatting and debug functions.
struct OpList(pub Vec<NetworkOp>);

impl fmt::Debug for OpList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        /// Currently, debug formatting is just passed through. It is conceivable to shorten
        /// the output by grouping `HandleMessage`s in the future.
        self.0.fmt(f)
    }
}
