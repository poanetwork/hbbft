//! Common supertraits for distributed algorithms.

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::iter::once;

use failure::Fail;
use serde::Serialize;

use fault_log::{Fault, FaultLog};
use TargetedMessage;

/// A transaction, user message, etc.
pub trait Contribution: Eq + Debug + Hash + Send + Sync {}
impl<C> Contribution for C where C: Eq + Debug + Hash + Send + Sync {}

/// A peer node's unique identifier.
pub trait NodeIdT: Eq + Ord + Clone + Debug + Hash + Send + Sync {}
impl<N> NodeIdT for N where N: Eq + Ord + Clone + Debug + Hash + Send + Sync {}

/// Messages.
pub trait Message: Debug + Send + Sync {}
impl<M> Message for M where M: Debug + Send + Sync {}

/// Session identifiers.
pub trait SessionIdT: Display + Serialize + Send + Sync + Clone {}
impl<S> SessionIdT for S where S: Display + Serialize + Send + Sync + Clone {}

/// Result of one step of the local state machine of a distributed algorithm. Such a result should
/// be used and never discarded by the client of the algorithm.
#[must_use = "The algorithm step result must be used."]
#[derive(Debug)]
pub struct Step<D>
where
    D: DistAlgorithm,
    <D as DistAlgorithm>::NodeId: NodeIdT,
{
    pub output: Vec<D::Output>,
    pub fault_log: FaultLog<D::NodeId>,
    pub messages: Vec<TargetedMessage<D::Message, D::NodeId>>,
}

impl<D> Default for Step<D>
where
    D: DistAlgorithm,
    <D as DistAlgorithm>::NodeId: NodeIdT,
{
    fn default() -> Step<D> {
        Step {
            output: Vec::default(),
            fault_log: FaultLog::default(),
            messages: Vec::default(),
        }
    }
}

impl<D: DistAlgorithm> Step<D>
where
    <D as DistAlgorithm>::NodeId: NodeIdT,
{
    /// Creates a new `Step` from the given collections.
    pub fn new(
        output: Vec<D::Output>,
        fault_log: FaultLog<D::NodeId>,
        messages: Vec<TargetedMessage<D::Message, D::NodeId>>,
    ) -> Self {
        Step {
            output,
            fault_log,
            messages,
        }
    }

    /// Returns the same step, with the given additional output.
    pub fn with_output<T: Into<Option<D::Output>>>(mut self, output: T) -> Self {
        self.output.extend(output.into());
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
    pub fn extend_with<D2, FM>(&mut self, other: Step<D2>, f_msg: FM) -> Vec<D2::Output>
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

    /// Extends this step with `other` and returns the result.
    pub fn join(mut self, other: Self) -> Self {
        self.extend(other);
        self
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

    /// Returns `true` if there are no messages, faults or outputs.
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

/// A distributed algorithm that defines a message flow.
pub trait DistAlgorithm: Send + Sync {
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
