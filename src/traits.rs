//! Common supertraits for distributed algorithms.

use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::iter::once;

use failure::Fail;
use rand::Rand;
use serde::{de::DeserializeOwned, Serialize};

use fault_log::{Fault, FaultLog};
use sender_queue::SenderQueueableMessage;
use {Target, TargetedMessage};

/// A transaction, user message, or other user data.
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

/// Single algorithm step outcome.
///
/// Each time input (typically in the form of user input or incoming network messages) is provided
/// to an instance of an algorithm, a `Step` is produced, potentially containing output values,
/// a fault log, and network messages.
///
/// Any `Step` **must always be used** by the client application; at the very least the resulting
/// messages must be queued.
///
/// ## Handling unused Steps
///
/// In the (rare) case of a `Step` not being of any interest at all, instead of discarding it
/// through `let _ = ...` or similar constructs, the implicit assumption should explicitly be
/// checked instead:
///
/// ```ignore
/// assert!(alg.propose(123).expect("Could not propose value").is_empty(),
///         "Algorithm will never output anything on first proposal");
/// ```
///
/// If an edge case occurs and outgoing messages are generated as a result, the `assert!` will
/// catch it, instead of potentially stalling the algorithm.
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

/// An interface to objects with epoch numbers. Different algorithms may have different internal
/// notion of _epoch_. This interface summarizes the properties that are essential for the message
/// sender queue.
pub trait Epoched {
    type Epoch: Copy + Message + Default + Eq + Ord + Serialize + DeserializeOwned;

    /// Returns the object's epoch number.
    fn epoch(&self) -> Self::Epoch;
}

impl<M: Epoched, N> Epoched for TargetedMessage<M, N> {
    type Epoch = <M as Epoched>::Epoch;

    fn epoch(&self) -> Self::Epoch {
        self.message.epoch()
    }
}

impl<'i, D> Step<D>
where
    D: DistAlgorithm,
    <D as DistAlgorithm>::NodeId: NodeIdT + Rand,
    <D as DistAlgorithm>::Message:
        'i + Clone + SenderQueueableMessage + Serialize + DeserializeOwned,
{
    /// Removes and returns any messages that are not yet accepted by remote nodes according to the
    /// mapping `remote_epochs`. This way the returned messages are postponed until later, and the
    /// remaining messages can be sent to remote nodes without delay.
    pub fn defer_messages(
        &mut self,
        peer_epochs: &'i BTreeMap<D::NodeId, <D::Message as Epoched>::Epoch>,
        max_future_epochs: u64,
    ) -> Vec<(D::NodeId, D::Message)>
    where
        <D as DistAlgorithm>::NodeId: 'i,
    {
        let messages = &mut self.messages;
        let pass =
            |TargetedMessage { target, message }: &TargetedMessage<D::Message, D::NodeId>| {
                match target {
                    Target::All => peer_epochs
                        .values()
                        .all(|&them| message.is_accepted(them, max_future_epochs)),
                    Target::Node(id) => peer_epochs
                        .get(&id)
                        .map_or(false, |&them| message.is_accepted(them, max_future_epochs)),
                }
            };
        // `Target::All` messages contained in the result of the partitioning are analyzed further
        // and each split into two sets of point messages: those which can be sent without delay and
        // those which should be postponed.
        let mut deferred_msgs: Vec<(D::NodeId, D::Message)> = Vec::new();
        let mut passed_msgs: Vec<_> = Vec::new();
        for msg in messages.drain(..) {
            if pass(&msg) {
                passed_msgs.push(msg);
            } else {
                let m = msg.message;
                match msg.target {
                    Target::Node(ref id) => {
                        let defer = {
                            let lagging = |&them| {
                                !(m.is_accepted(them, max_future_epochs) || m.is_obsolete(them))
                            };
                            peer_epochs.get(&id).map_or(true, lagging)
                        };
                        if defer {
                            deferred_msgs.push((id.clone(), m));
                        }
                    }
                    Target::All => {
                        for (id, &them) in peer_epochs {
                            if m.is_accepted(them, max_future_epochs) {
                                passed_msgs.push(Target::Node(id.clone()).message(m.clone()));
                            } else if !m.is_obsolete(them) {
                                deferred_msgs.push((id.clone(), m.clone()));
                            }
                        }
                    }
                }
            }
        }
        messages.extend(passed_msgs);
        deferred_msgs
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
