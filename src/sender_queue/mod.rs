//! # Sender queue
//!
//! A sender queue allows a `DistAlgorithm` that outputs `Epoched` messages to buffer those outgoing
//! messages based on their epochs. A message is sent to its recipient only when the recipient's
//! epoch matches the epoch of the message. Thus no queueing is required for incoming messages since
//! any incoming messages with non-matching epochs can be safely discarded.

mod message;

pub mod dynamic_honey_badger;
pub mod honey_badger;
pub mod queueing_honey_badger;

use std::collections::BTreeMap;
use std::fmt::Debug;

use rand::Rand;
use serde::{de::DeserializeOwned, Serialize};

use {DaStep, DistAlgorithm, Epoched, NodeIdT, Target};

pub use self::message::Message;

pub trait SenderQueueableMessage: Epoched {
    /// Whether the message is accepted in epoch `them`.
    fn is_accepted(&self, them: <Self as Epoched>::LinEpoch, max_future_epochs: u64) -> bool;

    /// Whether the epoch of the message is behind `them`.
    fn is_obsolete(&self, them: <Self as Epoched>::LinEpoch) -> bool;
}

pub trait SenderQueueableOutput<N, M>
where
    N: NodeIdT,
    M: Epoched,
{
    /// Returns an optional new node added with the batch. This node should be added to the set of
    /// all nodes.
    fn added_node(&self) -> Option<N>;

    /// Computes the next epoch after the `DynamicHoneyBadger` epoch of the batch.
    fn next_epoch(&self) -> <M as Epoched>::LinEpoch;
}

pub trait SenderQueueableEpoch
where
    Self: Sized,
{
    /// A _spanning epoch_ of an epoch `e` is an epoch `e0` such that
    ///
    /// - `e` and `e0` are incomparable by the partial ordering on epochs and
    ///
    /// - the duration of `e0` is at least that of `e`.
    ///
    /// Returned is a list of spanning epochs for the given epoch.
    ///
    /// For example, any `DynamicHoneyBadger` epoch `Epoch((x, Some(y)))` has a unique spanning
    /// epoch `Epoch((x, None))`. In turn, no epoch `Epoch((x, None))` has a spanning epoch.
    fn spanning_epochs(&self) -> Vec<Self>;
}

pub trait SenderQueueableDistAlgorithm
where
    Self: DistAlgorithm,
{
    /// The maximum number of subsequent future epochs that the `DistAlgorithm` is allowed to handle
    /// messages for.
    fn max_future_epochs(&self) -> u64;
}

pub type OutgoingQueue<D> = BTreeMap<
    (
        <D as DistAlgorithm>::NodeId,
        <<D as DistAlgorithm>::Message as Epoched>::Epoch,
    ),
    Vec<<D as DistAlgorithm>::Message>,
>;

/// An instance of `DistAlgorithm` wrapped with a queue of outgoing messages, that is, a sender
/// queue. This wrapping ensures that the messages sent to remote instances lead to progress of the
/// entire consensus network. In particular, messages to lagging remote nodes are queued and sent
/// only when those nodes' epochs match the queued messages' epochs. Thus all nodes can handle
/// incoming messages without queueing them and can ignore messages whose epochs are not currently
/// acccepted.
#[derive(Debug)]
pub struct SenderQueue<D>
where
    D: SenderQueueableDistAlgorithm,
    D::Message: Clone + SenderQueueableMessage + Serialize + DeserializeOwned,
    D::NodeId: NodeIdT + Rand,
    D::Output: SenderQueueableOutput<D::NodeId, D::Message>,
{
    /// The managed `DistAlgorithm` instance.
    algo: D,
    /// Our node ID.
    our_id: D::NodeId,
    /// Current linearizable epoch of the managed `DistAlgorithm`.
    lin_epoch: <D::Message as Epoched>::LinEpoch,
    /// Messages that couldn't be handled yet by remote nodes.
    outgoing_queue: OutgoingQueue<D>,
    /// The set of all remote nodes on the network including validator as well as non-validator
    /// (observer) nodes together with their epochs as of the last communication.
    peer_epochs: BTreeMap<D::NodeId, <D::Message as Epoched>::LinEpoch>,
}

pub type Step<D> = ::DaStep<SenderQueue<D>>;

impl<D> DistAlgorithm for SenderQueue<D>
where
    D: SenderQueueableDistAlgorithm + Debug + Send + Sync,
    D::Message: Clone + SenderQueueableMessage + Serialize + DeserializeOwned,
    D::NodeId: NodeIdT + Rand,
    D::Output: SenderQueueableOutput<D::NodeId, D::Message>,
    <D::Message as Epoched>::Epoch: SenderQueueableEpoch + From<<D::Message as Epoched>::LinEpoch>,
{
    type NodeId = D::NodeId;
    type Input = D::Input;
    type Output = D::Output;
    type Message = Message<D::Message>;
    type Error = D::Error;

    fn handle_input(&mut self, input: Self::Input) -> Result<DaStep<Self>, D::Error> {
        self.handle_input(input)
    }

    fn handle_message(
        &mut self,
        sender_id: &D::NodeId,
        message: Self::Message,
    ) -> Result<DaStep<Self>, D::Error> {
        self.handle_message(sender_id, message)
    }

    fn terminated(&self) -> bool {
        false
    }

    fn our_id(&self) -> &D::NodeId {
        &self.our_id
    }
}

impl<D> SenderQueue<D>
where
    D: SenderQueueableDistAlgorithm + Debug + Send + Sync,
    D::Message: Clone + SenderQueueableMessage + Serialize + DeserializeOwned,
    D::NodeId: NodeIdT + Rand,
    D::Output: SenderQueueableOutput<D::NodeId, D::Message>,
    <D::Message as Epoched>::Epoch: SenderQueueableEpoch + From<<D::Message as Epoched>::LinEpoch>,
{
    /// Returns a new `SenderQueueBuilder` configured to manage a given `DynamicHoneyBadger`
    /// instance.
    pub fn builder<I>(algo: D, peer_ids: I) -> SenderQueueBuilder<D>
    where
        I: Iterator<Item = D::NodeId>,
    {
        SenderQueueBuilder::new(algo, peer_ids)
    }

    pub fn handle_input(&mut self, input: D::Input) -> Result<DaStep<Self>, D::Error> {
        self.apply(|algo| algo.handle_input(input))
    }

    pub fn handle_message(
        &mut self,
        sender_id: &D::NodeId,
        message: Message<D::Message>,
    ) -> Result<DaStep<Self>, D::Error> {
        match message {
            Message::EpochStarted(lin_epoch) => Ok(self.handle_epoch_started(sender_id, lin_epoch)),
            Message::Algo(msg) => self.handle_message_content(sender_id, msg),
        }
    }

    /// Applies `f` to the wrapped algorithm and converts the step in the result to a sender queue
    /// step, deferring or dropping messages, where necessary.
    pub fn apply<F>(&mut self, f: F) -> Result<DaStep<Self>, D::Error>
    where
        F: FnOnce(&mut D) -> Result<DaStep<D>, D::Error>,
    {
        let mut step = f(&mut self.algo)?;
        let mut sender_queue_step = self.update_lin_epoch(&step);
        self.defer_messages(&mut step);
        sender_queue_step.extend(step.map(|output| output, Message::from));
        Ok(sender_queue_step)
    }

    /// Handles an epoch start announcement.
    fn handle_epoch_started(
        &mut self,
        sender_id: &D::NodeId,
        lin_epoch: <D::Message as Epoched>::LinEpoch,
    ) -> DaStep<Self> {
        self.peer_epochs
            .entry(sender_id.clone())
            .and_modify(|e| {
                if *e < lin_epoch {
                    *e = lin_epoch;
                }
            }).or_insert(lin_epoch);
        self.remove_earlier_messages(sender_id, <D::Message as Epoched>::Epoch::from(lin_epoch));
        self.process_new_epoch(sender_id, <D::Message as Epoched>::Epoch::from(lin_epoch))
    }

    /// Removes all messages queued for the remote node from epochs upto `epoch`.
    fn remove_earlier_messages(
        &mut self,
        sender_id: &D::NodeId,
        epoch: <D::Message as Epoched>::Epoch,
    ) {
        let earlier_keys: Vec<_> = self
            .outgoing_queue
            .keys()
            .cloned()
            .filter(|(id, this_epoch)| id == sender_id && *this_epoch < epoch)
            .collect();
        for key in earlier_keys {
            self.outgoing_queue.remove(&key);
        }
    }

    /// Processes an announcement of a new epoch update received from a remote node.
    fn process_new_epoch(
        &mut self,
        sender_id: &D::NodeId,
        epoch: <D::Message as Epoched>::Epoch,
    ) -> DaStep<Self> {
        // Send any HB messages for the HB epoch.
        let mut ready_messages = self
            .outgoing_queue
            .remove(&(sender_id.clone(), epoch))
            .unwrap_or_default();
        for u in epoch.spanning_epochs() {
            // Send any DHB messages for the DHB era.
            ready_messages.extend(
                self.outgoing_queue
                    .remove(&(sender_id.clone(), u))
                    .unwrap_or_default(),
            );
        }
        Step::<D>::from(
            ready_messages
                .into_iter()
                .map(|msg| Target::Node(sender_id.clone()).message(Message::Algo(msg))),
        )
    }

    /// Handles a Honey Badger algorithm message in a given epoch.
    fn handle_message_content(
        &mut self,
        sender_id: &D::NodeId,
        content: D::Message,
    ) -> Result<DaStep<Self>, D::Error> {
        self.apply(|algo| algo.handle_message(sender_id, content))
    }

    /// Updates the current Honey Badger epoch.
    fn update_lin_epoch(&mut self, step: &DaStep<D>) -> DaStep<Self> {
        // Look up `DynamicHoneyBadger` epoch updates and collect any added peers.
        let new_epoch = step.output.iter().fold(self.lin_epoch, |lin_epoch, batch| {
            let max_epoch = lin_epoch.max(batch.next_epoch());
            if let Some(node) = batch.added_node() {
                if &node != self.our_id() {
                    self.peer_epochs
                        .entry(node)
                        .or_insert_with(<D::Message as Epoched>::LinEpoch::default);
                }
            }
            max_epoch
        });
        if new_epoch != self.lin_epoch {
            self.lin_epoch = new_epoch;
            // Announce the new epoch.
            Target::All
                .message(Message::EpochStarted(self.lin_epoch))
                .into()
        } else {
            Step::<D>::default()
        }
    }

    /// Removes any messages to nodes at earlier epochs from the given `Step`. This may involve
    /// decomposing a `Target::All` message into `Target::Node` messages and sending some of the
    /// resulting messages while placing onto the queue those remaining messages whose recipient is
    /// currently at an earlier epoch.
    fn defer_messages(&mut self, step: &mut DaStep<D>) {
        let max_future_epochs = self.algo.max_future_epochs();
        // Append the deferred messages onto the queues.
        for (id, message) in step.defer_messages(&self.peer_epochs, max_future_epochs) {
            let epoch = message.epoch();
            self.outgoing_queue
                .entry((id, epoch))
                .or_insert_with(Vec::new)
                .push(message);
        }
    }

    /// Returns a reference to the managed algorithm.
    pub fn algo(&self) -> &D {
        &self.algo
    }
}

/// A builder of a Honey Badger with a sender queue. It configures the parameters and creates a new
/// instance of `SenderQueue`.
pub struct SenderQueueBuilder<D>
where
    D: SenderQueueableDistAlgorithm,
    D::Message: Epoched,
{
    algo: D,
    lin_epoch: <D::Message as Epoched>::LinEpoch,
    outgoing_queue: OutgoingQueue<D>,
    peer_epochs: BTreeMap<D::NodeId, <D::Message as Epoched>::LinEpoch>,
}

impl<D> SenderQueueBuilder<D>
where
    D: SenderQueueableDistAlgorithm + Debug + Send + Sync,
    D::Message: Clone + SenderQueueableMessage + Serialize + DeserializeOwned,
    D::NodeId: NodeIdT + Rand,
    D::Output: SenderQueueableOutput<D::NodeId, D::Message>,
    <D::Message as Epoched>::Epoch: SenderQueueableEpoch + From<<D::Message as Epoched>::LinEpoch>,
{
    pub fn new<I>(algo: D, peer_ids: I) -> Self
    where
        I: Iterator<Item = D::NodeId>,
    {
        SenderQueueBuilder {
            algo,
            lin_epoch: <D::Message as Epoched>::LinEpoch::default(),
            outgoing_queue: BTreeMap::default(),
            peer_epochs: peer_ids
                .map(|id| (id, <D::Message as Epoched>::LinEpoch::default()))
                .collect(),
        }
    }

    pub fn lin_epoch(mut self, lin_epoch: <D::Message as Epoched>::LinEpoch) -> Self {
        self.lin_epoch = lin_epoch;
        self
    }

    pub fn outgoing_queue(mut self, outgoing_queue: OutgoingQueue<D>) -> Self {
        self.outgoing_queue = outgoing_queue;
        self
    }

    pub fn peer_epochs(
        mut self,
        peer_epochs: BTreeMap<D::NodeId, <D::Message as Epoched>::LinEpoch>,
    ) -> Self {
        self.peer_epochs = peer_epochs;
        self
    }

    pub fn build(self, our_id: D::NodeId) -> (SenderQueue<D>, DaStep<SenderQueue<D>>) {
        let lin_epoch = <D::Message as Epoched>::LinEpoch::default();
        let sq = SenderQueue {
            algo: self.algo,
            our_id,
            lin_epoch: self.lin_epoch,
            outgoing_queue: self.outgoing_queue,
            peer_epochs: self.peer_epochs,
        };
        let step = Target::All.message(Message::EpochStarted(lin_epoch)).into();
        (sq, step)
    }
}
