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

use {DaStep, DistAlgorithm, Epoched, NodeIdT, Target};

pub use self::message::Message;

pub trait SenderQueueableMessage: Epoched {
    /// Whether the message needs to be deferred.
    fn is_premature(&self, them: <Self as Epoched>::Epoch, max_future_epochs: u64) -> bool;

    /// Whether the epoch of the message is behind `them`.
    fn is_obsolete(&self, them: <Self as Epoched>::Epoch) -> bool;

    /// Whether the message is neither obsolete nor premature.
    fn is_accepted(&self, them: <Self as Epoched>::Epoch, max_future_epochs: u64) -> bool {
        !self.is_premature(them, max_future_epochs) && !self.is_obsolete(them)
    }
}

pub trait SenderQueueableOutput<N, M>
where
    N: NodeIdT,
    M: Epoched,
{
    /// Returns an optional new node added with the batch. This node should be added to the set of
    /// all nodes.
    fn added_node(&self) -> Option<N>;
}

pub trait SenderQueueableDistAlgorithm: Epoched
where
    Self: DistAlgorithm,
{
    /// The maximum number of subsequent future epochs that the `DistAlgorithm` is allowed to handle
    /// messages for.
    fn max_future_epochs(&self) -> u64;
}

pub type OutgoingQueue<D> = BTreeMap<
    <D as DistAlgorithm>::NodeId,
    BTreeMap<<<D as DistAlgorithm>::Message as Epoched>::Epoch, Vec<<D as DistAlgorithm>::Message>>,
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
    D::Message: Epoched,
{
    /// The managed `DistAlgorithm` instance.
    algo: D,
    /// Our node ID.
    our_id: D::NodeId,
    /// Messages that couldn't be handled yet by remote nodes.
    outgoing_queue: OutgoingQueue<D>,
    /// The set of all remote nodes on the network including validator as well as non-validator
    /// (observer) nodes together with their epochs as of the last communication.
    peer_epochs: BTreeMap<D::NodeId, <D::Message as Epoched>::Epoch>,
}

pub type Step<D> = ::DaStep<SenderQueue<D>>;

impl<D> DistAlgorithm for SenderQueue<D>
where
    D: SenderQueueableDistAlgorithm + Debug,
    D::Message: Clone + SenderQueueableMessage + Epoched<Epoch = <D as Epoched>::Epoch>,
    D::NodeId: NodeIdT,
    D::Output: SenderQueueableOutput<D::NodeId, D::Message>,
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
    D: SenderQueueableDistAlgorithm + Debug,
    D::Message: Clone + SenderQueueableMessage + Epoched<Epoch = <D as Epoched>::Epoch>,
    D::NodeId: NodeIdT,
    D::Output: SenderQueueableOutput<D::NodeId, D::Message>,
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
            Message::EpochStarted(epoch) => Ok(self.handle_epoch_started(sender_id, epoch)),
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
        let mut sender_queue_step = self.update_epoch(&step);
        self.defer_messages(&mut step);
        sender_queue_step.extend(step.map(|output| output, Message::from));
        Ok(sender_queue_step)
    }

    /// Handles an epoch start announcement.
    fn handle_epoch_started(
        &mut self,
        sender_id: &D::NodeId,
        epoch: <D::Message as Epoched>::Epoch,
    ) -> DaStep<Self> {
        self.peer_epochs
            .entry(sender_id.clone())
            .and_modify(|e| {
                if *e < epoch {
                    *e = epoch;
                }
            }).or_insert(epoch);
        self.process_new_epoch(sender_id, epoch)
    }

    /// Processes an announcement of a new epoch update received from a remote node.
    fn process_new_epoch(
        &mut self,
        sender_id: &D::NodeId,
        epoch: <D::Message as Epoched>::Epoch,
    ) -> DaStep<Self> {
        let queue = match self.outgoing_queue.get_mut(sender_id) {
            None => return DaStep::<Self>::default(),
            Some(queue) => queue,
        };
        let earlier_keys: Vec<_> = queue
            .keys()
            .cloned()
            .take_while(|this_epoch| *this_epoch <= epoch)
            .collect();
        earlier_keys
            .into_iter()
            .filter_map(|key| queue.remove(&key))
            .flatten()
            .filter(|msg| !msg.is_obsolete(epoch))
            .map(|msg| Target::Node(sender_id.clone()).message(Message::Algo(msg)))
            .into()
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
    fn update_epoch(&mut self, step: &DaStep<D>) -> DaStep<Self> {
        if step.output.is_empty() {
            return Step::<D>::default();
        }
        // Look up `DynamicHoneyBadger` epoch updates and collect any added peers.
        for node in step.output.iter().filter_map(|batch| batch.added_node()) {
            if &node != self.our_id() {
                self.peer_epochs.entry(node).or_default();
            }
        }
        // Announce the new epoch.
        Target::All
            .message(Message::EpochStarted(self.algo.epoch()))
            .into()
    }

    /// Removes any messages to nodes at earlier epochs from the given `Step`. This may involve
    /// decomposing a `Target::All` message into `Target::Node` messages and sending some of the
    /// resulting messages while placing onto the queue those remaining messages whose recipient is
    /// currently at an earlier epoch.
    fn defer_messages(&mut self, step: &mut DaStep<D>) {
        let max_future_epochs = self.algo.max_future_epochs();
        // Append the deferred messages onto the queues.
        for (id, message) in step.defer_messages(&self.peer_epochs, max_future_epochs) {
            self.outgoing_queue
                .entry(id)
                .or_default()
                .entry(message.epoch())
                .or_default()
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
    outgoing_queue: OutgoingQueue<D>,
    peer_epochs: BTreeMap<D::NodeId, <D::Message as Epoched>::Epoch>,
}

impl<D> SenderQueueBuilder<D>
where
    D: SenderQueueableDistAlgorithm + Debug,
    D::Message: Clone + SenderQueueableMessage + Epoched<Epoch = <D as Epoched>::Epoch>,
    D::NodeId: NodeIdT,
    D::Output: SenderQueueableOutput<D::NodeId, D::Message>,
{
    pub fn new<I>(algo: D, peer_ids: I) -> Self
    where
        I: Iterator<Item = D::NodeId>,
    {
        SenderQueueBuilder {
            algo,
            outgoing_queue: BTreeMap::default(),
            peer_epochs: peer_ids
                .map(|id| (id, <D::Message as Epoched>::Epoch::default()))
                .collect(),
        }
    }

    pub fn outgoing_queue(mut self, outgoing_queue: OutgoingQueue<D>) -> Self {
        self.outgoing_queue = outgoing_queue;
        self
    }

    pub fn peer_epochs(
        mut self,
        peer_epochs: BTreeMap<D::NodeId, <D::Message as Epoched>::Epoch>,
    ) -> Self {
        self.peer_epochs = peer_epochs;
        self
    }

    pub fn build(self, our_id: D::NodeId) -> (SenderQueue<D>, DaStep<SenderQueue<D>>) {
        let epoch = self.algo.epoch();
        let sq = SenderQueue {
            algo: self.algo,
            our_id,
            outgoing_queue: self.outgoing_queue,
            peer_epochs: self.peer_epochs,
        };
        let step = Target::All.message(Message::EpochStarted(epoch)).into();
        (sq, step)
    }
}
