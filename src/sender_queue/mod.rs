//! # Sender queue
//!
//! A sender queue allows a `DistAlgorithm` that outputs `Epoched` messages to buffer those outgoing
//! messages based on their epochs. A message is sent to its recipient only when the recipient's
//! epoch matches the epoch of the message. Thus no queueing is required for incoming messages since
//! any incoming messages with non-matching epochs can be safely discarded.

mod dynamic_honey_badger;
mod honey_badger;
mod message;
mod queueing_honey_badger;

use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use log::debug;

use crate::traits::EpochT;
use crate::{DaStep, DistAlgorithm, Epoched, NodeIdT, Target};

pub use self::message::Message;

/// A message type that is suitable for use with a sender queue.
pub trait SenderQueueableMessage {
    /// The epoch type of the wrapped algorithm.
    type Epoch: EpochT;

    /// Whether the message needs to be deferred.
    fn is_premature(&self, them: Self::Epoch, max_future_epochs: u64) -> bool;

    /// Whether the epoch of the message is behind `them`.
    fn is_obsolete(&self, them: Self::Epoch) -> bool;

    /// Whether the message is neither obsolete nor premature.
    fn is_accepted(&self, them: Self::Epoch, max_future_epochs: u64) -> bool {
        !self.is_premature(them, max_future_epochs) && !self.is_obsolete(them)
    }

    /// Returns the earliest epoch in which this message can be handled.
    fn first_epoch(&self) -> Self::Epoch;
}

/// An output type compatible with the sender queue.
pub trait SenderQueueableOutput<N, E>
where
    N: NodeIdT,
{
    /// Returns the set of participants in the next epoch. New participants should be added to the
    /// set of peers for tracking their epochs. Old participants - ones that appear only among
    /// current participants - should be scheduled for removal from the set of peers in an orderly
    /// manner making sure that all messages those participants are entitled to are delivered to
    /// them.
    ///
    /// The common case of no change in the set of participants is denoted by `None`.
    fn participant_change(&self) -> Option<BTreeSet<N>>;

    /// The epoch in which the output was produced.
    fn output_epoch(&self) -> E;
}

/// A `DistAlgorithm` that can be wrapped by a sender queue.
pub trait SenderQueueableDistAlgorithm: Epoched + DistAlgorithm {
    /// The maximum number of subsequent future epochs that the `DistAlgorithm` is allowed to handle
    /// messages for.
    fn max_future_epochs(&self) -> u64;
}

/// A map with outgoing messages, per epoch and per target node.
pub type OutgoingQueue<D> = BTreeMap<
    <D as DistAlgorithm>::NodeId,
    BTreeMap<<D as Epoched>::Epoch, Vec<<D as DistAlgorithm>::Message>>,
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
{
    /// The managed `DistAlgorithm` instance.
    algo: D,
    /// Our node ID.
    our_id: D::NodeId,
    /// Messages that couldn't be handled yet by remote nodes.
    outgoing_queue: OutgoingQueue<D>,
    /// The set of all remote nodes on the network including validator as well as non-validator
    /// (observer) nodes together with their epochs as of the last communication.
    peer_epochs: BTreeMap<D::NodeId, D::Epoch>,
    /// The set of previously participating nodes now removed from the network. Each node is marked
    /// with an epoch after which it left. The node is a member of this set from the epoch when it
    /// was voted to be removed and until all messages have been delivered to it for all epochs in
    /// which it was still a participant.
    last_epochs: BTreeMap<D::NodeId, D::Epoch>,
    /// Participants of the managed algorithm after the latest change of the participant set. If the
    /// set of participants never changes, this set remains empty and unused. If the algorithm
    /// initiates a ballot to change the validators, the sender queue has to remember the new set of
    /// participants (validators both current and proposed) in order to roll the ballot back if it
    /// fails to progress.
    participants_after_change: BTreeSet<D::NodeId>,
}

/// A `SenderQueue` step. The output corresponds to the wrapped algorithm.
pub type Step<D> = crate::DaStep<SenderQueue<D>>;

impl<D> DistAlgorithm for SenderQueue<D>
where
    D: SenderQueueableDistAlgorithm + Debug,
    D::Message: Clone + SenderQueueableMessage<Epoch = D::Epoch>,
    D::NodeId: NodeIdT,
    D::Output: SenderQueueableOutput<D::NodeId, D::Epoch>,
{
    type NodeId = D::NodeId;
    type Input = D::Input;
    type Output = D::Output;
    type Message = Message<D::Message>;
    type Error = D::Error;
    type FaultKind = D::FaultKind;

    fn handle_input<R: Rng>(
        &mut self,
        input: Self::Input,
        rng: &mut R,
    ) -> Result<DaStep<Self>, D::Error> {
        self.handle_input(input, rng)
    }

    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &D::NodeId,
        message: Self::Message,
        rng: &mut R,
    ) -> Result<DaStep<Self>, D::Error> {
        self.handle_message(sender_id, message, rng)
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
    D::Message: Clone + SenderQueueableMessage<Epoch = D::Epoch>,
    D::NodeId: NodeIdT,
    D::Output: SenderQueueableOutput<D::NodeId, D::Epoch>,
{
    /// Returns a new `SenderQueueBuilder` configured to manage a given `DynamicHoneyBadger`
    /// instance.
    pub fn builder<I>(algo: D, peer_ids: I) -> SenderQueueBuilder<D>
    where
        I: Iterator<Item = D::NodeId>,
    {
        SenderQueueBuilder::new(algo, peer_ids)
    }

    /// Handles an input. This will call the wrapped algorithm's `handle_input`.
    pub fn handle_input<R: Rng>(
        &mut self,
        input: D::Input,
        rng: &mut R,
    ) -> Result<DaStep<Self>, D::Error> {
        self.apply(|algo| algo.handle_input(input, rng))
    }

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message<R: Rng>(
        &mut self,
        sender_id: &D::NodeId,
        message: Message<D::Message>,
        rng: &mut R,
    ) -> Result<DaStep<Self>, D::Error> {
        match message {
            Message::EpochStarted(epoch) => Ok(self.handle_epoch_started(sender_id, epoch)),
            Message::Algo(msg) => self.handle_message_content(sender_id, msg, rng),
        }
    }

    /// Returns an immutable reference to the wrapped algorithm.
    pub fn inner(&self) -> &D {
        &self.algo
    }

    /// Applies `f` to the wrapped algorithm and converts the step in the result to a sender queue
    /// step, deferring or dropping messages, where necessary.
    fn apply<F>(&mut self, f: F) -> Result<DaStep<Self>, D::Error>
    where
        F: FnOnce(&mut D) -> Result<DaStep<D>, D::Error>,
    {
        let mut step = f(&mut self.algo)?;
        let mut sender_queue_step = self.update_epoch(&step);
        self.defer_messages(&mut step);
        sender_queue_step.extend(step.map(|output| output, |fault| fault, Message::from));
        Ok(sender_queue_step)
    }

    /// Handles an epoch start announcement.
    fn handle_epoch_started(&mut self, sender_id: &D::NodeId, epoch: D::Epoch) -> DaStep<Self> {
        self.peer_epochs
            .entry(sender_id.clone())
            .and_modify(|e| {
                if *e < epoch {
                    *e = epoch;
                }
            })
            .or_insert(epoch);
        if !self.remove_participant_if_old(sender_id) {
            self.process_new_epoch(sender_id, epoch)
        } else {
            Step::<D>::default()
        }
    }

    /// Processes an announcement of a new epoch update received from a remote node.
    fn process_new_epoch(&mut self, sender_id: &D::NodeId, epoch: D::Epoch) -> DaStep<Self> {
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
    fn handle_message_content<R: Rng>(
        &mut self,
        sender_id: &D::NodeId,
        content: D::Message,
        rng: &mut R,
    ) -> Result<DaStep<Self>, D::Error> {
        self.apply(|algo| algo.handle_message(sender_id, content, rng))
    }

    /// Updates the current Honey Badger epoch.
    fn update_epoch(&mut self, step: &DaStep<D>) -> DaStep<Self> {
        if step.output.is_empty() {
            return Step::<D>::default();
        }
        // Look up `DynamicHoneyBadger` epoch updates and collect any added peers.
        for batch in &step.output {
            if let Some(next_participants) = batch.participant_change() {
                // Insert candidates.
                for id in &next_participants {
                    if id != self.our_id() {
                        self.peer_epochs.entry(id.clone()).or_default();
                    }
                }
                debug!(
                    "Participants after the last change: {:?}",
                    self.participants_after_change
                );
                debug!("Next participants: {:?}", next_participants);
                // Remove obsolete participants.
                for id in self
                    .participants_after_change
                    .clone()
                    .difference(&next_participants)
                {
                    // Begin the peer removal process.
                    self.remove_participant_after(&id, &batch.output_epoch());
                }
                self.participants_after_change = next_participants;
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
                .entry(message.first_epoch())
                .or_default()
                .push(message);
        }
    }

    /// Removes a given old participant if it has been scheduled for removal as a result of being
    /// superseded by a new set of participants of which it is not a member. Returns `true` if the
    /// participant has been removed and `false` otherwise.
    fn remove_participant_if_old(&mut self, id: &D::NodeId) -> bool {
        self.last_epochs
            .get(id)
            .cloned()
            .map_or(false, |last_epoch| self.remove_participant(id, &last_epoch))
    }

    /// Removes a given old participant after a specified epoch if that participant has become
    /// superseded by a new set of participants of which it is not a member. Returns `true` if the
    /// participant has been removed and `false` otherwise.
    fn remove_participant_after(&mut self, id: &D::NodeId, last_epoch: &D::Epoch) -> bool {
        self.last_epochs.insert(id.clone(), last_epoch.clone());
        self.remove_participant(id, last_epoch)
    }

    /// Removes a participant after a specified last epoch. The participant is removed if
    ///
    /// 1. its epoch is newer than its last epoch, or
    ///
    /// 2. the epoch of the managed algorithm instance is newer than the last epoch and the sender
    /// queue has sent all messages for all epochs up to the last epoch to the participant.
    ///
    /// Returns `true` if the participant has been removed and `false` otherwise.
    fn remove_participant(&mut self, id: &D::NodeId, last_epoch: &D::Epoch) -> bool {
        if *last_epoch >= self.algo.epoch() {
            return false;
        }
        if let Some(peer_epoch) = self.peer_epochs.get(id) {
            if last_epoch >= peer_epoch {
                return false;
            }
            if let Some(q) = self.outgoing_queue.get(id) {
                if q.keys().any(|epoch| epoch <= last_epoch) {
                    return false;
                }
            }
        }
        self.peer_epochs.remove(&id);
        self.last_epochs.remove(&id);
        self.outgoing_queue.remove(&id);
        true
    }

    /// Returns a reference to the managed algorithm.
    pub fn algo(&self) -> &D {
        &self.algo
    }

    /// Returns a mutable reference to the managed algorithm.
    pub fn algo_mut(&mut self) -> &mut D {
        &mut self.algo
    }
}

/// A builder of a Honey Badger with a sender queue. It configures the parameters and creates a new
/// instance of `SenderQueue`.
pub struct SenderQueueBuilder<D>
where
    D: SenderQueueableDistAlgorithm,
{
    algo: D,
    peer_epochs: BTreeMap<D::NodeId, D::Epoch>,
}

impl<D> SenderQueueBuilder<D>
where
    D: SenderQueueableDistAlgorithm + Debug,
    D::Message: Clone + SenderQueueableMessage<Epoch = D::Epoch>,
    D::NodeId: NodeIdT,
    D::Output: SenderQueueableOutput<D::NodeId, D::Epoch>,
{
    /// Creates a new builder, with an empty outgoing queue and the specified known peers.
    pub fn new<I>(algo: D, peer_ids: I) -> Self
    where
        I: Iterator<Item = D::NodeId>,
    {
        SenderQueueBuilder {
            algo,
            peer_epochs: peer_ids.map(|id| (id, D::Epoch::default())).collect(),
        }
    }

    /// Sets the peer epochs.
    pub fn peer_epochs(mut self, peer_epochs: BTreeMap<D::NodeId, D::Epoch>) -> Self {
        self.peer_epochs = peer_epochs;
        self
    }

    /// Creates a new sender queue and returns the `Step` with the initial message.
    pub fn build(self, our_id: D::NodeId) -> (SenderQueue<D>, DaStep<SenderQueue<D>>) {
        let epoch = self.algo.epoch();
        let sq = SenderQueue {
            algo: self.algo,
            our_id,
            outgoing_queue: BTreeMap::new(),
            peer_epochs: self.peer_epochs,
            last_epochs: BTreeMap::new(),
            participants_after_change: BTreeSet::new(),
        };
        let step = Target::All.message(Message::EpochStarted(epoch)).into();
        (sq, step)
    }
}
