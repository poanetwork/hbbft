use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;

use bincode;
use rand::Rand;
use serde::{Deserialize, Serialize};

use super::epoch_state::EpochState;
use super::{Batch, Error, ErrorKind, HoneyBadgerBuilder, Message, MessageContent, Result};
use fault_log::{Fault, FaultKind};
use messaging::{self, DistAlgorithm, Epoched, NetworkInfo, Target, TargetedMessage};
use traits::{Contribution, NodeIdT};

/// An instance of the Honey Badger Byzantine fault tolerant consensus algorithm.
#[derive(Debug)]
pub struct HoneyBadger<C, N: Rand> {
    /// Shared network data.
    pub(super) netinfo: Arc<NetworkInfo<N>>,
    /// The earliest epoch from which we have not yet received output.
    pub(super) epoch: u64,
    /// Whether we have already submitted a proposal for the current epoch.
    pub(super) has_input: bool,
    /// The subalgorithms for ongoing epochs.
    pub(super) epochs: BTreeMap<u64, EpochState<C, N>>,
    /// The maximum number of `Subset` instances that we run simultaneously.
    pub(super) max_future_epochs: u64,
    /// Messages that couldn't be handled yet by remote nodes.
    pub(super) outgoing_queue: BTreeMap<(N, u64), Vec<Message<N>>>,
    /// Known current epochs of remote nodes.
    pub(super) remote_epochs: BTreeMap<N, u64>,
    /// If used as part of `DynamicHoneyBadger`, this is the node which is being added using a
    /// `Change::Add` command. The command should be is ongoing. The node receives any broadcast
    /// message but is not a validator.
    pub(super) node_being_added: Option<N>,
}

pub type Step<C, N> = messaging::Step<HoneyBadger<C, N>>;

impl<C, N> DistAlgorithm for HoneyBadger<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeIdT + Rand,
{
    type NodeId = N;
    type Input = C;
    type Output = Batch<C, N>;
    type Message = Message<N>;
    type Error = Error;

    fn handle_input(&mut self, input: Self::Input) -> Result<Step<C, N>> {
        let mut step = self.propose(&input)?;
        self.defer_messages(&mut step);
        debug!(
            "{:?}@{} handle_input outgoing messages {:?} --- queued messages: {:?} --- remote epochs: {:?}",
            self.netinfo.our_id(),
            self.epoch,
            step.messages,
            self.outgoing_queue,
            self.remote_epochs
        );
        Ok(step)
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> Result<Step<C, N>> {
        let mut step = self.handle_message(sender_id, message)?;
        self.defer_messages(&mut step);
        debug!(
            "{:?}@{} handle_message outgoing messages {:?} --- queued messages: {:?} --- remote epochs: {:?}",
            self.netinfo.our_id(),
            self.epoch,
            step.messages,
            self.outgoing_queue,
            self.remote_epochs
        );
        Ok(step)
    }

    fn terminated(&self) -> bool {
        false
    }

    fn our_id(&self) -> &N {
        self.netinfo.our_id()
    }
}

impl<C, N> HoneyBadger<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeIdT + Rand,
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn builder(netinfo: Arc<NetworkInfo<N>>) -> HoneyBadgerBuilder<C, N> {
        HoneyBadgerBuilder::new(netinfo)
    }

    /// Proposes a new item in the current epoch.
    pub fn propose(&mut self, proposal: &C) -> Result<Step<C, N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        self.has_input = true;
        let ser_prop =
            bincode::serialize(&proposal).map_err(|err| ErrorKind::ProposeBincode(*err))?;
        let ciphertext = self.netinfo.public_key_set().public_key().encrypt(ser_prop);
        let epoch = self.epoch;
        let mut step = self.epoch_state_mut(epoch)?.propose(&ciphertext)?;
        step.extend(self.try_output_batches()?);
        Ok(step)
    }

    /// Handles a message received from `sender_id`.
    fn handle_message(&mut self, sender_id: &N, message: Message<N>) -> Result<Step<C, N>> {
        match message {
            Message::HoneyBadger { epoch, content } => {
                if !self.netinfo.is_node_validator(sender_id) {
                    return Err(ErrorKind::SenderNotValidator.into());
                }
                self.handle_message_content(sender_id, epoch, content)
            }
            Message::EpochStarted(epoch) => Ok(self.handle_epoch_started(sender_id, epoch)),
        }
    }

    /// Handles a Honey Badger algorithm message in a given epoch.
    fn handle_message_content(
        &mut self,
        sender_id: &N,
        epoch: u64,
        content: MessageContent<N>,
    ) -> Result<Step<C, N>> {
        if epoch < self.epoch || epoch > self.epoch + self.max_future_epochs {
            // Reject messages from past epochs or from future epochs that are not in the range yet.
            warn!(
                "{:?}@{} discarded {:?}@{}:{:?}",
                self.netinfo.our_id(),
                self.epoch,
                sender_id,
                epoch,
                content,
            );
            return Ok(Fault::new(sender_id.clone(), FaultKind::EpochOutOfRange).into());
        }
        // Accept and handle the message.
        let mut step = self
            .epoch_state_mut(epoch)?
            .handle_message_content(sender_id, content)?;
        step.extend(self.try_output_batches()?);
        Ok(step)
    }

    /// Handles an epoch start announcement.
    fn handle_epoch_started(&mut self, sender_id: &N, epoch: u64) -> Step<C, N> {
        self.remote_epochs
            .entry(sender_id.clone())
            .and_modify(|e| {
                if *e < epoch {
                    *e = epoch;
                }
            }).or_insert(epoch);
        // Remove all messages queued for the remote node from earlier epochs.
        let earlier_keys: Vec<_> = self
            .outgoing_queue
            .keys()
            .cloned()
            .filter(|(id, e)| id == sender_id && *e < epoch)
            .collect();
        for key in earlier_keys {
            self.outgoing_queue.remove(&key);
        }
        // If there are any messages to `sender_id` for `epoch`, send them now.
        if let Some(messages) = self.outgoing_queue.remove(&(sender_id.clone(), epoch)) {
            Step::from(
                messages
                    .into_iter()
                    .map(|msg| Target::Node(sender_id.clone()).message(msg)),
            )
        } else {
            Step::default()
        }
    }

    /// Returns `true` if input for the current epoch has already been provided.
    pub fn has_input(&self) -> bool {
        !self.netinfo.is_validator() || self.has_input
    }

    /// Returns the number of validators from which we have already received a proposal for the
    /// current epoch.
    pub(crate) fn received_proposals(&self) -> usize {
        self.epochs
            .get(&self.epoch)
            .map_or(0, EpochState::received_proposals)
    }

    /// Increments the epoch number and clears any state that is local to the finished epoch.
    fn update_epoch(&mut self) -> Result<Step<C, N>> {
        // Clear the state of the old epoch.
        self.epochs.remove(&self.epoch);
        self.epoch += 1;
        debug!(
            "{:?} updated to epoch {}",
            self.netinfo.our_id(),
            self.epoch
        );
        self.has_input = false;
        // The first message in an epoch announces the epoch transition.
        Ok(Target::All
            .message(Message::EpochStarted(self.epoch))
            .into())
    }

    /// Tries to decrypt contributions from all proposers and output those in a batch.
    fn try_output_batches(&mut self) -> Result<Step<C, N>> {
        let mut step = Step::default();
        while let Some((batch, fault_log)) = self
            .epochs
            .get(&self.epoch)
            .and_then(EpochState::try_output_batch)
        {
            // Queue the output and advance the epoch.
            step.output.push_back(batch);
            step.fault_log.extend(fault_log);
            step.extend(self.update_epoch()?);
        }
        Ok(step)
    }

    /// Returns a mutable reference to the state of the given `epoch`. Initializes a new one, if it
    /// doesn't exist yet.
    fn epoch_state_mut(&mut self, epoch: u64) -> Result<&mut EpochState<C, N>> {
        Ok(match self.epochs.entry(epoch) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(EpochState::new(self.netinfo.clone(), epoch)?),
        })
    }

    /// Provides a reference to the the queue of outgoing messages.
    pub(crate) fn outgoing_queue(&mut self) -> &mut BTreeMap<(N, u64), Vec<Message<N>>> {
        &mut self.outgoing_queue
    }

    /// Removes any messages to nodes at earlier epochs from the given `Step`. This may involve
    /// decomposing a `Target::All` message into `Target::Node` messages and sending some of the
    /// resulting messages while placing onto the queue those remaining messages whose recipient is
    /// currently at an earlier epoch.
    fn defer_messages(&mut self, step: &mut Step<C, N>) {
        let max_future_epochs = self.max_future_epochs;
        let is_accepting_epoch = |us: &Message<N>, them: u64| {
            let our_epoch = us.epoch();
            them <= our_epoch && our_epoch <= them + max_future_epochs
        };
        let is_later_epoch = |us: &Message<N>, them: u64| us.epoch() < them;
        let remote_epochs = &self.remote_epochs;
        let is_passed_unchanged = |msg: &TargetedMessage<_, _>| match &msg.message {
            Message::HoneyBadger { .. } => {
                let pass = |&them| is_accepting_epoch(&msg.message, them);
                match &msg.target {
                    Target::All => remote_epochs.values().all(pass),
                    Target::Node(id) => remote_epochs.get(&id).map_or(false, pass),
                }
            }
            Message::EpochStarted(_) => true,
        };
        let our_id = self.netinfo.our_id();
        let deferred_msgs = step.defer_messages(
            &self.remote_epochs,
            self.netinfo
                .all_ids()
                .chain(self.node_being_added.iter())
                .filter(|&id| id != our_id),
            is_accepting_epoch,
            is_later_epoch,
            is_passed_unchanged,
        );
        // Append the deferred messages onto the queue.
        for (id, message) in deferred_msgs {
            let epoch = message.epoch();
            self.outgoing_queue
                .entry((id, epoch))
                .and_modify(|e| e.push(message.clone()))
                .or_insert_with(|| vec![message.clone()]);
        }
    }
}
