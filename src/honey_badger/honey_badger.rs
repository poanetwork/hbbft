use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bincode;
use rand::Rand;
use serde::{Deserialize, Serialize};

use super::epoch_state::EpochState;
use super::{Batch, Error, ErrorKind, HoneyBadgerBuilder, Message, MessageContent, Result};
use fault_log::{Fault, FaultKind};
use messaging::{self, DistAlgorithm, NetworkInfo, Target};
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
}

pub type Step<C, N> = messaging::Step<HoneyBadger<C, N>>;

impl<C, N> Step<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeIdT + Rand,
{
    /// Removes and returns any messages that are not accepted by remote nodes according to the
    /// mapping `remote_epochs`. This way the returned messages are postponed until later, and the
    /// remaining messages can be sent to remote nodes without delay.
    fn defer_messages<'i, I>(
        &mut self,
        remote_epochs: &'i BTreeMap<N, u64>,
        max_future_epochs: u64,
        remote_ids: I,
    ) -> impl Iterator<Item = (N, Message<N>)>
    where
        I: 'i + Iterator<Item = &'i N>,
        N: 'i,
    {
        let accepts = |us: u64, them: u64| them <= us && us <= them + max_future_epochs;
        let is_early = |us: u64, them: u64| us < them;
        let messages: Vec<_> = self.messages.drain(..).collect();
        let (mut passed_msgs, failed_msgs): (Vec<_>, Vec<_>) =
            messages.into_iter().partition(|msg| match &msg.message {
                Message::HoneyBadger { epoch, .. } => {
                    let pass = |&them| accepts(*epoch, them);
                    match &msg.target {
                        Target::All => remote_epochs.values().all(pass),
                        Target::Node(id) => remote_epochs.get(&id).map_or(false, pass),
                    }
                }
                Message::EpochStarted(_) => true,
            });
        // `Target::All` messages contained in the result of the partitioning are analyzed further
        // and each split into two sets of point messages: those which can be sent without delay and
        // those which should be postponed.
        let remote_nodes: BTreeSet<&N> = remote_ids.collect();
        let mut deferred_msgs: Vec<(N, Message<N>)> = Vec::new();
        for msg in failed_msgs {
            match msg.target {
                Target::Node(id) => {
                    deferred_msgs.push((id, msg.message));
                }
                Target::All => {
                    let message = msg.message;
                    debug!("Filtered out broadcast: {:?}", message);
                    let epoch = message.epoch();
                    let isnt_late = |&them: &u64| accepts(epoch, them) || is_early(epoch, them);
                    let accepts = |&them: &u64| accepts(epoch, them);
                    let accepting_nodes: BTreeSet<&N> = remote_epochs
                        .iter()
                        .filter(|(_, them)| accepts(them))
                        .map(|(id, _)| id)
                        .collect();
                    let non_late_nodes: BTreeSet<&N> = remote_epochs
                        .iter()
                        .filter(|(_, them)| isnt_late(them))
                        .map(|(id, _)| id)
                        .collect();
                    for &id in &accepting_nodes {
                        passed_msgs.push(Target::Node(id.clone()).message(message.clone()));
                    }
                    let late_nodes: BTreeSet<_> =
                        remote_nodes.difference(&non_late_nodes).collect();
                    for &&id in &late_nodes {
                        deferred_msgs.push((id.clone(), message.clone()));
                    }
                    debug!(
                        "Accepting nodes: {:?} --- Late nodes: {:?} --- All remote nodes: {:?}",
                        accepting_nodes, late_nodes, remote_nodes
                    );
                }
            }
        }
        self.messages.extend(passed_msgs);
        deferred_msgs.into_iter()
    }
}

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
        self.propose(&input)
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> Result<Step<C, N>> {
        self.handle_message(sender_id, message)
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
        let step = match message {
            Message::HoneyBadger { epoch, content } => {
                if !self.netinfo.is_node_validator(sender_id) {
                    return Err(ErrorKind::SenderNotValidator.into());
                }
                self.handle_message_content(sender_id, epoch, content)
            }
            Message::EpochStarted(epoch) => Ok(self.handle_epoch_started(sender_id, epoch)),
        }?;
        debug!(
            "{:?}@{} outgoing messages {:?} --- queued messages: {:?} --- remote epochs: {:?}",
            self.netinfo.our_id(),
            self.epoch,
            step.messages,
            self.outgoing_queue,
            self.remote_epochs
        );
        Ok(step)
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
        let our_id = self.netinfo.our_id();
        let deferred_msgs = step.defer_messages(
            &self.remote_epochs,
            self.max_future_epochs,
            self.netinfo.all_ids().filter(|&id| id != our_id),
        );
        // Append the deferred messages onto the queue.
        for (id, message) in deferred_msgs {
            let epoch = message.epoch();
            self.outgoing_queue
                .entry((id, epoch))
                .and_modify(|e| e.push(message.clone()))
                .or_insert_with(|| vec![message.clone()]);
        }
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
}
