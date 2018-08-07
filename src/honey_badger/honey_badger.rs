use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;

use bincode;
use rand::Rand;
use serde::{Deserialize, Serialize};

use super::epoch_state::EpochState;
use super::{Batch, Error, ErrorKind, HoneyBadgerBuilder, Message, MessageContent, Result};
use messaging::{self, DistAlgorithm, NetworkInfo};
use traits::{Contribution, NodeUidT};

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
    /// The maximum number of `CommonSubset` instances that we run simultaneously.
    pub(super) max_future_epochs: u64,
    /// Messages for future epochs that couldn't be handled yet.
    pub(super) incoming_queue: BTreeMap<u64, Vec<(N, MessageContent<N>)>>,
}

pub type Step<C, N> = messaging::Step<HoneyBadger<C, N>>;

impl<C, N> DistAlgorithm for HoneyBadger<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeUidT + Rand,
{
    type NodeUid = N;
    type Input = C;
    type Output = Batch<C, N>;
    type Message = Message<N>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<Step<C, N>> {
        self.propose(&input)
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> Result<Step<C, N>> {
        self.handle_message(sender_id, message)
    }

    fn terminated(&self) -> bool {
        false
    }

    fn our_id(&self) -> &N {
        self.netinfo.our_uid()
    }
}

impl<C, N> HoneyBadger<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeUidT + Rand,
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
        if !self.netinfo.is_node_validator(sender_id) {
            return Err(ErrorKind::UnknownSender.into());
        }
        let Message { epoch, content } = message;
        if epoch > self.epoch + self.max_future_epochs {
            // Postpone handling this message.
            self.incoming_queue
                .entry(epoch)
                .or_insert_with(Vec::new)
                .push((sender_id.clone(), content));
        } else if epoch == self.epoch {
            let mut step = self
                .epoch_state_mut(epoch)?
                .handle_message_content(sender_id, content)?;
            step.extend(self.try_output_batches()?);
            return Ok(step);
        } // And ignore all messages from past epochs.
        Ok(Step::default())
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
        self.has_input = false;
        let max_epoch = self.epoch + self.max_future_epochs;
        let mut step = Step::default();
        if let Some(messages) = self.incoming_queue.remove(&max_epoch) {
            let epoch_state = self.epoch_state_mut(max_epoch)?;
            for (sender_id, content) in messages {
                step.extend(epoch_state.handle_message_content(&sender_id, content)?);
            }
        }
        Ok(step)
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
}
