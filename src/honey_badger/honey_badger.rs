use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;

use derivative::Derivative;
use rand::{Rand, Rng};
use serde::{de::DeserializeOwned, Serialize};
use serde_derive::{Deserialize, Serialize};

use super::epoch_state::EpochState;
use super::{Batch, Error, ErrorKind, HoneyBadgerBuilder, Message, Result};
use {util, Contribution, DistAlgorithm, Fault, FaultKind, NetworkInfo, NodeIdT};

pub use super::epoch_state::SubsetHandlingStrategy;

/// An instance of the Honey Badger Byzantine fault tolerant consensus algorithm.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct HoneyBadger<C, N: Rand> {
    /// Shared network data.
    pub(super) netinfo: Arc<NetworkInfo<N>>,
    /// A session identifier. Different session IDs foil replay attacks in two instances with the
    /// same epoch numbers and the same validators.
    pub(super) session_id: u64,
    /// The earliest epoch from which we have not yet received output.
    pub(super) epoch: u64,
    /// Whether we have already submitted a proposal for the current epoch.
    pub(super) has_input: bool,
    /// The subalgorithms for ongoing epochs.
    pub(super) epochs: BTreeMap<u64, EpochState<C, N>>,
    /// The maximum number of `Subset` instances that we run simultaneously.
    pub(super) max_future_epochs: u64,
    /// A random number generator used for secret key generation.
    // Boxed to avoid overloading the algorithm's type with more generics.
    #[derivative(Debug(format_with = "util::fmt_rng"))]
    pub(super) rng: Box<dyn Rng + Send + Sync>,
    /// Represents the optimization strategy to use for output of the `Subset` algorithm.
    pub(super) subset_handling_strategy: SubsetHandlingStrategy,
    /// The schedule for which rounds we should use threshold encryption.
    pub(super) encryption_schedule: EncryptionSchedule,
    /// Whether to generate a pseudorandom value in each epoch.
    pub(super) random_value: bool,
}

pub type Step<C, N> = ::DaStep<HoneyBadger<C, N>>;

impl<C, N> DistAlgorithm for HoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
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
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Rand,
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn builder(netinfo: Arc<NetworkInfo<N>>) -> HoneyBadgerBuilder<C, N> {
        HoneyBadgerBuilder::new(netinfo)
    }

    /// Proposes a contribution in the current epoch.
    ///
    /// Returns an error if we already made a proposal in this epoch.
    ///
    /// If we are the only validator, this will immediately output a batch, containing our
    /// proposal.
    pub fn propose(&mut self, proposal: &C) -> Result<Step<C, N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        self.has_input = true;
        let epoch = self.epoch;
        let step = {
            let epoch_state = {
                self.epoch_state_mut(epoch)?;
                self.epochs.get_mut(&epoch).expect(
                    "We created the epoch_state in `self.epoch_state_mut(...)` just a moment ago.",
                )
            };
            let rng = &mut self.rng;
            epoch_state.propose(proposal, rng)?
        };
        Ok(step.join(self.try_output_batches()?))
    }

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message(&mut self, sender_id: &N, message: Message<N>) -> Result<Step<C, N>> {
        if !self.netinfo.is_node_validator(sender_id) {
            return Err(ErrorKind::UnknownSender.into());
        }
        let Message { epoch, content } = message;
        if epoch > self.epoch + self.max_future_epochs {
            Ok(Fault::new(sender_id.clone(), FaultKind::UnexpectedHbMessageEpoch).into())
        } else if epoch < self.epoch {
            // The message is late; discard it.
            Ok(Step::default())
        } else {
            let step = self
                .epoch_state_mut(epoch)?
                .handle_message_content(sender_id, content)?;
            Ok(step.join(self.try_output_batches()?))
        }
    }

    /// Returns `true` if input for the current epoch has already been provided.
    pub fn has_input(&self) -> bool {
        !self.netinfo.is_validator() || self.has_input
    }

    /// Returns the current encryption schedule that determines in which epochs contributions are
    /// encrypted.
    pub fn get_encryption_schedule(&self) -> EncryptionSchedule {
        self.encryption_schedule
    }

    /// Returns the epoch of the next batch that will be output.
    pub fn next_epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the number of validators from which we have already received a proposal for the
    /// current epoch.
    pub(crate) fn received_proposals(&self) -> usize {
        self.epochs
            .get(&self.epoch)
            .map_or(0, EpochState::received_proposals)
    }

    /// Increments the epoch number and clears any state that is local to the finished epoch.
    fn update_epoch(&mut self) {
        // Clear the state of the old epoch.
        self.epochs.remove(&self.epoch);
        self.epoch += 1;
        self.has_input = false;
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
            step.output.push(batch);
            step.fault_log.extend(fault_log);
            self.update_epoch();
        }
        Ok(step)
    }

    /// Returns a mutable reference to the state of the given `epoch`. Initializes a new one, if it
    /// doesn't exist yet.
    fn epoch_state_mut(&mut self, epoch: u64) -> Result<&mut EpochState<C, N>> {
        Ok(match self.epochs.entry(epoch) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(EpochState::new(
                self.netinfo.clone(),
                self.session_id,
                epoch,
                self.subset_handling_strategy.clone(),
                self.random_value,
                self.encryption_schedule.use_on_epoch(epoch),
            )?),
        })
    }

    /// Returns the maximum future epochs of the Honey Badger algorithm instance.
    pub fn max_future_epochs(&self) -> u64 {
        self.max_future_epochs
    }
}

/// How frequently Threshold Encryption should be used.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum EncryptionSchedule {
    Always,
    Never,
    EveryNthEpoch(u32),
    /// How many with encryption, followed by how many without encryption.
    TickTock(u32, u32),
}

impl EncryptionSchedule {
    pub fn use_on_epoch(self, epoch: u64) -> bool {
        match self {
            EncryptionSchedule::Always => true,
            EncryptionSchedule::Never => false,
            EncryptionSchedule::EveryNthEpoch(n) => (epoch % u64::from(n)) == 0,
            EncryptionSchedule::TickTock(on, off) => (epoch % u64::from(on + off)) <= u64::from(on),
        }
    }
}
