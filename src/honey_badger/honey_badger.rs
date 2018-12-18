use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;

use derivative::Derivative;
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};
use serde_derive::{Deserialize, Serialize};

use super::epoch_state::EpochState;
use super::{Batch, Error, FaultKind, HoneyBadgerBuilder, Message, Result};
use crate::{Contribution, DistAlgorithm, Fault, NetworkInfo, NodeIdT};

use super::Params;

/// An instance of the Honey Badger Byzantine fault tolerant consensus algorithm.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct HoneyBadger<C, N> {
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
    /// Parameters controlling Honey Badger's behavior and performance.
    pub(super) params: Params,
}

/// A `HoneyBadger` step, possibly containing multiple outputs.
pub type Step<C, N> = crate::DaStep<HoneyBadger<C, N>>;

impl<C, N> DistAlgorithm for HoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT,
{
    type NodeId = N;
    type Input = C;
    type Output = Batch<C, N>;
    type Message = Message<N>;
    type Error = Error;
    type FaultKind = FaultKind;

    fn handle_input<R: Rng>(&mut self, input: Self::Input, rng: &mut R) -> Result<Step<C, N>> {
        self.propose(&input, rng)
    }

    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &Self::NodeId,
        message: Self::Message,
        _rng: &mut R,
    ) -> Result<Step<C, N>> {
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
    N: NodeIdT,
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
    pub fn propose<R: Rng>(&mut self, proposal: &C, rng: &mut R) -> Result<Step<C, N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        self.has_input = true;
        let step = self.epoch_state_mut(self.epoch)?.propose(proposal, rng)?;
        Ok(step.join(self.try_output_batches()?))
    }

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message(&mut self, sender_id: &N, message: Message<N>) -> Result<Step<C, N>> {
        if !self.netinfo.is_node_validator(sender_id) {
            return Err(Error::UnknownSender);
        }
        let Message { epoch, content } = message;
        if epoch > self.epoch + self.params.max_future_epochs {
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
        self.params.encryption_schedule
    }

    /// Returns the epoch of the next batch that will be output.
    pub fn next_epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the number of validators from which we have already received a proposal for the
    /// current epoch.
    ///
    /// This can be used to find out whether our node is stalling progress. Depending on the
    /// application logic, nodes may e.g. only propose when they have any pending transactions. In
    /// that case, they should repeatedly call this method: if it returns _f + 1_ or more, that
    /// means at least one correct node has proposed a contribution. In that case, we might want to
    /// propose one, too, even if it's empty, to avoid unnecessarily delaying the next batch.
    pub fn received_proposals(&self) -> usize {
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
                self.params.subset_handling_strategy.clone(),
                self.params.encryption_schedule.use_on_epoch(epoch),
            )?),
        })
    }

    /// Returns the maximum future epochs of the Honey Badger algorithm instance.
    pub fn max_future_epochs(&self) -> u64 {
        self.params.max_future_epochs
    }

    /// Returns the parameters controlling Honey Badger's behavior and performance.
    pub fn params(&self) -> &Params {
        &self.params
    }
}

/// How frequently Threshold Encryption should be used.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum EncryptionSchedule {
    /// Always encrypt. All contributions are encrypted in every epoch.
    Always,
    /// Never encrypt. All contributions are plaintext in every epoch.
    Never,
    /// Every _n_-th epoch uses encryption. In all other epochs, contributions are plaintext.
    EveryNthEpoch(u32),
    /// With `TickTock(n, m)`, `n` epochs use encryption, followed by `m` epochs that don't.
    /// `m` out of `n + m` epochs will use plaintext contributions.
    TickTock(u32, u32),
}

impl EncryptionSchedule {
    /// Returns `true` if the contributions in the `epoch` should be encrypted.
    pub fn use_on_epoch(self, epoch: u64) -> bool {
        match self {
            EncryptionSchedule::Always => true,
            EncryptionSchedule::Never => false,
            EncryptionSchedule::EveryNthEpoch(n) => (epoch % u64::from(n)) == 0,
            EncryptionSchedule::TickTock(on, off) => (epoch % u64::from(on + off)) <= u64::from(on),
        }
    }
}
