use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use bincode;
use crypto::Ciphertext;
use itertools::Itertools;
use rand::Rand;
use serde::{Deserialize, Serialize};

use super::{Batch, Error, ErrorKind, HoneyBadgerBuilder, Message, MessageContent, Result};
use common_subset::{self, CommonSubset};
use fault_log::FaultKind;
use messaging::{self, DistAlgorithm, NetworkInfo};
use threshold_decryption::{self as td, ThresholdDecryption};
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
    /// The Asynchronous Common Subset instance that decides which nodes' transactions to include,
    /// indexed by epoch.
    pub(super) common_subsets: BTreeMap<u64, CommonSubset<N>>,
    /// The maximum number of `CommonSubset` instances that we run simultaneously.
    pub(super) max_future_epochs: u64,
    /// Messages for future epochs that couldn't be handled yet.
    pub(super) incoming_queue: BTreeMap<u64, Vec<(N, MessageContent<N>)>>,
    /// The threshold decryption algorithm, by epoch and proposer.
    pub(super) threshold_decryption: BTreeMap<u64, BTreeMap<N, ThresholdDecryption<N>>>,
    /// Decoded accepted proposals.
    pub(super) decrypted_contributions: BTreeMap<u64, BTreeMap<N, Vec<u8>>>,
    pub(super) _phantom: PhantomData<C>,
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
            return self.handle_message_content(sender_id, epoch, content);
        } // And ignore all messages from past epochs.
        Ok(Step::default())
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
        let epoch = self.epoch;
        let cs_step = {
            let cs = match self.common_subsets.entry(epoch) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(
                    CommonSubset::new(self.netinfo.clone(), epoch)
                        .map_err(ErrorKind::CreateCommonSubset)?,
                ),
            };
            let ser_prop =
                bincode::serialize(&proposal).map_err(|err| ErrorKind::ProposeBincode(*err))?;
            let ciphertext = self.netinfo.public_key_set().public_key().encrypt(ser_prop);
            self.has_input = true;
            cs.input(bincode::serialize(&ciphertext).unwrap())
                .map_err(ErrorKind::InputCommonSubset)?
        };
        self.process_output(cs_step, epoch)
    }

    /// Returns `true` if input for the current epoch has already been provided.
    pub fn has_input(&self) -> bool {
        !self.netinfo.is_validator() || self.has_input
    }

    /// Returns the number of validators from which we have already received a proposal for the
    /// current epoch.
    pub(crate) fn received_proposals(&self) -> usize {
        self.common_subsets
            .get(&self.epoch)
            .map_or(0, CommonSubset::received_proposals)
    }

    /// Handles a message for the given epoch.
    fn handle_message_content(
        &mut self,
        sender_id: &N,
        epoch: u64,
        content: MessageContent<N>,
    ) -> Result<Step<C, N>> {
        match content {
            MessageContent::CommonSubset(cs_msg) => {
                self.handle_common_subset_message(sender_id, epoch, cs_msg)
            }
            MessageContent::DecryptionShare { proposer_id, share } => {
                self.handle_decryption_share_message(sender_id, epoch, proposer_id, share)
            }
        }
    }

    /// Handles a message for the common subset sub-algorithm.
    fn handle_common_subset_message(
        &mut self,
        sender_id: &N,
        epoch: u64,
        message: common_subset::Message<N>,
    ) -> Result<Step<C, N>> {
        let cs_step = {
            // Borrow the instance for `epoch`, or create it.
            let cs = match self.common_subsets.entry(epoch) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    if epoch < self.epoch {
                        // Epoch has already terminated. Message is obsolete.
                        return Ok(Step::default());
                    } else {
                        let cs_result = CommonSubset::new(self.netinfo.clone(), epoch);
                        entry.insert(cs_result.map_err(ErrorKind::CreateCommonSubset)?)
                    }
                }
            };
            cs.handle_message(sender_id, message)
                .map_err(ErrorKind::HandleCommonSubsetMessage)?
        };
        self.process_output(cs_step, epoch)
    }

    /// Handles decryption shares sent by `HoneyBadger` instances.
    fn handle_decryption_share_message(
        &mut self,
        sender_id: &N,
        epoch: u64,
        proposer_id: N,
        share: td::Message,
    ) -> Result<Step<C, N>> {
        let netinfo = self.netinfo.clone();
        let td_step = self
            .threshold_decryption
            .entry(epoch)
            .or_insert_with(BTreeMap::new)
            .entry(proposer_id.clone())
            .or_insert_with(|| ThresholdDecryption::new(netinfo))
            .handle_message(sender_id, share)
            .map_err(ErrorKind::ThresholdDecryption)?;
        let mut step = self.process_threshold_decryption(epoch, proposer_id, td_step)?;
        if epoch == self.epoch {
            step.extend(self.try_output_batches()?);
        }
        Ok(step)
    }

    /// Processes a Threshold Decryption step.
    fn process_threshold_decryption(
        &mut self,
        epoch: u64,
        proposer_id: N,
        td_step: td::Step<N>,
    ) -> Result<Step<C, N>> {
        let mut step = Step::default();
        let opt_output = step.extend_with(td_step, |share| {
            MessageContent::DecryptionShare {
                proposer_id: proposer_id.clone(),
                share,
            }.with_epoch(epoch)
        });
        if let Some(output) = opt_output.into_iter().next() {
            self.decrypted_contributions
                .entry(epoch)
                .or_insert_with(BTreeMap::new)
                .insert(proposer_id, output);
        }
        Ok(step)
    }

    /// When contributions of transactions have been decrypted for all valid proposers in this
    /// epoch, moves those contributions into a batch, outputs the batch and updates the epoch.
    fn try_output_batch(&mut self) -> Result<Option<Step<C, N>>> {
        let proposer_ids = match self.threshold_decryption.get(&self.epoch) {
            Some(cts) => cts.keys().cloned().collect_vec(),
            None => return Ok(None), // Decryption hasn't even started yet.
        };

        let mut step = Step::default();

        // Deserialize the output.
        let contributions: BTreeMap<N, C> = {
            let decrypted = match self.decrypted_contributions.get(&self.epoch) {
                Some(dc) if dc.keys().eq(proposer_ids.iter()) => dc,
                _ => return Ok(None), // Not enough decrypted contributions yet.
            };
            decrypted
                .into_iter()
                .flat_map(|(proposer_id, ser_contrib)| {
                    // If deserialization fails, the proposer of that item is faulty. Ignore it.
                    if let Ok(contrib) = bincode::deserialize::<C>(ser_contrib) {
                        Some((proposer_id.clone(), contrib))
                    } else {
                        let fault_kind = FaultKind::BatchDeserializationFailed;
                        step.fault_log.append(proposer_id.clone(), fault_kind);
                        None
                    }
                })
                .collect()
        };
        let batch = Batch {
            epoch: self.epoch,
            contributions,
        };
        debug!(
            "{:?} Epoch {} output {:?}",
            self.netinfo.our_uid(),
            self.epoch,
            batch.contributions.keys().collect::<Vec<_>>()
        );
        // Queue the output and advance the epoch.
        step.output.push_back(batch);
        step.extend(self.update_epoch()?);
        Ok(Some(step))
    }

    /// Increments the epoch number and clears any state that is local to the finished epoch.
    fn update_epoch(&mut self) -> Result<Step<C, N>> {
        // Clear the state of the old epoch.
        self.threshold_decryption.remove(&self.epoch);
        self.decrypted_contributions.remove(&self.epoch);
        self.common_subsets.remove(&self.epoch);
        self.epoch += 1;
        self.has_input = false;
        let max_epoch = self.epoch + self.max_future_epochs;
        let mut step = Step::default();
        // TODO: Once stable, use `Iterator::flatten`.
        for (sender_id, content) in
            Itertools::flatten(self.incoming_queue.remove(&max_epoch).into_iter())
        {
            step.extend(self.handle_message_content(&sender_id, max_epoch, content)?);
        }
        // Handle any decryption shares received for the new epoch.
        step.extend(self.try_output_batches()?);
        Ok(step)
    }

    /// Tries to decrypt contributions from all proposers and output those in a batch.
    fn try_output_batches(&mut self) -> Result<Step<C, N>> {
        let mut step = Step::default();
        while let Some(new_step) = self.try_output_batch()? {
            step.extend(new_step);
        }
        Ok(step)
    }

    fn send_decryption_shares(
        &mut self,
        cs_output: BTreeMap<N, Vec<u8>>,
        epoch: u64,
    ) -> Result<Step<C, N>> {
        let mut step = Step::default();
        for (proposer_id, v) in cs_output {
            // TODO: Input into ThresholdDecryption. Check errors!
            let ciphertext: Ciphertext = match bincode::deserialize(&v) {
                Ok(ciphertext) => ciphertext,
                Err(err) => {
                    warn!(
                        "Cannot deserialize ciphertext from {:?}: {:?}",
                        proposer_id, err
                    );
                    let fault_kind = FaultKind::InvalidCiphertext;
                    step.fault_log.append(proposer_id, fault_kind);
                    continue;
                }
            };
            let netinfo = self.netinfo.clone();
            let td_step = match self
                .threshold_decryption
                .entry(epoch)
                .or_insert_with(BTreeMap::new)
                .entry(proposer_id.clone())
                .or_insert_with(|| ThresholdDecryption::new(netinfo))
                .input(ciphertext)
            {
                Ok(td_step) => td_step,
                Err(td::Error::InvalidCiphertext(_)) => {
                    warn!("Invalid ciphertext from {:?}", proposer_id);
                    let fault_kind = FaultKind::ShareDecryptionFailed;
                    step.fault_log.append(proposer_id.clone(), fault_kind);
                    continue;
                }
                Err(err) => return Err(ErrorKind::ThresholdDecryption(err).into()),
            };
            step.extend(self.process_threshold_decryption(epoch, proposer_id, td_step)?);
        }
        if epoch == self.epoch {
            step.extend(self.try_output_batches()?);
        }
        Ok(step)
    }

    /// Checks whether the current epoch has output, and if it does, sends out our decryption
    /// shares.  The `epoch` argument allows to differentiate between calls which produce output in
    /// all conditions, `epoch == None`, and calls which only produce output in a given epoch,
    /// `epoch == Some(given_epoch)`.
    fn process_output(
        &mut self,
        cs_step: common_subset::Step<N>,
        epoch: u64,
    ) -> Result<Step<C, N>> {
        let mut step = Step::default();
        let mut cs_outputs = step.extend_with(cs_step, |cs_msg| {
            MessageContent::CommonSubset(cs_msg).with_epoch(epoch)
        });
        if let Some(cs_output) = cs_outputs.pop_front() {
            // There is at most one output.
            step.extend(self.send_decryption_shares(cs_output, epoch)?);
        }
        if !cs_outputs.is_empty() {
            error!("Multiple outputs from a single Common Subset instance.");
        }
        Ok(step)
    }
}
