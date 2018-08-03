use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::mem;
use std::sync::Arc;

use bincode;
use crypto::{Ciphertext, DecryptionShare};
use itertools::Itertools;
use rand::Rand;
use serde::{Deserialize, Serialize};

use super::{Batch, Error, ErrorKind, HoneyBadgerBuilder, Message, MessageContent, Result};
use common_subset::{self, CommonSubset};
use fault_log::{Fault, FaultKind, FaultLog};
use messaging::{self, DistAlgorithm, NetworkInfo, Target};
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
    /// Received decryption shares for an epoch. Each decryption share has a sender and a
    /// proposer. The outer `BTreeMap` has epochs as its key. The next `BTreeMap` has proposers as
    /// its key. The inner `BTreeMap` has the sender as its key.
    pub(super) received_shares: BTreeMap<u64, BTreeMap<N, BTreeMap<N, DecryptionShare>>>,
    /// Decoded accepted proposals.
    pub(super) decrypted_contributions: BTreeMap<N, Vec<u8>>,
    /// Ciphertexts output by Common Subset in an epoch.
    pub(super) ciphertexts: BTreeMap<u64, BTreeMap<N, Ciphertext>>,
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
                        .map_err(ErrorKind::ProposeCommonSubset0)?,
                ),
            };
            let ser_prop =
                bincode::serialize(&proposal).map_err(|err| ErrorKind::ProposeBincode(*err))?;
            let ciphertext = self.netinfo.public_key_set().public_key().encrypt(ser_prop);
            self.has_input = true;
            cs.input(bincode::serialize(&ciphertext).unwrap())
                .map_err(ErrorKind::ProposeCommonSubset1)?
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
                        entry.insert(
                            CommonSubset::new(self.netinfo.clone(), epoch)
                                .map_err(ErrorKind::HandleCommonMessageCommonSubset0)?,
                        )
                    }
                }
            };
            cs.handle_message(sender_id, message)
                .map_err(ErrorKind::HandleCommonMessageCommonSubset1)?
        };
        let step = self.process_output(cs_step, epoch)?;
        self.remove_terminated();
        Ok(step)
    }

    /// Handles decryption shares sent by `HoneyBadger` instances.
    fn handle_decryption_share_message(
        &mut self,
        sender_id: &N,
        epoch: u64,
        proposer_id: N,
        share: DecryptionShare,
    ) -> Result<Step<C, N>> {
        if let Some(ciphertext) = self
            .ciphertexts
            .get(&epoch)
            .and_then(|cts| cts.get(&proposer_id))
        {
            if !self.verify_decryption_share(sender_id, &share, ciphertext) {
                let fault_kind = FaultKind::UnverifiedDecryptionShareSender;
                return Ok(Fault::new(sender_id.clone(), fault_kind).into());
            }
        }

        // Insert the share.
        self.received_shares
            .entry(epoch)
            .or_insert_with(BTreeMap::new)
            .entry(proposer_id)
            .or_insert_with(BTreeMap::new)
            .insert(sender_id.clone(), share);

        if epoch == self.epoch {
            self.try_output_batches()
        } else {
            Ok(Step::default())
        }
    }

    /// Verifies a given decryption share using the sender's public key and the proposer's
    /// ciphertext. Returns `true` if verification has been successful and `false` if verification
    /// has failed.
    fn verify_decryption_share(
        &self,
        sender_id: &N,
        share: &DecryptionShare,
        ciphertext: &Ciphertext,
    ) -> bool {
        if let Some(pk) = self.netinfo.public_key_share(sender_id) {
            pk.verify_decryption_share(&share, ciphertext)
        } else {
            false
        }
    }

    /// When contributions of transactions have been decrypted for all valid proposers in this
    /// epoch, moves those contributions into a batch, outputs the batch and updates the epoch.
    fn try_output_batch(&mut self) -> Result<Option<Step<C, N>>> {
        // Return if we don't have ciphertexts yet.
        let proposer_ids = match self.ciphertexts.get(&self.epoch) {
            Some(cts) => cts.keys().cloned().collect_vec(),
            None => return Ok(None),
        };

        // Try to decrypt all contributions. If some are still missing, return.
        if !proposer_ids
            .into_iter()
            .all(|id| self.try_decrypt_proposer_contribution(id))
        {
            return Ok(None);
        }

        let mut step = Step::default();

        // Deserialize the output.
        let contributions: BTreeMap<N, C> =
            mem::replace(&mut self.decrypted_contributions, BTreeMap::new())
                .into_iter()
                .flat_map(|(proposer_id, ser_contrib)| {
                    // If deserialization fails, the proposer of that item is faulty. Ignore it.
                    if let Ok(contrib) = bincode::deserialize::<C>(&ser_contrib) {
                        Some((proposer_id, contrib))
                    } else {
                        let fault_kind = FaultKind::BatchDeserializationFailed;
                        step.fault_log.append(proposer_id, fault_kind);
                        None
                    }
                }).collect();
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
        self.ciphertexts.remove(&self.epoch);
        self.received_shares.remove(&self.epoch);
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

    /// Tries to decrypt the contribution from a given proposer.
    fn try_decrypt_proposer_contribution(&mut self, proposer_id: N) -> bool {
        if self.decrypted_contributions.contains_key(&proposer_id) {
            return true; // Already decrypted.
        }
        let shares = if let Some(shares) = self
            .received_shares
            .get(&self.epoch)
            .and_then(|sh| sh.get(&proposer_id))
        {
            shares
        } else {
            return false; // No shares yet.
        };
        if shares.len() <= self.netinfo.num_faulty() {
            return false; // Not enough shares yet.
        }

        if let Some(ciphertext) = self
            .ciphertexts
            .get(&self.epoch)
            .and_then(|cts| cts.get(&proposer_id))
        {
            match {
                let to_idx = |(id, share)| (self.netinfo.node_index(id).unwrap(), share);
                let share_itr = shares.into_iter().map(to_idx);
                self.netinfo.public_key_set().decrypt(share_itr, ciphertext)
            } {
                Ok(contrib) => {
                    self.decrypted_contributions.insert(proposer_id, contrib);
                }
                Err(err) => error!("{:?} Decryption failed: {:?}.", self.our_id(), err),
            }
        }
        true
    }

    fn send_decryption_shares(
        &mut self,
        cs_output: BTreeMap<N, Vec<u8>>,
        epoch: u64,
    ) -> Result<Step<C, N>> {
        let mut step = Step::default();
        let mut ciphertexts = BTreeMap::new();
        for (proposer_id, v) in cs_output {
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
            if !ciphertext.verify() {
                warn!("Invalid ciphertext from {:?}", proposer_id);
                let fault_kind = FaultKind::ShareDecryptionFailed;
                step.fault_log.append(proposer_id.clone(), fault_kind);
                continue;
            }
            let (incorrect_senders, faults) =
                self.verify_pending_decryption_shares(&proposer_id, &ciphertext, epoch);
            self.remove_incorrect_decryption_shares(&proposer_id, incorrect_senders, epoch);
            step.fault_log.extend(faults);
            if self.netinfo.is_validator() {
                step.extend(self.send_decryption_share(&proposer_id, &ciphertext, epoch)?);
            }
            ciphertexts.insert(proposer_id, ciphertext);
        }
        self.ciphertexts.insert(epoch, ciphertexts);
        if epoch == self.epoch {
            step.extend(self.try_output_batches()?);
        }
        Ok(step)
    }

    /// Sends decryption shares without verifying the ciphertext.
    fn send_decryption_share(
        &mut self,
        proposer_id: &N,
        ciphertext: &Ciphertext,
        epoch: u64,
    ) -> Result<Step<C, N>> {
        let share = self
            .netinfo
            .secret_key_share()
            .decrypt_share_no_verify(&ciphertext);
        // Send the share to remote nodes.
        let our_id = self.netinfo.our_uid().clone();
        // Insert the share.
        self.received_shares
            .entry(epoch)
            .or_insert_with(BTreeMap::new)
            .entry(proposer_id.clone())
            .or_insert_with(BTreeMap::new)
            .insert(our_id, share.clone());
        let content = MessageContent::DecryptionShare {
            proposer_id: proposer_id.clone(),
            share,
        };
        Ok(Target::All.message(content.with_epoch(epoch)).into())
    }

    /// Verifies the shares of the current epoch that are pending verification. Returned are the
    /// senders with incorrect pending shares.
    fn verify_pending_decryption_shares(
        &self,
        proposer_id: &N,
        ciphertext: &Ciphertext,
        epoch: u64,
    ) -> (BTreeSet<N>, FaultLog<N>) {
        let mut incorrect_senders = BTreeSet::new();
        let mut fault_log = FaultLog::new();
        if let Some(sender_shares) = self
            .received_shares
            .get(&epoch)
            .and_then(|e| e.get(proposer_id))
        {
            for (sender_id, share) in sender_shares {
                if !self.verify_decryption_share(sender_id, share, ciphertext) {
                    let fault_kind = FaultKind::UnverifiedDecryptionShareSender;
                    fault_log.append(sender_id.clone(), fault_kind);
                    incorrect_senders.insert(sender_id.clone());
                }
            }
        }
        (incorrect_senders, fault_log)
    }

    fn remove_incorrect_decryption_shares(
        &mut self,
        proposer_id: &N,
        incorrect_senders: BTreeSet<N>,
        epoch: u64,
    ) {
        if let Some(sender_shares) = self
            .received_shares
            .get_mut(&epoch)
            .and_then(|e| e.get_mut(proposer_id))
        {
            for sender_id in incorrect_senders {
                sender_shares.remove(&sender_id);
            }
        }
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

    /// Removes all `CommonSubset` instances from _past_ epochs that have terminated.
    fn remove_terminated(&mut self) {
        let terminated_epochs: Vec<u64> = self
            .common_subsets
            .iter()
            .take_while(|&(epoch, _)| *epoch < self.epoch)
            .filter(|&(_, cs)| cs.terminated())
            .map(|(epoch, _)| *epoch)
            .collect();
        for epoch in terminated_epochs {
            debug!(
                "{:?} Epoch {} has terminated.",
                self.netinfo.our_uid(),
                epoch
            );
            self.common_subsets.remove(&epoch);
        }
    }
}
