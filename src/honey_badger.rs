//! # Honey Badger
//!
//! Honey Badger allows a network of _N_ nodes with at most _f_ faulty ones,
//! where _3 f < N_, to input "contributions" - any kind of data -, and to agree on a sequence of
//! _batches_ of contributions. The protocol proceeds in _epochs_, starting at number 0, and outputs
//! one batch in each epoch. It never terminates: It handles a continuous stream of incoming
//! contributions and keeps producing new batches from them. All correct nodes will output the same
//! batch for each epoch. Each validator proposes one contribution per epoch, and every batch will
//! contain the contributions of at least _N - f_ validators.
//!
//! ## How it works
//!
//! In every epoch, every validator encrypts their contribution and proposes it to the others.
//! A `CommonSubset` instance determines which proposals are accepted and will be part of the new
//! batch. Using threshold encryption, the nodes collaboratively decrypt all accepted
//! contributions. Invalid contributions (that e.g. cannot be deserialized) are discarded - their
//! proposers must be faulty -, and the remaining ones are output as the new batch. The next epoch
//! begins as soon as the validators propose new contributions again.
//!
//! So it is essentially an endlessly repeating `CommonSubset`, but with the proposed values
//! encrypted. The encryption makes it harder for an attacker to try and censor a particular value
//! by influencing the set of proposals that make it into the common subset, because they don't
//! know the decrypted values before the subset is determined.

use rand::Rand;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::mem;
use std::sync::Arc;

use bincode;
use crypto::{Ciphertext, DecryptionShare};
use failure::{Backtrace, Context, Fail};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use common_subset::{self, CommonSubset};
use fault_log::{Fault, FaultKind, FaultLog};
use messaging::{self, DistAlgorithm, NetworkInfo, Target};

/// Honey badger error variants.
#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "ProposeBincode error: {}", _0)]
    ProposeBincode(bincode::ErrorKind),
    #[fail(display = "ProposeCommonSubset0 error: {}", _0)]
    ProposeCommonSubset0(common_subset::Error),
    #[fail(display = "ProposeCommonSubset1 error: {}", _0)]
    ProposeCommonSubset1(common_subset::Error),
    #[fail(display = "HandleCommonMessageCommonSubset0 error: {}", _0)]
    HandleCommonMessageCommonSubset0(common_subset::Error),
    #[fail(display = "HandleCommonMessageCommonSubset1 error: {}", _0)]
    HandleCommonMessageCommonSubset1(common_subset::Error),
    #[fail(display = "Unknown sender")]
    UnknownSender,
}

/// A honey badger error.
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

/// A Honey Badger builder, to configure the parameters and create new instances of `HoneyBadger`.
pub struct HoneyBadgerBuilder<C, NodeUid> {
    /// Shared network data.
    netinfo: Arc<NetworkInfo<NodeUid>>,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    _phantom: PhantomData<C>,
}

impl<C, NodeUid> HoneyBadgerBuilder<C, NodeUid>
where
    C: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq,
    NodeUid: Ord + Clone + Debug + Rand,
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn new(netinfo: Arc<NetworkInfo<NodeUid>>) -> Self {
        HoneyBadgerBuilder {
            netinfo,
            max_future_epochs: 3,
            _phantom: PhantomData,
        }
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: usize) -> &mut Self {
        self.max_future_epochs = max_future_epochs;
        self
    }

    /// Creates a new Honey Badger instance.
    pub fn build(&self) -> HoneyBadger<C, NodeUid> {
        HoneyBadger {
            netinfo: self.netinfo.clone(),
            epoch: 0,
            has_input: false,
            common_subsets: BTreeMap::new(),
            max_future_epochs: self.max_future_epochs as u64,
            incoming_queue: BTreeMap::new(),
            received_shares: BTreeMap::new(),
            decrypted_contributions: BTreeMap::new(),
            ciphertexts: BTreeMap::new(),
            _phantom: PhantomData,
        }
    }
}

/// An instance of the Honey Badger Byzantine fault tolerant consensus algorithm.
#[derive(Debug)]
pub struct HoneyBadger<C, NodeUid: Rand> {
    /// Shared network data.
    netinfo: Arc<NetworkInfo<NodeUid>>,
    /// The earliest epoch from which we have not yet received output.
    epoch: u64,
    /// Whether we have already submitted a proposal for the current epoch.
    has_input: bool,
    /// The Asynchronous Common Subset instance that decides which nodes' transactions to include,
    /// indexed by epoch.
    common_subsets: BTreeMap<u64, CommonSubset<NodeUid>>,
    /// The maximum number of `CommonSubset` instances that we run simultaneously.
    max_future_epochs: u64,
    /// Messages for future epochs that couldn't be handled yet.
    incoming_queue: BTreeMap<u64, Vec<(NodeUid, MessageContent<NodeUid>)>>,
    /// Received decryption shares for an epoch. Each decryption share has a sender and a
    /// proposer. The outer `BTreeMap` has epochs as its key. The next `BTreeMap` has proposers as
    /// its key. The inner `BTreeMap` has the sender as its key.
    received_shares: BTreeMap<u64, BTreeMap<NodeUid, BTreeMap<NodeUid, DecryptionShare>>>,
    /// Decoded accepted proposals.
    decrypted_contributions: BTreeMap<NodeUid, Vec<u8>>,
    /// Ciphertexts output by Common Subset in an epoch.
    ciphertexts: BTreeMap<u64, BTreeMap<NodeUid, Ciphertext>>,
    _phantom: PhantomData<C>,
}

pub type Step<C, NodeUid> = messaging::Step<HoneyBadger<C, NodeUid>>;

impl<C, NodeUid> DistAlgorithm for HoneyBadger<C, NodeUid>
where
    C: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq,
    NodeUid: Ord + Clone + Debug + Rand,
{
    type NodeUid = NodeUid;
    type Input = C;
    type Output = Batch<C, NodeUid>;
    type Message = Message<NodeUid>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<Step<C, NodeUid>> {
        self.propose(&input)
    }

    fn handle_message(
        &mut self,
        sender_id: &NodeUid,
        message: Self::Message,
    ) -> Result<Step<C, NodeUid>> {
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

    fn our_id(&self) -> &NodeUid {
        self.netinfo.our_uid()
    }
}

impl<C, NodeUid> HoneyBadger<C, NodeUid>
where
    C: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq,
    NodeUid: Ord + Clone + Debug + Rand,
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn builder(netinfo: Arc<NetworkInfo<NodeUid>>) -> HoneyBadgerBuilder<C, NodeUid> {
        HoneyBadgerBuilder::new(netinfo)
    }

    /// Proposes a new item in the current epoch.
    pub fn propose(&mut self, proposal: &C) -> Result<Step<C, NodeUid>> {
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

    /// Handles a message for the given epoch.
    fn handle_message_content(
        &mut self,
        sender_id: &NodeUid,
        epoch: u64,
        content: MessageContent<NodeUid>,
    ) -> Result<Step<C, NodeUid>> {
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
        sender_id: &NodeUid,
        epoch: u64,
        message: common_subset::Message<NodeUid>,
    ) -> Result<Step<C, NodeUid>> {
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
        sender_id: &NodeUid,
        epoch: u64,
        proposer_id: NodeUid,
        share: DecryptionShare,
    ) -> Result<Step<C, NodeUid>> {
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
        sender_id: &NodeUid,
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
    fn try_output_batch(&mut self) -> Result<Option<Step<C, NodeUid>>> {
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
        let contributions: BTreeMap<NodeUid, C> =
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
                })
                .collect();
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
    fn update_epoch(&mut self) -> Result<Step<C, NodeUid>> {
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
    fn try_output_batches(&mut self) -> Result<Step<C, NodeUid>> {
        let mut step = Step::default();
        while let Some(new_step) = self.try_output_batch()? {
            step.extend(new_step);
        }
        Ok(step)
    }

    /// Tries to decrypt the contribution from a given proposer.
    fn try_decrypt_proposer_contribution(&mut self, proposer_id: NodeUid) -> bool {
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
        cs_output: BTreeMap<NodeUid, Vec<u8>>,
        epoch: u64,
    ) -> Result<Step<C, NodeUid>> {
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
        proposer_id: &NodeUid,
        ciphertext: &Ciphertext,
        epoch: u64,
    ) -> Result<Step<C, NodeUid>> {
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
        proposer_id: &NodeUid,
        ciphertext: &Ciphertext,
        epoch: u64,
    ) -> (BTreeSet<NodeUid>, FaultLog<NodeUid>) {
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
        proposer_id: &NodeUid,
        incorrect_senders: BTreeSet<NodeUid>,
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
        cs_step: common_subset::Step<NodeUid>,
        epoch: u64,
    ) -> Result<Step<C, NodeUid>> {
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

/// A batch of contributions the algorithm has output.
#[derive(Clone, Debug)]
pub struct Batch<C, NodeUid> {
    pub epoch: u64,
    pub contributions: BTreeMap<NodeUid, C>,
}

impl<C, NodeUid: Ord> Batch<C, NodeUid> {
    /// Returns an iterator over references to all transactions included in the batch.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = <&'a C as IntoIterator>::Item>
    where
        &'a C: IntoIterator,
    {
        self.contributions.values().flat_map(|item| item)
    }

    /// Returns an iterator over all transactions included in the batch. Consumes the batch.
    pub fn into_tx_iter(self) -> impl Iterator<Item = <C as IntoIterator>::Item>
    where
        C: IntoIterator,
    {
        self.contributions.into_iter().flat_map(|(_, vec)| vec)
    }

    /// Returns the number of transactions in the batch (without detecting duplicates).
    pub fn len<Tx>(&self) -> usize
    where
        C: AsRef<[Tx]>,
    {
        self.contributions
            .values()
            .map(C::as_ref)
            .map(<[Tx]>::len)
            .sum()
    }

    /// Returns `true` if the batch contains no transactions.
    pub fn is_empty<Tx>(&self) -> bool
    where
        C: AsRef<[Tx]>,
    {
        self.contributions
            .values()
            .map(C::as_ref)
            .all(<[Tx]>::is_empty)
    }
}

/// The content of a `HoneyBadger` message. It should be further annotated with an epoch.
#[derive(Clone, Debug, Deserialize, Rand, Serialize)]
pub enum MessageContent<NodeUid: Rand> {
    /// A message belonging to the common subset algorithm in the given epoch.
    CommonSubset(common_subset::Message<NodeUid>),
    /// A decrypted share of the output of `proposer_id`.
    DecryptionShare {
        proposer_id: NodeUid,
        share: DecryptionShare,
    },
}

impl<NodeUid: Rand> MessageContent<NodeUid> {
    pub fn with_epoch(self, epoch: u64) -> Message<NodeUid> {
        Message {
            epoch,
            content: self,
        }
    }
}

/// A message sent to or received from another node's Honey Badger instance.
#[derive(Clone, Debug, Deserialize, Rand, Serialize)]
pub struct Message<NodeUid: Rand> {
    epoch: u64,
    content: MessageContent<NodeUid>,
}

impl<NodeUid: Rand> Message<NodeUid> {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
