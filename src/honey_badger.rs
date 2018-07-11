use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Not;
use std::sync::Arc;

use bincode;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use common_subset::{self, CommonSubset};
use crypto::{Ciphertext, DecryptionShare};
use fault_log::{FaultKind, FaultLog};
use messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};

error_chain!{
    types {
        Error, ErrorKind, ResultExt, HoneyBadgerResult;
    }

    links {
        CommonSubset(common_subset::Error, common_subset::ErrorKind);
    }

    foreign_links {
        Bincode(Box<bincode::ErrorKind>);
    }

    errors {
        UnknownSender
    }
}

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
    NodeUid: Ord + Clone + Debug,
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
            messages: MessageQueue(VecDeque::new()),
            output: VecDeque::new(),
            incoming_queue: BTreeMap::new(),
            received_shares: BTreeMap::new(),
            decrypted_contributions: BTreeMap::new(),
            ciphertexts: BTreeMap::new(),
        }
    }
}

/// An instance of the Honey Badger Byzantine fault tolerant consensus algorithm.
pub struct HoneyBadger<C, NodeUid> {
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
    /// The messages that need to be sent to other nodes.
    messages: MessageQueue<NodeUid>,
    /// The outputs from completed epochs.
    output: VecDeque<Batch<C, NodeUid>>,
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
}

impl<C, NodeUid> DistAlgorithm for HoneyBadger<C, NodeUid>
where
    C: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq,
    NodeUid: Ord + Clone + Debug,
{
    type NodeUid = NodeUid;
    type Input = C;
    type Output = Batch<C, NodeUid>;
    type Message = Message<NodeUid>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        Ok(self.propose(&input)?)
    }

    fn handle_message(
        &mut self,
        sender_id: &NodeUid,
        message: Self::Message,
    ) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        if !self.netinfo.all_uids().contains(sender_id) {
            return Err(ErrorKind::UnknownSender.into());
        }
        let Message { epoch, content } = message;
        if epoch < self.epoch {
            // Ignore all messages from past epochs.
            return Ok(FaultLog::new());
        }
        if epoch > self.epoch + self.max_future_epochs {
            // Postpone handling this message.
            self.incoming_queue
                .entry(epoch)
                .or_insert_with(Vec::new)
                .push((sender_id.clone(), content));
            return Ok(FaultLog::new());
        }
        self.handle_message_content(sender_id, epoch, content)
    }

    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, NodeUid>> {
        self.messages.pop_front()
    }

    fn next_output(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
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
    NodeUid: Ord + Clone + Debug,
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn builder(netinfo: Arc<NetworkInfo<NodeUid>>) -> HoneyBadgerBuilder<C, NodeUid> {
        HoneyBadgerBuilder::new(netinfo)
    }

    /// Proposes a new item in the current epoch.
    pub fn propose(&mut self, proposal: &C) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        if !self.netinfo.is_validator() {
            return Ok(FaultLog::new());
        }
        let cs = match self.common_subsets.entry(self.epoch) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                entry.insert(CommonSubset::new(self.netinfo.clone(), self.epoch)?)
            }
        };
        let ser_prop = bincode::serialize(&proposal)?;
        let ciphertext = self.netinfo.public_key_set().public_key().encrypt(ser_prop);
        let fault_log = cs.input(bincode::serialize(&ciphertext).unwrap())?;
        self.has_input = true;
        self.messages.extend_with_epoch(self.epoch, cs);
        Ok(fault_log)
    }

    /// Returns `true` if input for the current epoch has already been provided.
    pub fn has_input(&self) -> bool {
        self.has_input
    }

    /// Handles a message for the given epoch.
    fn handle_message_content(
        &mut self,
        sender_id: &NodeUid,
        epoch: u64,
        content: MessageContent<NodeUid>,
    ) -> HoneyBadgerResult<FaultLog<NodeUid>> {
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
    ) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        let mut fault_log = FaultLog::new();
        {
            // Borrow the instance for `epoch`, or create it.
            let cs = match self.common_subsets.entry(epoch) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    if epoch < self.epoch {
                        // Epoch has already terminated. Message is obsolete.
                        return Ok(fault_log);
                    } else {
                        entry.insert(CommonSubset::new(self.netinfo.clone(), epoch)?)
                    }
                }
            };
            // Handle the message and put the outgoing messages into the queue.
            cs.handle_message(sender_id, message)?
                .merge_into(&mut fault_log);
            self.messages.extend_with_epoch(epoch, cs);
        }
        // If this is the current epoch, the message could cause a new output.
        if epoch == self.epoch {
            self.process_output()?.merge_into(&mut fault_log);
        }
        self.remove_terminated(epoch);
        Ok(fault_log)
    }

    /// Handles decryption shares sent by `HoneyBadger` instances.
    fn handle_decryption_share_message(
        &mut self,
        sender_id: &NodeUid,
        epoch: u64,
        proposer_id: NodeUid,
        share: DecryptionShare,
    ) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        let mut fault_log = FaultLog::new();

        if let Some(ciphertext) = self
            .ciphertexts
            .get(&self.epoch)
            .and_then(|cts| cts.get(&proposer_id))
        {
            if !self.verify_decryption_share(sender_id, &share, ciphertext) {
                let fault_kind = FaultKind::UnverifiedDecryptionShareSender;
                fault_log.append(sender_id.clone(), fault_kind);
                return Ok(fault_log);
            }
        }

        {
            // Insert the share.
            let proposer_shares = self
                .received_shares
                .entry(epoch)
                .or_insert_with(BTreeMap::new)
                .entry(proposer_id.clone())
                .or_insert_with(BTreeMap::new);
            proposer_shares.insert(sender_id.clone(), share);
        }

        if epoch == self.epoch && self.try_decrypt_proposer_contribution(proposer_id) {
            self.try_output_batch()?.merge_into(&mut fault_log);
        }

        Ok(fault_log)
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

    /// When contributions of transactions have been decrypted for all valid proposers in this epoch,
    /// moves those transactions into a batch, outputs the batch and updates the epoch.
    fn try_output_batch(&mut self) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        // Wait until contributions have been successfully decoded for all proposer nodes with correct
        // ciphertext outputs.
        if !self.all_contributions_decrypted() {
            return Ok(FaultLog::new());
        }

        // Deserialize the output.
        let mut fault_log = FaultLog::new();
        let contributions: BTreeMap<NodeUid, C> = self
            .decrypted_contributions
            .iter()
            .flat_map(|(proposer_id, ser_contrib)| {
                // If deserialization fails, the proposer of that item is faulty. Ignore it.
                if let Ok(contrib) = bincode::deserialize::<C>(&ser_contrib) {
                    Some((proposer_id.clone(), contrib))
                } else {
                    let fault_kind = FaultKind::BatchDeserializationFailed;
                    fault_log.append(proposer_id.clone(), fault_kind);
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
            batch.contributions
        );
        // Queue the output and advance the epoch.
        self.output.push_back(batch);
        self.update_epoch()?.merge_into(&mut fault_log);
        Ok(fault_log)
    }

    /// Increments the epoch number and clears any state that is local to the finished epoch.
    fn update_epoch(&mut self) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        // Clear the state of the old epoch.
        self.ciphertexts.remove(&self.epoch);
        self.decrypted_contributions.clear();
        self.received_shares.remove(&self.epoch);
        self.epoch += 1;
        self.has_input = false;
        let max_epoch = self.epoch + self.max_future_epochs;
        let mut fault_log = FaultLog::new();
        // TODO: Once stable, use `Iterator::flatten`.
        for (sender_id, content) in
            Itertools::flatten(self.incoming_queue.remove(&max_epoch).into_iter())
        {
            self.handle_message_content(&sender_id, max_epoch, content)?
                .merge_into(&mut fault_log);
        }
        // Handle any decryption shares received for the new epoch.
        self.try_decrypt_and_output_batch()?
            .merge_into(&mut fault_log);
        Ok(fault_log)
    }

    /// Tries to decrypt transaction contributions from all proposers and output those transactions in
    /// a batch.
    fn try_decrypt_and_output_batch(&mut self) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        if let Some(proposer_ids) = self
            .received_shares
            .get(&self.epoch)
            .map(|shares| shares.keys().cloned().collect::<BTreeSet<NodeUid>>())
        {
            // Try to output a batch if there is a non-empty set of proposers for which we have
            // already received decryption shares.
            if !proposer_ids.is_empty()
                && proposer_ids
                    .iter()
                    .all(|proposer_id| self.try_decrypt_proposer_contribution(proposer_id.clone()))
            {
                return self.try_output_batch();
            }
        }
        Ok(FaultLog::new())
    }

    /// Returns true if and only if contributions have been decrypted for all selected proposers in
    /// this epoch.
    fn all_contributions_decrypted(&mut self) -> bool {
        let ciphertexts = self
            .ciphertexts
            .entry(self.epoch)
            .or_insert_with(BTreeMap::new);
        let all_ciphertext_proposers: BTreeSet<_> = ciphertexts.keys().collect();
        let all_decrypted_contribution_proposers: BTreeSet<_> =
            self.decrypted_contributions.keys().collect();
        all_ciphertext_proposers == all_decrypted_contribution_proposers
    }

    /// Tries to decrypt the contribution from a given proposer. Outputs `true` if and only if
    /// decryption finished without errors.
    fn try_decrypt_proposer_contribution(&mut self, proposer_id: NodeUid) -> bool {
        let shares = &self.received_shares[&self.epoch][&proposer_id];
        if shares.len() <= self.netinfo.num_faulty() {
            return false;
        }

        if let Some(ciphertext) = self
            .ciphertexts
            .get(&self.epoch)
            .and_then(|cts| cts.get(&proposer_id))
        {
            let ids_u64: BTreeMap<&NodeUid, u64> = shares
                .keys()
                .map(|id| (id, *self.netinfo.node_index(id).unwrap() as u64))
                .collect();
            let indexed_shares: BTreeMap<&u64, _> = shares
                .into_iter()
                .map(|(id, share)| (&ids_u64[id], share))
                .collect();
            if let Ok(decrypted_contribution) = self
                .netinfo
                .public_key_set()
                .decrypt(indexed_shares, ciphertext)
            {
                self.decrypted_contributions
                    .insert(proposer_id, decrypted_contribution);
                return true;
            }
        }
        false
    }

    fn send_decryption_shares(
        &mut self,
        cs_output: BTreeMap<NodeUid, Vec<u8>>,
    ) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        let mut fault_log = FaultLog::new();
        for (proposer_id, v) in cs_output {
            let mut ciphertext: Ciphertext;
            if let Ok(ct) = bincode::deserialize(&v) {
                ciphertext = ct;
            } else {
                warn!("Invalid ciphertext from proposer {:?} ignored", proposer_id);
                let fault_kind = FaultKind::InvalidCiphertext;
                fault_log.append(proposer_id.clone(), fault_kind);
                continue;
            }
            let (incorrect_senders, faults) =
                self.verify_pending_decryption_shares(&proposer_id, &ciphertext);
            self.remove_incorrect_decryption_shares(&proposer_id, incorrect_senders);
            fault_log.extend(faults);

            if !self.send_decryption_share(&proposer_id, &ciphertext)? {
                warn!("Share decryption failed for proposer {:?}", proposer_id);
                let fault_kind = FaultKind::ShareDecryptionFailed;
                fault_log.append(proposer_id.clone(), fault_kind);
                continue;
            }
            let ciphertexts = self
                .ciphertexts
                .entry(self.epoch)
                .or_insert_with(BTreeMap::new);
            ciphertexts.insert(proposer_id, ciphertext);
        }
        Ok(fault_log)
    }

    /// Verifies the ciphertext and sends decryption shares. Returns whether it is valid.
    fn send_decryption_share(
        &mut self,
        proposer_id: &NodeUid,
        ciphertext: &Ciphertext,
    ) -> HoneyBadgerResult<BoolWithFaultLog<NodeUid>> {
        if !self.netinfo.is_validator() {
            return Ok(ciphertext.verify().into());
        }
        let share = match self.netinfo.secret_key().decrypt_share(&ciphertext) {
            None => return Ok(BoolWithFaultLog::False),
            Some(share) => share,
        };
        // Send the share to remote nodes.
        let content = MessageContent::DecryptionShare {
            proposer_id: proposer_id.clone(),
            share: share.clone(),
        };
        let message = Target::All.message(content.with_epoch(self.epoch));
        self.messages.0.push_back(message);
        let our_id = self.netinfo.our_uid().clone();
        let epoch = self.epoch;
        // Receive the share locally.
        self.handle_decryption_share_message(&our_id, epoch, proposer_id.clone(), share)
            .map(|fault_log| fault_log.into())
    }

    /// Verifies the shares of the current epoch that are pending verification. Returned are the
    /// senders with incorrect pending shares.
    fn verify_pending_decryption_shares(
        &self,
        proposer_id: &NodeUid,
        ciphertext: &Ciphertext,
    ) -> (BTreeSet<NodeUid>, FaultLog<NodeUid>) {
        let mut incorrect_senders = BTreeSet::new();
        let mut fault_log = FaultLog::new();
        if let Some(sender_shares) = self
            .received_shares
            .get(&self.epoch)
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
    ) {
        if let Some(sender_shares) = self
            .received_shares
            .get_mut(&self.epoch)
            .and_then(|e| e.get_mut(proposer_id))
        {
            for sender_id in incorrect_senders {
                sender_shares.remove(&sender_id);
            }
        }
    }

    /// Checks whether the current epoch has output, and if it does, sends out our decryption shares.
    fn process_output(&mut self) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        let mut fault_log = FaultLog::new();
        if let Some(cs_output) = self.take_current_output() {
            self.send_decryption_shares(cs_output)?
                .merge_into(&mut fault_log);
            // TODO: May also check that there is no further output from Common Subset.
        }
        Ok(fault_log)
    }

    /// Returns the output of the current epoch's `CommonSubset` instance, if any.
    fn take_current_output(&mut self) -> Option<BTreeMap<NodeUid, Vec<u8>>> {
        self.common_subsets
            .get_mut(&self.epoch)
            .and_then(CommonSubset::next_output)
    }

    /// Removes all `CommonSubset` instances from _past_ epochs that have terminated.
    fn remove_terminated(&mut self, from_epoch: u64) {
        for epoch in from_epoch..self.epoch {
            if self
                .common_subsets
                .get(&epoch)
                .map_or(false, CommonSubset::terminated)
            {
                debug!(
                    "{:?} Epoch {} has terminated.",
                    self.netinfo.our_uid(),
                    epoch
                );
                self.common_subsets.remove(&epoch);
            }
        }
    }
}

/// A batch of contributions the algorithm has output.
#[derive(Clone)]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum MessageContent<NodeUid> {
    /// A message belonging to the common subset algorithm in the given epoch.
    CommonSubset(common_subset::Message<NodeUid>),
    /// A decrypted share of the output of `proposer_id`.
    DecryptionShare {
        proposer_id: NodeUid,
        share: DecryptionShare,
    },
}

impl<NodeUid> MessageContent<NodeUid> {
    pub fn with_epoch(self, epoch: u64) -> Message<NodeUid> {
        Message {
            epoch,
            content: self,
        }
    }
}

/// A message sent to or received from another node's Honey Badger instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message<NodeUid> {
    epoch: u64,
    content: MessageContent<NodeUid>,
}

impl<NodeUid> Message<NodeUid> {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// The queue of outgoing messages in a `HoneyBadger` instance.
#[derive(Deref, DerefMut)]
struct MessageQueue<NodeUid>(VecDeque<TargetedMessage<Message<NodeUid>, NodeUid>>);

impl<NodeUid: Clone + Debug + Ord> MessageQueue<NodeUid> {
    /// Appends to the queue the messages from `cs`, wrapped with `epoch`.
    fn extend_with_epoch(&mut self, epoch: u64, cs: &mut CommonSubset<NodeUid>) {
        let convert = |msg: TargetedMessage<common_subset::Message<NodeUid>, NodeUid>| {
            msg.map(|cs_msg| MessageContent::CommonSubset(cs_msg).with_epoch(epoch))
        };
        self.extend(cs.message_iter().map(convert));
    }
}

// The return type for `HoneyBadger` methods that return a boolean and a
// fault log.
enum BoolWithFaultLog<NodeUid: Clone> {
    True(FaultLog<NodeUid>),
    False,
}

impl<NodeUid: Clone> Into<BoolWithFaultLog<NodeUid>> for bool {
    fn into(self) -> BoolWithFaultLog<NodeUid> {
        if self {
            BoolWithFaultLog::True(FaultLog::new())
        } else {
            BoolWithFaultLog::False
        }
    }
}

impl<NodeUid: Clone> Into<BoolWithFaultLog<NodeUid>> for FaultLog<NodeUid> {
    fn into(self) -> BoolWithFaultLog<NodeUid> {
        BoolWithFaultLog::True(self)
    }
}

impl<NodeUid: Clone> Not for BoolWithFaultLog<NodeUid> {
    type Output = bool;

    fn not(self) -> Self::Output {
        match self {
            BoolWithFaultLog::False => true,
            _ => false,
        }
    }
}
