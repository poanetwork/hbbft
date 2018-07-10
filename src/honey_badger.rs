use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Not;
use std::rc::Rc;
use std::{cmp, iter, mem};

use bincode;
use itertools::Itertools;
use rand;
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
pub struct HoneyBadgerBuilder<Tx, NodeUid> {
    /// Shared network data.
    netinfo: Rc<NetworkInfo<NodeUid>>,
    /// The target number of transactions to be included in each batch.
    // TODO: Do experiments and pick a suitable default.
    batch_size: usize,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    _phantom: PhantomData<Tx>,
}

impl<Tx, NodeUid> HoneyBadgerBuilder<Tx, NodeUid> where NodeUid: Ord + Clone + Debug
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn new(netinfo: Rc<NetworkInfo<NodeUid>>) -> Self {
        HoneyBadgerBuilder { netinfo,
                             batch_size: 100,
                             max_future_epochs: 3,
                             _phantom: PhantomData, }
    }

    /// Sets the target number of transactions per batch.
    pub fn batch_size(&mut self, batch_size: usize) -> &mut Self {
        self.batch_size = batch_size;
        self
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: usize) -> &mut Self {
        self.max_future_epochs = max_future_epochs;
        self
    }

    /// Creates a new Honey Badger instance with an empty buffer.
    pub fn build(&self) -> HoneyBadgerResult<(HoneyBadger<Tx, NodeUid>, FaultLog<NodeUid>)>
        where Tx: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq {
        self.build_with_transactions(None)
    }

    /// Returns a new Honey Badger instance that starts with the given transactions in its buffer.
    pub fn build_with_transactions<TI>(
        &self,
        txs: TI)
        -> HoneyBadgerResult<(HoneyBadger<Tx, NodeUid>, FaultLog<NodeUid>)>
        where TI: IntoIterator<Item = Tx>,
              Tx: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq
    {
        let mut honey_badger = HoneyBadger { netinfo: self.netinfo.clone(),
                                             buffer: Vec::new(),
                                             epoch: 0,
                                             common_subsets: BTreeMap::new(),
                                             batch_size: self.batch_size,
                                             max_future_epochs: self.max_future_epochs as u64,
                                             messages: MessageQueue(VecDeque::new()),
                                             output: VecDeque::new(),
                                             incoming_queue: BTreeMap::new(),
                                             received_shares: BTreeMap::new(),
                                             decrypted_selections: BTreeMap::new(),
                                             ciphertexts: BTreeMap::new(), };
        honey_badger.buffer.extend(txs);
        let fault_log = honey_badger.propose()?;
        Ok((honey_badger, fault_log))
    }
}

/// An instance of the Honey Badger Byzantine fault tolerant consensus algorithm.
pub struct HoneyBadger<Tx, NodeUid> {
    /// Shared network data.
    netinfo: Rc<NetworkInfo<NodeUid>>,
    /// The buffer of transactions that have not yet been included in any output batch.
    buffer: Vec<Tx>,
    /// The earliest epoch from which we have not yet received output.
    epoch: u64,
    /// The Asynchronous Common Subset instance that decides which nodes' transactions to include,
    /// indexed by epoch.
    common_subsets: BTreeMap<u64, CommonSubset<NodeUid>>,
    /// The target number of transactions to be included in each batch.
    // TODO: Do experiments and recommend a batch size. It should be proportional to
    // `num_nodes * num_nodes * log(num_nodes)`.
    batch_size: usize,
    /// The maximum number of `CommonSubset` instances that we run simultaneously.
    max_future_epochs: u64,
    /// The messages that need to be sent to other nodes.
    messages: MessageQueue<NodeUid>,
    /// The outputs from completed epochs.
    output: VecDeque<Batch<Tx, NodeUid>>,
    /// Messages for future epochs that couldn't be handled yet.
    incoming_queue: BTreeMap<u64, Vec<(NodeUid, MessageContent<NodeUid>)>>,
    /// Received decryption shares for an epoch. Each decryption share has a sender and a
    /// proposer. The outer `BTreeMap` has epochs as its key. The next `BTreeMap` has proposers as
    /// its key. The inner `BTreeMap` has the sender as its key.
    received_shares: BTreeMap<u64, BTreeMap<NodeUid, BTreeMap<NodeUid, DecryptionShare>>>,
    /// Decoded accepted proposals.
    decrypted_selections: BTreeMap<NodeUid, Vec<u8>>,
    /// Ciphertexts output by Common Subset in an epoch.
    ciphertexts: BTreeMap<u64, BTreeMap<NodeUid, Ciphertext>>,
}

impl<Tx, NodeUid> DistAlgorithm for HoneyBadger<Tx, NodeUid>
    where Tx: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq,
          NodeUid: Ord + Clone + Debug
{
    type NodeUid = NodeUid;
    type Input = Tx;
    type Output = Batch<Tx, NodeUid>;
    type Message = Message<NodeUid>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        self.add_transactions(iter::once(input));
        Ok(FaultLog::new())
    }

    fn handle_message(&mut self,
                      sender_id: &NodeUid,
                      message: Self::Message)
                      -> HoneyBadgerResult<FaultLog<NodeUid>>
    {
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
            self.incoming_queue.entry(epoch)
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

impl<Tx, NodeUid> HoneyBadger<Tx, NodeUid>
    where Tx: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq,
          NodeUid: Ord + Clone + Debug
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn builder(netinfo: Rc<NetworkInfo<NodeUid>>) -> HoneyBadgerBuilder<Tx, NodeUid> {
        HoneyBadgerBuilder::new(netinfo)
    }

    /// Adds transactions into the buffer.
    pub fn add_transactions<I: IntoIterator<Item = Tx>>(&mut self, txs: I) {
        self.buffer.extend(txs);
    }

    /// Empties and returns the transaction buffer.
    pub fn drain_buffer(&mut self) -> Vec<Tx> {
        mem::replace(&mut self.buffer, Vec::new())
    }

    /// Proposes a new batch in the current epoch.
    fn propose(&mut self) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        if !self.netinfo.is_validator() {
            return Ok(FaultLog::new());
        }
        let proposal = self.choose_transactions()?;
        let cs = match self.common_subsets.entry(self.epoch) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                entry.insert(CommonSubset::new(self.netinfo.clone(), self.epoch)?)
            },
        };
        let ciphertext = self.netinfo.public_key_set().public_key().encrypt(proposal);
        let fault_log = cs.input(bincode::serialize(&ciphertext).unwrap())?;
        self.messages.extend_with_epoch(self.epoch, cs);
        Ok(fault_log)
    }

    /// Returns a random choice of `batch_size / all_uids.len()` buffered transactions, and
    /// serializes them.
    fn choose_transactions(&self) -> HoneyBadgerResult<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let amount = cmp::max(1, self.batch_size / self.netinfo.all_uids().len());
        let batch_size = cmp::min(self.batch_size, self.buffer.len());
        let sample = match rand::seq::sample_iter(&mut rng, &self.buffer[..batch_size], amount) {
            Ok(choice) => choice,
            Err(choice) => choice, // Fewer than `amount` were available, which is fine.
        };
        debug!("{:?} Proposing in epoch {}: {:?}",
               self.netinfo.our_uid(),
               self.epoch,
               sample);
        Ok(bincode::serialize(&sample)?)
    }

    /// Handles a message for the given epoch.
    fn handle_message_content(&mut self,
                              sender_id: &NodeUid,
                              epoch: u64,
                              content: MessageContent<NodeUid>)
                              -> HoneyBadgerResult<FaultLog<NodeUid>>
    {
        match content {
            MessageContent::CommonSubset(cs_msg) => {
                self.handle_common_subset_message(sender_id, epoch, cs_msg)
            },
            MessageContent::DecryptionShare { proposer_id, share } => {
                self.handle_decryption_share_message(sender_id, epoch, proposer_id, share)
            },
        }
    }

    /// Handles a message for the common subset sub-algorithm.
    fn handle_common_subset_message(&mut self,
                                    sender_id: &NodeUid,
                                    epoch: u64,
                                    message: common_subset::Message<NodeUid>)
                                    -> HoneyBadgerResult<FaultLog<NodeUid>>
    {
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
                },
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
    fn handle_decryption_share_message(&mut self,
                                       sender_id: &NodeUid,
                                       epoch: u64,
                                       proposer_id: NodeUid,
                                       share: DecryptionShare)
                                       -> HoneyBadgerResult<FaultLog<NodeUid>>
    {
        let mut fault_log = FaultLog::new();

        if let Some(ciphertext) = self.ciphertexts
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
            let proposer_shares = self.received_shares
                                      .entry(epoch)
                                      .or_insert_with(BTreeMap::new)
                                      .entry(proposer_id.clone())
                                      .or_insert_with(BTreeMap::new);
            proposer_shares.insert(sender_id.clone(), share);
        }

        if epoch == self.epoch && self.try_decrypt_proposer_selection(proposer_id) {
            if let BoolWithFaultLog::True(faults) = self.try_output_batch()? {
                fault_log.extend(faults);
            }
        }

        Ok(fault_log)
    }

    /// Verifies a given decryption share using the sender's public key and the proposer's
    /// ciphertext. Returns `true` if verification has been successful and `false` if verification
    /// has failed.
    fn verify_decryption_share(&self,
                               sender_id: &NodeUid,
                               share: &DecryptionShare,
                               ciphertext: &Ciphertext)
                               -> bool
    {
        if let Some(pk) = self.netinfo.public_key_share(sender_id) {
            pk.verify_decryption_share(&share, ciphertext)
        } else {
            false
        }
    }

    /// When selections of transactions have been decrypted for all valid proposers in this epoch,
    /// moves those transactions into a batch, outputs the batch and updates the epoch.
    fn try_output_batch(&mut self) -> HoneyBadgerResult<BoolWithFaultLog<NodeUid>> {
        // Wait until selections have been successfully decoded for all proposer nodes with correct
        // ciphertext outputs.
        if !self.all_selections_decrypted() {
            return Ok(BoolWithFaultLog::False);
        }

        // Deserialize the output.
        let mut fault_log = FaultLog::new();
        let transactions: BTreeMap<NodeUid, Vec<Tx>> =
            self.decrypted_selections.iter()
                .flat_map(|(proposer_id, ser_batch)| {
                              // If deserialization fails, the proposer of that batch is
                              // faulty. Log the faulty proposer and ignore the batch.
                              if let Ok(proposed) = bincode::deserialize::<Vec<Tx>>(&ser_batch) {
                                  Some((proposer_id.clone(), proposed))
                              } else {
                                  let fault_kind = FaultKind::BatchDeserializationFailed;
                                  fault_log.append(proposer_id.clone(), fault_kind);
                                  None
                              }
                          })
                .collect();
        let batch = Batch { epoch: self.epoch,
                            transactions, };
        {
            let tx_set: HashSet<&Tx> = batch.iter().collect();
            // Remove the output transactions from our buffer.
            self.buffer.retain(|tx| !tx_set.contains(&tx));
        }
        debug!("{:?} Epoch {} output {:?}",
               self.netinfo.our_uid(),
               self.epoch,
               batch.transactions);
        // Queue the output and advance the epoch.
        self.output.push_back(batch);
        self.update_epoch()?.merge_into(&mut fault_log);
        Ok(BoolWithFaultLog::True(fault_log))
    }

    /// Increments the epoch number and clears any state that is local to the finished epoch.
    fn update_epoch(&mut self) -> HoneyBadgerResult<FaultLog<NodeUid>> {
        // Clear the state of the old epoch.
        self.ciphertexts.remove(&self.epoch);
        self.decrypted_selections.clear();
        self.received_shares.remove(&self.epoch);
        self.epoch += 1;
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
        if let BoolWithFaultLog::True(faults) = self.try_decrypt_and_output_batch()? {
            fault_log.extend(faults);
        } else {
            // Continue with this epoch if a batch is not output by
            // `try_decrypt_and_output_batch`.
            self.propose()?.merge_into(&mut fault_log);
        }
        Ok(fault_log)
    }

    /// Tries to decrypt transaction selections from all proposers and output those transactions in
    /// a batch.
    fn try_decrypt_and_output_batch(&mut self) -> HoneyBadgerResult<BoolWithFaultLog<NodeUid>> {
        if let Some(proposer_ids) =
            self.received_shares.get(&self.epoch).map(|shares| {
                                                          shares.keys()
                                                                .cloned()
                                                                .collect::<BTreeSet<NodeUid>>()
                                                      }) {
            // Try to output a batch if there is a non-empty set of proposers for which we have already received
            // decryption shares.
            if !proposer_ids.is_empty()
                && proposer_ids
                    .iter()
                    .all(|proposer_id| self.try_decrypt_proposer_selection(proposer_id.clone()))
            {
                self.try_output_batch()
            } else {
                Ok(BoolWithFaultLog::False)
            }
        } else {
            Ok(BoolWithFaultLog::False)
        }
    }

    /// Returns true if and only if transaction selections have been decrypted for all proposers in
    /// this epoch.
    fn all_selections_decrypted(&mut self) -> bool {
        let ciphertexts = self.ciphertexts
                              .entry(self.epoch)
                              .or_insert_with(BTreeMap::new);
        let all_ciphertext_proposers: BTreeSet<_> = ciphertexts.keys().collect();
        let all_decrypted_selection_proposers: BTreeSet<_> =
            self.decrypted_selections.keys().collect();
        all_ciphertext_proposers == all_decrypted_selection_proposers
    }

    /// Tries to decrypt the selection of transactions from a given proposer. Outputs `true` if and
    /// only if decryption finished without errors.
    fn try_decrypt_proposer_selection(&mut self, proposer_id: NodeUid) -> bool {
        let shares = &self.received_shares[&self.epoch][&proposer_id];
        if shares.len() <= self.netinfo.num_faulty() {
            return false;
        }

        if let Some(ciphertext) = self.ciphertexts
                                      .get(&self.epoch)
                                      .and_then(|cts| cts.get(&proposer_id))
        {
            let ids_u64: BTreeMap<&NodeUid, u64> =
                shares.keys()
                      .map(|id| (id, *self.netinfo.node_index(id).unwrap() as u64))
                      .collect();
            let indexed_shares: BTreeMap<&u64, _> = shares.into_iter()
                                                          .map(|(id, share)| (&ids_u64[id], share))
                                                          .collect();
            if let Ok(decrypted_selection) = self.netinfo
                                                 .public_key_set()
                                                 .decrypt(indexed_shares, ciphertext)
            {
                self.decrypted_selections.insert(proposer_id, decrypted_selection);
                return true;
            }
        }
        false
    }

    fn send_decryption_shares(&mut self,
                              cs_output: BTreeMap<NodeUid, Vec<u8>>)
                              -> HoneyBadgerResult<FaultLog<NodeUid>>
    {
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
            let ciphertexts = self.ciphertexts
                                  .entry(self.epoch)
                                  .or_insert_with(BTreeMap::new);
            ciphertexts.insert(proposer_id, ciphertext);
        }
        Ok(fault_log)
    }

    /// Verifies the ciphertext and sends decryption shares. Returns whether it is valid.
    fn send_decryption_share(&mut self,
                             proposer_id: &NodeUid,
                             ciphertext: &Ciphertext)
                             -> HoneyBadgerResult<BoolWithFaultLog<NodeUid>>
    {
        if !self.netinfo.is_validator() {
            return Ok(ciphertext.verify().into());
        }
        let share = match self.netinfo.secret_key().decrypt_share(&ciphertext) {
            None => return Ok(BoolWithFaultLog::False),
            Some(share) => share,
        };
        // Send the share to remote nodes.
        let content = MessageContent::DecryptionShare { proposer_id: proposer_id.clone(),
                                                        share: share.clone(), };
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
    fn verify_pending_decryption_shares(&self,
                                        proposer_id: &NodeUid,
                                        ciphertext: &Ciphertext)
                                        -> (BTreeSet<NodeUid>, FaultLog<NodeUid>)
    {
        let mut incorrect_senders = BTreeSet::new();
        let mut fault_log = FaultLog::new();
        if let Some(sender_shares) = self.received_shares
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

    fn remove_incorrect_decryption_shares(&mut self,
                                          proposer_id: &NodeUid,
                                          incorrect_senders: BTreeSet<NodeUid>)
    {
        if let Some(sender_shares) = self.received_shares
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
        self.common_subsets.get_mut(&self.epoch)
            .and_then(CommonSubset::next_output)
    }

    /// Removes all `CommonSubset` instances from _past_ epochs that have terminated.
    fn remove_terminated(&mut self, from_epoch: u64) {
        for epoch in from_epoch..self.epoch {
            if self.common_subsets
                   .get(&epoch)
                   .map_or(false, CommonSubset::terminated)
            {
                debug!("{:?} Epoch {} has terminated.",
                       self.netinfo.our_uid(),
                       epoch);
                self.common_subsets.remove(&epoch);
            }
        }
    }
}

/// A batch of transactions the algorithm has output.
///
/// TODO: Consider adding a `faulty_nodes` field to describe and report failures detected by `HoneyBadger`.
#[derive(Clone)]
pub struct Batch<Tx, NodeUid> {
    pub epoch: u64,
    pub transactions: BTreeMap<NodeUid, Vec<Tx>>,
}

impl<Tx, NodeUid: Ord> Batch<Tx, NodeUid> {
    /// Returns an iterator over references to all transactions included in the batch.
    pub fn iter(&self) -> impl Iterator<Item = &Tx> {
        self.transactions.values().flat_map(|vec| vec)
    }

    /// Returns an iterator over all transactions included in the batch. Consumes the batch.
    pub fn into_tx_iter(self) -> impl Iterator<Item = Tx> {
        self.transactions.into_iter().flat_map(|(_, vec)| vec)
    }

    /// Returns the number of transactions in the batch (without detecting duplicates).
    pub fn len(&self) -> usize {
        self.transactions.values().map(Vec::len).sum()
    }

    /// Returns `true` if the batch contains no transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.values().all(Vec::is_empty)
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
        Message { epoch,
                  content: self, }
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
