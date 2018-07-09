use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::marker::PhantomData;
use std::rc::Rc;
use std::{cmp, iter, mem};

use bincode;
use itertools::Itertools;
use rand;
use serde::{Deserialize, Serialize};

use common_subset::{self, CommonSubset};
use crypto::{Ciphertext, DecryptionShare};
use messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};
use traits::{Contribution, NodeUid};

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
    netinfo: Rc<NetworkInfo<NodeUid>>,
    /// The target number of transactions to be included in each batch.
    // TODO: Do experiments and pick a suitable default.
    batch_size: usize,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    _phantom: PhantomData<C>,
}

impl<C, N> HoneyBadgerBuilder<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeUid,
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn new(netinfo: Rc<NetworkInfo<N>>) -> Self {
        HoneyBadgerBuilder {
            netinfo,
            batch_size: 100,
            max_future_epochs: 3,
            _phantom: PhantomData,
        }
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
    pub fn build(&self) -> HoneyBadgerResult<HoneyBadger<C, N>>
    where
        C: Contribution + Serialize + for<'r> Deserialize<'r>,
    {
        self.build_with_transactions(None)
    }

    /// Returns a new Honey Badger instance that starts with the given transactions in its buffer.
    pub fn build_with_transactions<TI>(
        &self,
        txs: TI,
    ) -> HoneyBadgerResult<HoneyBadger<C, N>>
    where
        TI: IntoIterator<Item = C>,
        C: Contribution + Serialize + for<'r> Deserialize<'r>,
    {
        let mut honey_badger = HoneyBadger {
            netinfo: self.netinfo.clone(),
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
            ciphertexts: BTreeMap::new(),
        };
        honey_badger.buffer.extend(txs);
        honey_badger.propose()?;
        Ok(honey_badger)
    }
}

/// An instance of the Honey Badger Byzantine fault tolerant consensus algorithm.
pub struct HoneyBadger<C, N> {
    /// Shared network data.
    netinfo: Rc<NetworkInfo<N>>,
    /// The buffer of transactions that have not yet been included in any output batch.
    buffer: Vec<C>,
    /// The earliest epoch from which we have not yet received output.
    epoch: u64,
    /// The Asynchronous Common Subset instance that decides which nodes' transactions to include,
    /// indexed by epoch.
    common_subsets: BTreeMap<u64, CommonSubset<N>>,
    /// The target number of transactions to be included in each batch.
    // TODO: Do experiments and recommend a batch size. It should be proportional to
    // `num_nodes * num_nodes * log(num_nodes)`.
    batch_size: usize,
    /// The maximum number of `CommonSubset` instances that we run simultaneously.
    max_future_epochs: u64,
    /// The messages that need to be sent to other nodes.
    messages: MessageQueue<N>,
    /// The outputs from completed epochs.
    output: VecDeque<Batch<C, N>>,
    /// Messages for future epochs that couldn't be handled yet.
    incoming_queue: BTreeMap<u64, Vec<(N, MessageContent<N>)>>,
    /// Received decryption shares for an epoch. Each decryption share has a sender and a
    /// proposer. The outer `BTreeMap` has epochs as its key. The next `BTreeMap` has proposers as
    /// its key. The inner `BTreeMap` has the sender as its key.
    received_shares: BTreeMap<u64, BTreeMap<N, BTreeMap<N, DecryptionShare>>>,
    /// Decoded accepted proposals.
    decrypted_selections: BTreeMap<N, Vec<u8>>,
    /// Ciphertexts output by Common Subset in an epoch.
    ciphertexts: BTreeMap<u64, BTreeMap<N, Ciphertext>>,
}

impl<C, N> DistAlgorithm for HoneyBadger<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeUid,
{
    type NodeUid = N;
    type Input = C;
    type Output = Batch<C, N>;
    type Message = Message<N>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> HoneyBadgerResult<()> {
        self.add_transactions(iter::once(input));
        Ok(())
    }

    fn handle_message(
        &mut self,
        sender_id: &N,
        message: Self::Message,
    ) -> HoneyBadgerResult<()> {
        if !self.netinfo.all_uids().contains(sender_id) {
            return Err(ErrorKind::UnknownSender.into());
        }
        let Message { epoch, content } = message;
        if epoch < self.epoch {
            // Ignore all messages from past epochs.
            return Ok(());
        }
        if epoch > self.epoch + self.max_future_epochs {
            // Postpone handling this message.
            self.incoming_queue
                .entry(epoch)
                .or_insert_with(Vec::new)
                .push((sender_id.clone(), content));
            return Ok(());
        }
        self.handle_message_content(sender_id, epoch, content)
    }

    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, N>> {
        self.messages.pop_front()
    }

    fn next_output(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
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
    N: NodeUid,
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn builder(netinfo: Rc<NetworkInfo<N>>) -> HoneyBadgerBuilder<C, N> {
        HoneyBadgerBuilder::new(netinfo)
    }

    /// Adds transactions into the buffer.
    pub fn add_transactions<I: IntoIterator<Item = C>>(&mut self, txs: I) {
        self.buffer.extend(txs);
    }

    /// Empties and returns the transaction buffer.
    pub fn drain_buffer(&mut self) -> Vec<C> {
        mem::replace(&mut self.buffer, Vec::new())
    }

    /// Proposes a new batch in the current epoch.
    fn propose(&mut self) -> HoneyBadgerResult<()> {
        if !self.netinfo.is_validator() {
            return Ok(());
        }
        let proposal = self.choose_transactions()?;
        let cs = match self.common_subsets.entry(self.epoch) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                entry.insert(CommonSubset::new(self.netinfo.clone(), self.epoch)?)
            }
        };
        let ciphertext = self.netinfo.public_key_set().public_key().encrypt(proposal);
        cs.input(bincode::serialize(&ciphertext).unwrap())?;
        self.messages.extend_with_epoch(self.epoch, cs);
        Ok(())
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
        debug!(
            "{:?} Proposing in epoch {}: {:?}",
            self.netinfo.our_uid(),
            self.epoch,
            sample
        );
        Ok(bincode::serialize(&sample)?)
    }

    /// Handles a message for the given epoch.
    fn handle_message_content(
        &mut self,
        sender_id: &N,
        epoch: u64,
        content: MessageContent<N>,
    ) -> HoneyBadgerResult<()> {
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
    ) -> HoneyBadgerResult<()> {
        {
            // Borrow the instance for `epoch`, or create it.
            let cs = match self.common_subsets.entry(epoch) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    if epoch < self.epoch {
                        return Ok(()); // Epoch has already terminated. Message is obsolete.
                    } else {
                        entry.insert(CommonSubset::new(self.netinfo.clone(), epoch)?)
                    }
                }
            };
            // Handle the message and put the outgoing messages into the queue.
            cs.handle_message(sender_id, message)?;
            self.messages.extend_with_epoch(epoch, cs);
        }
        // If this is the current epoch, the message could cause a new output.
        if epoch == self.epoch {
            self.process_output()?;
        }
        self.remove_terminated(epoch);
        Ok(())
    }

    /// Handles decryption shares sent by `HoneyBadger` instances.
    fn handle_decryption_share_message(
        &mut self,
        sender_id: &N,
        epoch: u64,
        proposer_id: N,
        share: DecryptionShare,
    ) -> HoneyBadgerResult<()> {
        if let Some(ciphertext) = self
            .ciphertexts
            .get(&self.epoch)
            .and_then(|cts| cts.get(&proposer_id))
        {
            if !self.verify_decryption_share(sender_id, &share, ciphertext) {
                // TODO: Log the incorrect sender.
                return Ok(());
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

        if epoch == self.epoch && self.try_decrypt_proposer_selection(proposer_id) {
            self.try_output_batch()?;
        }

        Ok(())
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

    /// When selections of transactions have been decrypted for all valid proposers in this epoch,
    /// moves those transactions into a batch, outputs the batch and updates the epoch.
    fn try_output_batch(&mut self) -> HoneyBadgerResult<bool> {
        // Wait until selections have been successfully decoded for all proposer nodes with correct
        // ciphertext outputs.
        if !self.all_selections_decrypted() {
            return Ok(false);
        }

        // Deserialize the output.
        let transactions: BTreeMap<N, Vec<C>> = self
            .decrypted_selections
            .iter()
            .flat_map(|(proposer_id, ser_batch)| {
                // If deserialization fails, the proposer of that batch is faulty. Ignore it.
                bincode::deserialize::<Vec<C>>(&ser_batch)
                    .ok()
                    .map(|proposed| (proposer_id.clone(), proposed))
            })
            .collect();
        let batch = Batch {
            epoch: self.epoch,
            transactions,
        };
        {
            let tx_set: HashSet<&C> = batch.iter().collect();
            // Remove the output transactions from our buffer.
            self.buffer.retain(|tx| !tx_set.contains(&tx));
        }
        debug!(
            "{:?} Epoch {} output {:?}",
            self.netinfo.our_uid(),
            self.epoch,
            batch.transactions
        );
        // Queue the output and advance the epoch.
        self.output.push_back(batch);
        self.update_epoch()?;
        Ok(true)
    }

    /// Increments the epoch number and clears any state that is local to the finished epoch.
    fn update_epoch(&mut self) -> HoneyBadgerResult<()> {
        // Clear the state of the old epoch.
        self.ciphertexts.remove(&self.epoch);
        self.decrypted_selections.clear();
        self.received_shares.remove(&self.epoch);
        self.epoch += 1;
        let max_epoch = self.epoch + self.max_future_epochs;
        // TODO: Once stable, use `Iterator::flatten`.
        for (sender_id, content) in
            Itertools::flatten(self.incoming_queue.remove(&max_epoch).into_iter())
        {
            self.handle_message_content(&sender_id, max_epoch, content)?;
        }
        // Handle any decryption shares received for the new epoch.
        if !self.try_decrypt_and_output_batch()? {
            // Continue with this epoch if a batch is not output by `try_decrypt_and_output_batch`.
            self.propose()?;
        }
        Ok(())
    }

    /// Tries to decrypt transaction selections from all proposers and output those transactions in
    /// a batch.
    fn try_decrypt_and_output_batch(&mut self) -> HoneyBadgerResult<bool> {
        if let Some(proposer_ids) = self
            .received_shares
            .get(&self.epoch)
            .map(|shares| shares.keys().cloned().collect::<BTreeSet<N>>())
        {
            // Try to output a batch if there is a non-empty set of proposers for which we have already received
            // decryption shares.
            if !proposer_ids.is_empty()
                && proposer_ids
                    .iter()
                    .all(|proposer_id| self.try_decrypt_proposer_selection(proposer_id.clone()))
            {
                self.try_output_batch()
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Returns true if and only if transaction selections have been decrypted for all proposers in
    /// this epoch.
    fn all_selections_decrypted(&mut self) -> bool {
        let ciphertexts = self
            .ciphertexts
            .entry(self.epoch)
            .or_insert_with(BTreeMap::new);
        let all_ciphertext_proposers: BTreeSet<_> = ciphertexts.keys().collect();
        let all_decrypted_selection_proposers: BTreeSet<_> =
            self.decrypted_selections.keys().collect();
        all_ciphertext_proposers == all_decrypted_selection_proposers
    }

    /// Tries to decrypt the selection from a given proposer. Outputs `true` if and only if
    /// decryption finished without errors.
    fn try_decrypt_proposer_selection(&mut self, proposer_id: N) -> bool {
        let shares = &self.received_shares[&self.epoch][&proposer_id];
        if shares.len() <= self.netinfo.num_faulty() {
            return false;
        }

        if let Some(ciphertext) = self
            .ciphertexts
            .get(&self.epoch)
            .and_then(|cts| cts.get(&proposer_id))
        {
            let ids_u64: BTreeMap<&N, u64> = shares
                .keys()
                .map(|id| (id, *self.netinfo.node_index(id).unwrap() as u64))
                .collect();
            let indexed_shares: BTreeMap<&u64, _> = shares
                .into_iter()
                .map(|(id, share)| (&ids_u64[id], share))
                .collect();
            if let Ok(decrypted_selection) = self
                .netinfo
                .public_key_set()
                .decrypt(indexed_shares, ciphertext)
            {
                self.decrypted_selections
                    .insert(proposer_id, decrypted_selection);
                return true;
            }
        }
        false
    }

    fn send_decryption_shares(
        &mut self,
        cs_output: BTreeMap<N, Vec<u8>>,
    ) -> Result<(), Error> {
        for (proposer_id, v) in cs_output {
            let mut ciphertext: Ciphertext;
            if let Ok(ct) = bincode::deserialize(&v) {
                ciphertext = ct;
            } else {
                warn!("Invalid ciphertext from proposer {:?} ignored", proposer_id);
                // TODO: Log the incorrect node `j`.
                continue;
            }
            let incorrect_senders =
                self.verify_pending_decryption_shares(&proposer_id, &ciphertext);
            self.remove_incorrect_decryption_shares(&proposer_id, incorrect_senders);

            if !self.send_decryption_share(&proposer_id, &ciphertext)? {
                warn!("Share decryption failed for proposer {:?}", proposer_id);
                // TODO: Log the decryption failure.
                continue;
            }
            let ciphertexts = self
                .ciphertexts
                .entry(self.epoch)
                .or_insert_with(BTreeMap::new);
            ciphertexts.insert(proposer_id, ciphertext);
        }
        Ok(())
    }

    /// Verifies the ciphertext and sends decryption shares. Returns whether it is valid.
    fn send_decryption_share(
        &mut self,
        proposer_id: &N,
        ciphertext: &Ciphertext,
    ) -> HoneyBadgerResult<bool> {
        if !self.netinfo.is_validator() {
            return Ok(ciphertext.verify());
        }
        let share = match self.netinfo.secret_key().decrypt_share(&ciphertext) {
            None => return Ok(false),
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
        self.handle_decryption_share_message(&our_id, epoch, proposer_id.clone(), share)?;
        Ok(true)
    }

    /// Verifies the shares of the current epoch that are pending verification. Returned are the
    /// senders with incorrect pending shares.
    fn verify_pending_decryption_shares(
        &self,
        proposer_id: &N,
        ciphertext: &Ciphertext,
    ) -> BTreeSet<N> {
        let mut incorrect_senders = BTreeSet::new();
        if let Some(sender_shares) = self
            .received_shares
            .get(&self.epoch)
            .and_then(|e| e.get(proposer_id))
        {
            for (sender_id, share) in sender_shares {
                if !self.verify_decryption_share(sender_id, share, ciphertext) {
                    incorrect_senders.insert(sender_id.clone());
                }
            }
        }
        incorrect_senders
    }

    fn remove_incorrect_decryption_shares(
        &mut self,
        proposer_id: &N,
        incorrect_senders: BTreeSet<N>,
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
    fn process_output(&mut self) -> Result<(), Error> {
        if let Some(cs_output) = self.take_current_output() {
            self.send_decryption_shares(cs_output)?;
            // TODO: May also check that there is no further output from Common Subset.
        }
        Ok(())
    }

    /// Returns the output of the current epoch's `CommonSubset` instance, if any.
    fn take_current_output(&mut self) -> Option<BTreeMap<N, Vec<u8>>> {
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

/// A batch of transactions the algorithm has output.
///
/// TODO: Consider adding a `faulty_nodes` field to describe and report failures detected by `HoneyBadger`.
#[derive(Clone)]
pub struct Batch<C, N> {
    pub epoch: u64,
    pub transactions: BTreeMap<N, Vec<C>>,
}

impl<C, N: NodeUid> Batch<C, N> {
    /// Returns an iterator over references to all transactions included in the batch.
    // pub fn iter(&self) -> impl Iterator<Item = &C> {
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = &C> {
        self.transactions.values().flat_map(|vec| vec)
    }

    /// Returns an iterator over all transactions included in the batch. Consumes the batch.
    pub fn into_tx_iter(self) -> impl Iterator<Item = C> {
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
pub enum MessageContent<N> {
    /// A message belonging to the common subset algorithm in the given epoch.
    CommonSubset(common_subset::Message<N>),
    /// A decrypted share of the output of `proposer_id`.
    DecryptionShare {
        proposer_id: N,
        share: DecryptionShare,
    },
}

impl<N> MessageContent<N> {
    pub fn with_epoch(self, epoch: u64) -> Message<N> {
        Message {
            epoch,
            content: self,
        }
    }
}

/// A message sent to or received from another node's Honey Badger instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message<N> {
    epoch: u64,
    content: MessageContent<N>,
}

impl<N> Message<N> {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// The queue of outgoing messages in a `HoneyBadger` instance.
#[derive(Deref, DerefMut)]
struct MessageQueue<N>(VecDeque<TargetedMessage<Message<N>, N>>);

impl<N: NodeUid> MessageQueue<N> {
    /// Appends to the queue the messages from `cs`, wrapped with `epoch`.
    fn extend_with_epoch(&mut self, epoch: u64, cs: &mut CommonSubset<N>) {
        let convert = |msg: TargetedMessage<common_subset::Message<N>, N>| {
            msg.map(|cs_msg| MessageContent::CommonSubset(cs_msg).with_epoch(epoch))
        };
        self.extend(cs.message_iter().map(convert));
    }
}
