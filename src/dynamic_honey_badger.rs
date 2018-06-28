//! # Dynamic Honey Badger
//!
//! Like Honey Badger, this protocol allows a network of `N` nodes with at most `f` faulty ones,
//! where `3 * f < N`, to input "transactions" - any kind of data -, and to agree on a sequence of
//! _batches_ of transactions. The protocol proceeds in _epochs_, starting at number 0, and outputs
//! one batch in each epoch. It never terminates: It handles a continuous stream of incoming
//! transactions and keeps producing new batches from them. All correct nodes will output the same
//! batch for each epoch.
//!
//! Unlike Honey Badger, this algorithm allows dynamically adding new full peers from the pool of
//! observer nodes, and turning full peers back into observers. As a signal to initiate that
//! process, it defines a special `Change` input variant, which contains either a vote
//! `Add(node_id, public_key)`, to add a new full peer, or `Remove(node_id)` to remove it. Each
//! full peer can have at most one active vote, and casting another vote revokes the previous one.
//! Once a simple majority of full nodes has the same active vote, a reconfiguration process begins
//! (they need to create new cryptographic key shares for the new composition).
//!
//! The state of that process after each epoch is communicated via the `Batch::change` field. When
//! this contains an `InProgress(Add(..))` value, all nodes need to send every future `Target::All`
//! message to the new node, too. Once the value is `Complete`, the votes will be reset, and the
//! next epoch will run using the new set of full nodes.
//!
//! ## How it works
//!
//! Dynamic Honey Badger runs a regular Honey Badger instance internally, which in addition to the
//! user's transactions contains special transactions for the change votes and the key generation
//! messages: Running votes and key generation "on-chain", as transactions, greatly simplifies
//! these processes, since it is guaranteed that every node will see the same sequence of votes and
//! messages.
//!
//! Every time Honey Badger outputs a new batch, Dynamic Honey Badger outputs the user transactions
//! in its own batch. The other transactions are processed: votes are counted and key generation
//! messages are passed into a `SyncKeyGen` instance.
//!
//! If after an epoch key generation has completed, the Honey Badger instance (including all
//! pending batches) is dropped, and replaced by a new one with the new set of participants.
//!
//! Otherwise we check if the majority of votes has changed. If a new change has a majority, the
//! `SyncKeyGen` instance is dropped, and a new one is started to create keys according to the new
//! pending change.
// TODO: Document how to add observers, once that is supported.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::mem;
use std::rc::Rc;

use bincode;
use clear_on_drop::ClearOnDrop;
use serde::{Deserialize, Serialize};

use crypto::{PublicKey, PublicKeySet, SecretKey, Signature};
use honey_badger::{self, HoneyBadger};
use messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};
use sync_key_gen::{Accept, Propose, SyncKeyGen};

type KeyGenOutput = (PublicKeySet, Option<ClearOnDrop<Box<SecretKey>>>);

error_chain!{
    links {
        HoneyBadger(honey_badger::Error, honey_badger::ErrorKind);
    }

    foreign_links {
        Bincode(Box<bincode::ErrorKind>);
    }

    errors {
        UnknownSender
    }
}

/// A node change action: adding or removing a node.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum Change<NodeUid> {
    /// Add a node. The public key is used only temporarily, for key generation.
    Add(NodeUid, PublicKey),
    /// Remove a node.
    Remove(NodeUid),
}

impl<NodeUid> Change<NodeUid> {
    /// Returns the ID of the current candidate for being added, if any.
    fn candidate(&self) -> Option<&NodeUid> {
        match *self {
            Change::Add(ref id, _) => Some(id),
            Change::Remove(_) => None,
        }
    }
}

/// A change status: whether a node addition or removal is currently in progress or completed.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum ChangeState<NodeUid> {
    /// No node is currently being considered for addition or removal.
    None,
    /// A change is currently in progress. If it is an addition, all broadcast messages must be
    /// sent to the new node, too.
    InProgress(Change<NodeUid>),
    /// A change has been completed in this epoch. From the next epoch on, the new composition of
    /// the network will perform the consensus process.
    Complete(Change<NodeUid>),
}

/// The user input for `DynamicHoneyBadger`.
#[derive(Clone, Debug)]
pub enum Input<Tx, NodeUid> {
    /// A user-defined transaction.
    User(Tx),
    /// A vote to change the set of nodes.
    Change(Change<NodeUid>),
}

/// A Honey Badger instance that can handle adding and removing nodes.
pub struct DynamicHoneyBadger<Tx, NodeUid>
where
    Tx: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Ord + Clone + Serialize + for<'r> Deserialize<'r> + Debug,
{
    /// Shared network data.
    netinfo: NetworkInfo<NodeUid>,
    /// The target number of transactions per batch.
    batch_size: usize,
    /// The first epoch after the latest node change.
    start_epoch: u64,
    /// Collected votes for adding or removing nodes. Each node has one vote, and casting another
    /// vote revokes the previous one. Resets whenever the set of peers is successfully changed.
    votes: BTreeMap<NodeUid, Change<NodeUid>>,
    /// The `HoneyBadger` instance with the current set of nodes.
    honey_badger: HoneyBadger<Transaction<Tx, NodeUid>, NodeUid>,
    /// The current key generation process, and the change it applies to.
    key_gen: Option<(SyncKeyGen<NodeUid>, Change<NodeUid>)>,
    /// A queue for messages from future epochs that cannot be handled yet.
    incoming_queue: Vec<(NodeUid, Message<NodeUid>)>,
    /// The messages that need to be sent to other nodes.
    messages: MessageQueue<NodeUid>,
    /// The outputs from completed epochs.
    output: VecDeque<Batch<Tx, NodeUid>>,
}

impl<Tx, NodeUid> DistAlgorithm for DynamicHoneyBadger<Tx, NodeUid>
where
    Tx: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Eq + Ord + Clone + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
{
    type NodeUid = NodeUid;
    type Input = Input<Tx, NodeUid>;
    type Output = Batch<Tx, NodeUid>;
    type Message = Message<NodeUid>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<()> {
        // User transactions are forwarded to `HoneyBadger` right away. Internal messages are
        // in addition signed and broadcast.
        match input {
            Input::User(tx) => {
                self.honey_badger.input(Transaction::User(tx))?;
                self.process_output()
            }
            Input::Change(change) => self.send_transaction(NodeTransaction::Change(change)),
        }
    }

    fn handle_message(&mut self, sender_id: &NodeUid, message: Self::Message) -> Result<()> {
        let epoch = message.epoch();
        if epoch < self.start_epoch {
            return Ok(()); // Obsolete message.
        }
        if epoch > self.start_epoch {
            // Message cannot be handled yet. Save it for later.
            let entry = (sender_id.clone(), message);
            self.incoming_queue.push(entry);
            return Ok(());
        }
        match message {
            Message::HoneyBadger(_, hb_msg) => self.handle_honey_badger_message(sender_id, hb_msg),
            Message::Signed(_, node_tx, sig) => self.handle_signed_message(sender_id, node_tx, sig),
        }
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

impl<Tx, NodeUid> DynamicHoneyBadger<Tx, NodeUid>
where
    Tx: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Eq + Ord + Clone + Debug + Serialize + for<'r> Deserialize<'r> + Hash,
{
    /// Returns a new instance with the given parameters, starting at epoch `0`.
    pub fn new(netinfo: NetworkInfo<NodeUid>, batch_size: usize) -> Result<Self> {
        let honey_badger = HoneyBadger::new(Rc::new(netinfo.clone()), batch_size, None)?;
        let dyn_hb = DynamicHoneyBadger {
            netinfo,
            batch_size,
            start_epoch: 0,
            votes: BTreeMap::new(),
            honey_badger,
            key_gen: None,
            incoming_queue: Vec::new(),
            messages: MessageQueue(VecDeque::new()),
            output: VecDeque::new(),
        };
        Ok(dyn_hb)
    }

    /// Handles a message for the `HoneyBadger` instance.
    fn handle_honey_badger_message(
        &mut self,
        sender_id: &NodeUid,
        message: honey_badger::Message<NodeUid>,
    ) -> Result<()> {
        if !self.netinfo.all_uids().contains(sender_id) {
            info!("Unknown sender {:?} of message {:?}", sender_id, message);
            return Err(ErrorKind::UnknownSender.into());
        }
        // Handle the message and put the outgoing messages into the queue.
        self.honey_badger.handle_message(sender_id, message)?;
        self.process_output()
    }

    /// Handles a vote or key generation message and tries to commit it as a transaction. These
    /// messages are only handled once they appear in a batch output from Honey Badger.
    fn handle_signed_message(
        &mut self,
        sender_id: &NodeUid,
        node_tx: NodeTransaction<NodeUid>,
        sig: Box<Signature>,
    ) -> Result<()> {
        self.verify_signature(sender_id, &*sig, &node_tx)?;
        let tx = Transaction::Signed(self.start_epoch, sender_id.clone(), node_tx, sig);
        self.honey_badger.input(tx)?;
        self.process_output()
    }

    /// Processes all pending batches output by Honey Badger.
    fn process_output(&mut self) -> Result<()> {
        let start_epoch = self.start_epoch;
        while let Some(hb_batch) = self.honey_badger.next_output() {
            // Create the batch we output ourselves. It will contain the _user_ transactions of
            // `hb_batch`, and the current change state.
            let mut batch = Batch::new(hb_batch.epoch + self.start_epoch);
            // Add the user transactions to `batch` and handle votes and DKG messages.
            for (id, tx_vec) in hb_batch.transactions {
                let entry = batch.transactions.entry(id);
                let id_txs = entry.or_insert_with(Vec::new);
                for tx in tx_vec {
                    match tx {
                        Transaction::User(tx) => id_txs.push(tx),
                        Transaction::Signed(epoch, s_id, node_tx, sig) => {
                            if epoch < self.start_epoch {
                                info!("Obsolete node transaction: {:?}.", node_tx);
                                continue;
                            }
                            if !self.verify_signature(&s_id, &sig, &node_tx)? {
                                info!("Invalid signature from {:?} for: {:?}.", s_id, node_tx);
                                continue;
                            }
                            use self::NodeTransaction::*;
                            match node_tx {
                                Change(change) => self.handle_vote(s_id, change),
                                Propose(propose) => self.handle_propose(&s_id, propose)?,
                                Accept(accept) => self.handle_accept(&s_id, accept)?,
                            }
                        }
                    }
                }
            }
            if let Some(((pub_key_set, sk), change)) = self.take_key_gen_output() {
                // If DKG completed, apply the change.
                debug!("{:?} DKG for {:?} complete!", self.our_id(), change);
                // If we are a full peer, we received a new secret key. Otherwise keep the old one.
                let sk = sk.unwrap_or_else(|| {
                    ClearOnDrop::new(Box::new(self.netinfo.secret_key().clone()))
                });
                // Restart Honey Badger in the next epoch, and inform the user about the change.
                self.start_epoch = batch.epoch + 1;
                self.apply_change(&change, pub_key_set, sk)?;
                batch.change = ChangeState::Complete(change);
            } else {
                // If the majority changed, restart DKG. Inform the user about the current change.
                self.update_key_gen()?;
                if let Some((_, ref change)) = self.key_gen {
                    batch.change = ChangeState::InProgress(change.clone());
                }
            }
            self.output.push_back(batch);
        }
        self.messages
            .extend_with_epoch(self.start_epoch, &mut self.honey_badger);
        // If `start_epoch` changed, we can now handle some queued messages.
        if start_epoch < self.start_epoch {
            let queue = mem::replace(&mut self.incoming_queue, Vec::new());
            for (sender_id, msg) in queue {
                self.handle_message(&sender_id, msg)?;
            }
        }
        Ok(())
    }

    /// Restarts Honey Badger with a new set of nodes, and resets the Key Generation.
    fn apply_change(
        &mut self,
        change: &Change<NodeUid>,
        pub_key_set: PublicKeySet,
        sk: ClearOnDrop<Box<SecretKey>>,
    ) -> Result<()> {
        self.votes.clear();
        self.key_gen = None;
        let mut all_uids = self.netinfo.all_uids().clone();
        if !match *change {
            Change::Remove(ref id) => all_uids.remove(id),
            Change::Add(ref id, _) => all_uids.insert(id.clone()),
        } {
            info!("No-op change: {:?}", change);
        }
        let netinfo = NetworkInfo::new(self.our_id().clone(), all_uids, sk, pub_key_set);
        self.netinfo = netinfo.clone();
        // TODO: If there are more pending outputs, maybe their transactions should be added, too?
        // They will have been removed from the buffer already.
        let old_buffer = self.honey_badger.drain_buffer().into_iter();
        let new_buffer = old_buffer.filter(Transaction::is_user);
        self.honey_badger = HoneyBadger::new(Rc::new(netinfo), self.batch_size, new_buffer)?;
        Ok(())
    }

    /// If the majority of votes has changed, restarts Key Generation for the set of nodes implied
    /// by the current change.
    fn update_key_gen(&mut self) -> Result<()> {
        let change = match current_majority(&self.votes, &self.netinfo) {
            None => {
                self.key_gen = None;
                return Ok(());
            }
            Some(change) => {
                if self.key_gen.as_ref().map(|&(_, ref ch)| ch) == Some(change) {
                    return Ok(()); // The change is the same as last epoch. Continue DKG as is.
                }
                change.clone()
            }
        };
        debug!("{:?} Restarting DKG for {:?}.", self.our_id(), change);
        // Use the existing key shares - with the change applied - as keys for DKG.
        let mut pub_keys = self.netinfo.public_key_map().clone();
        if match change {
            Change::Remove(ref id) => pub_keys.remove(id).is_none(),
            Change::Add(ref id, ref pk) => pub_keys.insert(id.clone(), pk.clone()).is_some(),
        } {
            info!("{:?} No-op change: {:?}", self.our_id(), change);
        }
        // TODO: This needs to be the same as `num_faulty` will be in the _new_
        // `NetworkInfo` if the change goes through. It would be safer to deduplicate.
        let threshold = (pub_keys.len() - 1) / 3;
        let sk = self.netinfo.secret_key().clone();
        let our_uid = self.our_id().clone();
        let (key_gen, propose) = SyncKeyGen::new(&our_uid, sk, pub_keys, threshold);
        self.key_gen = Some((key_gen, change));
        if let Some(propose) = propose {
            self.send_transaction(NodeTransaction::Propose(propose))?;
        }
        Ok(())
    }

    /// Handles a `Propose` message that was output by Honey Badger.
    fn handle_propose(&mut self, sender_id: &NodeUid, propose: Propose) -> Result<()> {
        let handle = |&mut (ref mut key_gen, _): &mut (SyncKeyGen<NodeUid>, _)| {
            key_gen.handle_propose(&sender_id, propose)
        };
        match self.key_gen.as_mut().and_then(handle) {
            Some(accept) => self.send_transaction(NodeTransaction::Accept(accept)),
            None => Ok(()),
        }
    }

    /// Handles an `Accept` message that was output by Honey Badger.
    fn handle_accept(&mut self, sender_id: &NodeUid, accept: Accept) -> Result<()> {
        if let Some(&mut (ref mut key_gen, _)) = self.key_gen.as_mut() {
            key_gen.handle_accept(&sender_id, accept);
        }
        Ok(())
    }

    /// Signs and sends a `NodeTransaction` and also tries to commit it.
    fn send_transaction(&mut self, node_tx: NodeTransaction<NodeUid>) -> Result<()> {
        let sig = self.sign(&node_tx)?;
        let msg = Message::Signed(self.start_epoch, node_tx.clone(), sig.clone());
        self.messages.push_back(Target::All.message(msg));
        if !self.netinfo.is_peer() {
            return Ok(());
        }
        let our_uid = self.netinfo.our_uid().clone();
        let hb_tx = Transaction::Signed(self.start_epoch, our_uid, node_tx, sig);
        self.honey_badger.input(hb_tx)?;
        self.process_output()
    }

    /// If the current Key Generation process is ready, returns the generated key set.
    ///
    /// We require the minimum number of completed proposals (`SyncKeyGen::is_ready`) and if a new
    /// node is joining, we require in addition that the new node's proposal is complete. That way
    /// the new node knows that it's key is secret, without having to trust any number of nodes.
    fn take_key_gen_output(&mut self) -> Option<(KeyGenOutput, Change<NodeUid>)> {
        let is_ready = |&(ref key_gen, ref change): &(SyncKeyGen<_>, Change<_>)| {
            let candidate_ready = |id: &NodeUid| key_gen.is_node_ready(id);
            key_gen.is_ready() && change.candidate().map_or(true, candidate_ready)
        };
        if self.key_gen.as_ref().map_or(false, is_ready) {
            let generate = |(key_gen, change): (SyncKeyGen<_>, _)| (key_gen.generate(), change);
            self.key_gen.take().map(generate)
        } else {
            None
        }
    }

    /// Returns a signature of `node_tx`, or an error if serialization fails.
    fn sign(&self, node_tx: &NodeTransaction<NodeUid>) -> Result<Box<Signature>> {
        let ser = bincode::serialize(node_tx)?;
        Ok(Box::new(self.netinfo.secret_key().sign(ser)))
    }

    /// Returns `true` if the signature of `node_tx` by the node with the specified ID is valid.
    /// Returns an error if the payload fails to serialize.
    fn verify_signature(
        &self,
        node_id: &NodeUid,
        sig: &Signature,
        node_tx: &NodeTransaction<NodeUid>,
    ) -> Result<bool> {
        let ser = bincode::serialize(node_tx)?;
        let pk_opt = (self.netinfo.public_key_share(node_id)).or_else(|| {
            self.key_gen
                .iter()
                .filter_map(|&(_, ref change): &(_, Change<_>)| match *change {
                    Change::Add(ref id, ref pk) if id == node_id => Some(pk),
                    Change::Add(_, _) | Change::Remove(_) => None,
                })
                .next()
        });
        Ok(pk_opt.map_or(false, |pk| pk.verify(&sig, ser)))
    }

    /// Adds a vote for a node change by the node with `id`.
    fn handle_vote(&mut self, sender_id: NodeUid, change: Change<NodeUid>) {
        let obsolete = match change {
            Change::Add(ref id, _) => self.netinfo.all_uids().contains(id),
            Change::Remove(ref id) => !self.netinfo.all_uids().contains(id),
        };
        if !obsolete {
            self.votes.insert(sender_id, change);
        }
    }
}

/// Returns the change that currently has a majority of votes, if any.
fn current_majority<'a, NodeUid: Ord + Clone + Hash + Eq>(
    votes: &'a BTreeMap<NodeUid, Change<NodeUid>>,
    netinfo: &'a NetworkInfo<NodeUid>,
) -> Option<&'a Change<NodeUid>> {
    let mut vote_counts: HashMap<&Change<NodeUid>, usize> = HashMap::new();
    for change in votes.values() {
        let entry = vote_counts.entry(change).or_insert(0);
        *entry += 1;
        if *entry * 2 > netinfo.num_nodes() {
            return Some(change);
        }
    }
    None
}

/// The transactions for the internal `HoneyBadger` instance: this includes both user-defined
/// "regular" transactions as well as internal transactions for coordinating node additions and
/// removals and key generation.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Hash)]
enum Transaction<Tx, NodeUid> {
    /// A user-defined transaction.
    User(Tx),
    /// A signed internal message that gets committed via Honey Badger to communicate synchronously.
    Signed(u64, NodeUid, NodeTransaction<NodeUid>, Box<Signature>),
}

impl<Tx, NodeUid> Transaction<Tx, NodeUid> {
    /// Returns `true` if this is a user transaction.
    fn is_user(&self) -> bool {
        match *self {
            Transaction::User(_) => true,
            Transaction::Signed(_, _, _, _) => false,
        }
    }
}

/// A batch of transactions the algorithm has output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Batch<Tx, NodeUid> {
    /// The sequence number: there is exactly one batch in each epoch.
    pub epoch: u64,
    /// The user transactions committed in this epoch.
    pub transactions: BTreeMap<NodeUid, Vec<Tx>>,
    /// The current state of adding or removing a node: whether any is in progress, or completed
    /// this epoch.
    pub change: ChangeState<NodeUid>,
}

impl<Tx, NodeUid: Ord> Batch<Tx, NodeUid> {
    /// Returns a new, empty batch with the given epoch.
    pub fn new(epoch: u64) -> Self {
        Batch {
            epoch,
            transactions: BTreeMap::new(),
            change: ChangeState::None,
        }
    }

    /// Returns an iterator over all transactions included in the batch.
    pub fn iter(&self) -> impl Iterator<Item = &Tx> {
        self.transactions.values().flat_map(|vec| vec)
    }

    /// Returns the number of transactions in the batch (without detecting duplicates).
    pub fn len(&self) -> usize {
        self.transactions.values().map(Vec::len).sum()
    }

    /// Returns `true` if the batch contains no transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.values().all(Vec::is_empty)
    }

    /// Returns whether any change to the set of participating nodes is in progress or was
    /// completed in this epoch.
    pub fn change(&self) -> &ChangeState<NodeUid> {
        &self.change
    }
}

/// An internal message that gets committed via Honey Badger to communicate synchronously.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Hash, Clone)]
pub enum NodeTransaction<NodeUid> {
    /// A vote to add or remove a node.
    Change(Change<NodeUid>),
    /// A `SyncKeyGen::Propose` message for key generation.
    Propose(Propose),
    /// A `SyncKeyGen::Accept` message for key generation.
    Accept(Accept),
}

/// A message sent to or received from another node's Honey Badger instance.
#[cfg_attr(feature = "serialization-serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub enum Message<NodeUid> {
    /// A message belonging to the `HoneyBadger` algorithm started in the given epoch.
    HoneyBadger(u64, honey_badger::Message<NodeUid>),
    /// A transaction to be committed, signed by a node.
    Signed(u64, NodeTransaction<NodeUid>, Box<Signature>),
}

impl<NodeUid> Message<NodeUid> {
    pub fn epoch(&self) -> u64 {
        match *self {
            Message::HoneyBadger(epoch, _) => epoch,
            Message::Signed(epoch, _, _) => epoch,
        }
    }
}

/// The queue of outgoing messages in a `HoneyBadger` instance.
#[derive(Deref, DerefMut)]
struct MessageQueue<NodeUid>(VecDeque<TargetedMessage<Message<NodeUid>, NodeUid>>);

impl<NodeUid> MessageQueue<NodeUid>
where
    NodeUid: Eq + Hash + Ord + Clone + Debug + Serialize + for<'r> Deserialize<'r>,
{
    /// Appends to the queue the messages from `hb`, wrapped with `epoch`.
    fn extend_with_epoch<Tx>(&mut self, epoch: u64, hb: &mut HoneyBadger<Tx, NodeUid>)
    where
        Tx: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    {
        let convert = |msg: TargetedMessage<honey_badger::Message<NodeUid>, NodeUid>| {
            msg.map(|hb_msg| Message::HoneyBadger(epoch, hb_msg))
        };
        self.extend(hb.message_iter().map(convert));
    }
}
