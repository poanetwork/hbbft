//! # Dynamic Honey Badger
//!
//! Like Honey Badger, this protocol allows a network of _N_ nodes with at most _f_ faulty ones,
//! where _3 f < N_, to input "contributions" - any kind of data -, and to agree on a sequence of
//! _batches_ of contributions. The protocol proceeds in _epochs_, starting at number 0, and outputs
//! one batch in each epoch. It never terminates: It handles a continuous stream of incoming
//! contributions and keeps producing new batches from them. All correct nodes will output the same
//! batch for each epoch.
//!
//! Unlike Honey Badger, this algorithm allows dynamically adding new validators from the pool of
//! observer nodes, and turning validators back into observers. As a signal to initiate that
//! process, it defines a special `Change` input variant, which contains either a vote
//! `Add(node_id, public_key)`, to add a new validator, or `Remove(node_id)` to remove it. Each
//! validator can have at most one active vote, and casting another vote revokes the previous one.
//! Once a simple majority of validators has the same active vote, a reconfiguration process begins
//! (they need to create new cryptographic key shares for the new composition).
//!
//! The state of that process after each epoch is communicated via the `Batch::change` field. When
//! this contains an `InProgress(Add(..))` value, all nodes need to send every future `Target::All`
//! message to the new node, too. Once the value is `Complete`, the votes will be reset, and the
//! next epoch will run using the new set of validators.
//!
//! New observers can also be added by starting them with an appropriate `start_epoch` parameter
//! and ensuring that they receive all `Target::All` messages from that epoch on. Together with the
//! above mechanism, this allows the network to change dynamically. You can introduce a new node to
//! the network and make it a validator, you can demote validators to observers, and you can remove
//! observers at any time.
//!
//! ## How it works
//!
//! Dynamic Honey Badger runs a regular Honey Badger instance internally, which in addition to the
//! user's contributions contains special transactions for the change votes and the key generation
//! messages: Running votes and key generation "on-chain" greatly simplifies these processes, since
//! it is guaranteed that every node will see the same sequence of votes and messages.
//!
//! Every time Honey Badger outputs a new batch, Dynamic Honey Badger outputs the user
//! contributions in its own batch. The other transactions are processed: votes are counted and key
//! generation messages are passed into a `SyncKeyGen` instance.
//!
//! If after an epoch key generation has completed, the Honey Badger instance (including all
//! pending batches) is dropped, and replaced by a new one with the new set of participants.
//!
//! Otherwise we check if the majority of votes has changed. If a new change has a majority, the
//! `SyncKeyGen` instance is dropped, and a new one is started to create keys according to the new
//! pending change.

use rand::Rand;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::hash::Hash;
use std::mem;
use std::sync::Arc;

use bincode;
use serde::{Deserialize, Serialize};

use self::votes::{SignedVote, VoteCounter};
use crypto::{PublicKeySet, SecretKey, Signature};
use fault_log::{FaultKind, FaultLog};
use honey_badger::{HoneyBadger, Message as HbMessage};
use messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};
use sync_key_gen::{Accept, Propose, ProposeOutcome, SyncKeyGen};

pub use self::batch::Batch;
pub use self::builder::DynamicHoneyBadgerBuilder;
pub use self::change::{Change, ChangeState};
pub use self::error::{Error, ErrorKind, Result};

mod batch;
mod builder;
mod change;
mod error;
mod votes;

type KeyGenOutput = (PublicKeySet, Option<SecretKey>);

/// The user input for `DynamicHoneyBadger`.
#[derive(Clone, Debug)]
pub enum Input<C, NodeUid> {
    /// A user-defined contribution for the next epoch.
    User(C),
    /// A vote to change the set of validators.
    Change(Change<NodeUid>),
}

/// A Honey Badger instance that can handle adding and removing nodes.
pub struct DynamicHoneyBadger<C, NodeUid: Rand>
where
    C: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Ord + Clone + Serialize + for<'r> Deserialize<'r> + Debug,
{
    /// Shared network data.
    netinfo: NetworkInfo<NodeUid>,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    /// The first epoch after the latest node change.
    start_epoch: u64,
    /// The buffer and counter for the pending and committed change votes.
    vote_counter: VoteCounter<NodeUid>,
    /// Pending node transactions that we will propose in the next epoch.
    key_gen_msg_buffer: Vec<SignedKeyGenMsg<NodeUid>>,
    /// The `HoneyBadger` instance with the current set of nodes.
    honey_badger: HoneyBadger<InternalContrib<C, NodeUid>, NodeUid>,
    /// The current key generation process, and the change it applies to.
    key_gen: Option<(SyncKeyGen<NodeUid>, Change<NodeUid>)>,
    /// A queue for messages from future epochs that cannot be handled yet.
    incoming_queue: Vec<(NodeUid, Message<NodeUid>)>,
    /// The messages that need to be sent to other nodes.
    messages: MessageQueue<NodeUid>,
    /// The outputs from completed epochs.
    output: VecDeque<Batch<C, NodeUid>>,
}

impl<C, NodeUid> DistAlgorithm for DynamicHoneyBadger<C, NodeUid>
where
    C: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Eq + Ord + Clone + Serialize + for<'r> Deserialize<'r> + Debug + Hash + Rand,
{
    type NodeUid = NodeUid;
    type Input = Input<C, NodeUid>;
    type Output = Batch<C, NodeUid>;
    type Message = Message<NodeUid>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<FaultLog<NodeUid>> {
        // User contributions are forwarded to `HoneyBadger` right away. Votes are signed and
        // broadcast.
        match input {
            Input::User(contrib) => self.propose(contrib),
            Input::Change(change) => {
                self.vote_for(change)?;
                Ok(FaultLog::new())
            }
        }
    }

    fn handle_message(
        &mut self,
        sender_id: &NodeUid,
        message: Self::Message,
    ) -> Result<FaultLog<NodeUid>> {
        let epoch = message.epoch();
        if epoch < self.start_epoch {
            return Ok(FaultLog::new()); // Obsolete message.
        }
        if epoch > self.start_epoch {
            // Message cannot be handled yet. Save it for later.
            let entry = (sender_id.clone(), message);
            self.incoming_queue.push(entry);
            return Ok(FaultLog::new());
        }
        match message {
            Message::HoneyBadger(_, hb_msg) => self.handle_honey_badger_message(sender_id, hb_msg),
            Message::KeyGen(_, kg_msg, sig) => self.handle_key_gen_message(sender_id, kg_msg, *sig),
            Message::SignedVote(signed_vote) => {
                self.vote_counter.add_pending_vote(sender_id, signed_vote)
            }
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

impl<C, NodeUid> DynamicHoneyBadger<C, NodeUid>
where
    C: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Eq + Ord + Clone + Debug + Serialize + for<'r> Deserialize<'r> + Hash + Rand,
{
    /// Returns a new `DynamicHoneyBadgerBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    pub fn builder(netinfo: NetworkInfo<NodeUid>) -> DynamicHoneyBadgerBuilder<C, NodeUid> {
        DynamicHoneyBadgerBuilder::new(netinfo)
    }

    /// Returns `true` if input for the current epoch has already been provided.
    pub fn has_input(&self) -> bool {
        self.honey_badger.has_input()
    }

    /// Proposes a contribution in the current epoch.
    pub fn propose(&mut self, contrib: C) -> Result<FaultLog<NodeUid>> {
        let mut fault_log = self.honey_badger.input(InternalContrib {
            contrib,
            key_gen_messages: self.key_gen_msg_buffer.clone(),
            votes: self.vote_counter.pending_votes().cloned().collect(),
        })?;
        self.process_output()?.merge_into(&mut fault_log);
        Ok(fault_log)
    }

    /// Cast a vote to change the set of validators.
    pub fn vote_for(&mut self, change: Change<NodeUid>) -> Result<()> {
        if !self.netinfo.is_validator() {
            return Ok(()); // TODO: Return an error?
        }
        let signed_vote = self.vote_counter.sign_vote_for(change)?.clone();
        let msg = Message::SignedVote(signed_vote);
        self.messages.push_back(Target::All.message(msg));
        Ok(())
    }

    /// Returns the information about the node IDs in the network, and the cryptographic keys.
    pub fn netinfo(&self) -> &NetworkInfo<NodeUid> {
        &self.netinfo
    }

    /// Handles a message for the `HoneyBadger` instance.
    fn handle_honey_badger_message(
        &mut self,
        sender_id: &NodeUid,
        message: HbMessage<NodeUid>,
    ) -> Result<FaultLog<NodeUid>> {
        if !self.netinfo.all_uids().contains(sender_id) {
            info!("Unknown sender {:?} of message {:?}", sender_id, message);
            return Err(ErrorKind::UnknownSender.into());
        }
        // Handle the message and put the outgoing messages into the queue.
        let mut fault_log = self.honey_badger.handle_message(sender_id, message)?;
        self.process_output()?.merge_into(&mut fault_log);
        Ok(fault_log)
    }

    /// Handles a vote or key generation message and tries to commit it as a transaction. These
    /// messages are only handled once they appear in a batch output from Honey Badger.
    fn handle_key_gen_message(
        &mut self,
        sender_id: &NodeUid,
        kg_msg: KeyGenMessage,
        sig: Signature,
    ) -> Result<FaultLog<NodeUid>> {
        self.verify_signature(sender_id, &sig, &kg_msg)?;
        let tx = SignedKeyGenMsg(self.start_epoch, sender_id.clone(), kg_msg, sig);
        self.key_gen_msg_buffer.push(tx);
        self.process_output()
    }

    /// Processes all pending batches output by Honey Badger.
    fn process_output(&mut self) -> Result<FaultLog<NodeUid>> {
        let mut fault_log = FaultLog::new();
        let start_epoch = self.start_epoch;
        while let Some(hb_batch) = self.honey_badger.next_output() {
            // Create the batch we output ourselves. It will contain the _user_ transactions of
            // `hb_batch`, and the current change state.
            let mut batch = Batch::new(hb_batch.epoch + self.start_epoch);
            // Add the user transactions to `batch` and handle votes and DKG messages.
            for (id, int_contrib) in hb_batch.contributions {
                let votes = int_contrib.votes;
                fault_log.extend(self.vote_counter.add_committed_votes(&id, votes)?);
                batch.contributions.insert(id, int_contrib.contrib);
                for SignedKeyGenMsg(epoch, s_id, kg_msg, sig) in int_contrib.key_gen_messages {
                    if epoch < self.start_epoch {
                        info!("Obsolete key generation message: {:?}.", kg_msg);
                        continue;
                    }
                    if !self.verify_signature(&s_id, &sig, &kg_msg)? {
                        info!("Invalid signature from {:?} for: {:?}.", s_id, kg_msg);
                        let fault_kind = FaultKind::InvalidKeyGenMessageSignature;
                        fault_log.append(s_id.clone(), fault_kind);
                        continue;
                    }
                    match kg_msg {
                        KeyGenMessage::Propose(propose) => self.handle_propose(&s_id, propose)?,
                        KeyGenMessage::Accept(accept) => self.handle_accept(&s_id, accept)?,
                    }.merge_into(&mut fault_log);
                }
            }
            if let Some(((pub_key_set, sk), change)) = self.take_key_gen_output() {
                // If DKG completed, apply the change.
                debug!("{:?} DKG for {:?} complete!", self.our_id(), change);
                // If we are a validator, we received a new secret key. Otherwise keep the old one.
                let sk = sk.unwrap_or_else(|| self.netinfo.secret_key().clone());
                // Restart Honey Badger in the next epoch, and inform the user about the change.
                self.apply_change(&change, pub_key_set, sk, batch.epoch + 1)?;
                batch.change = ChangeState::Complete(change);
            } else if let Some(change) = self.vote_counter.compute_majority().cloned() {
                // If there is a majority, restart DKG. Inform the user about the current change.
                self.update_key_gen(batch.epoch + 1, change)?;
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
                self.handle_message(&sender_id, msg)?
                    .merge_into(&mut fault_log);
            }
        }
        Ok(fault_log)
    }

    /// Restarts Honey Badger with a new set of nodes, and resets the Key Generation.
    fn apply_change(
        &mut self,
        change: &Change<NodeUid>,
        pub_key_set: PublicKeySet,
        sk: SecretKey,
        epoch: u64,
    ) -> Result<()> {
        self.key_gen = None;
        let mut all_uids = self.netinfo.all_uids().clone();
        if !match *change {
            Change::Remove(ref id) => all_uids.remove(id),
            Change::Add(ref id, _) => all_uids.insert(id.clone()),
        } {
            info!("No-op change: {:?}", change);
        }
        let netinfo = NetworkInfo::new(self.our_id().clone(), all_uids, sk, pub_key_set);
        self.netinfo = netinfo;
        self.restart_honey_badger(epoch)
    }

    /// If the majority of votes has changed, restarts Key Generation for the set of nodes implied
    /// by the current change.
    fn update_key_gen(&mut self, epoch: u64, change: Change<NodeUid>) -> Result<()> {
        if self.key_gen.as_ref().map(|&(_, ref ch)| ch) == Some(&change) {
            return Ok(()); // The change is the same as before. Continue DKG as is.
        }
        debug!("{:?} Restarting DKG for {:?}.", self.our_id(), change);
        // Use the existing key shares - with the change applied - as keys for DKG.
        let mut pub_keys = self.netinfo.public_key_map().clone();
        if match change {
            Change::Remove(ref id) => pub_keys.remove(id).is_none(),
            Change::Add(ref id, ref pk) => pub_keys.insert(id.clone(), pk.clone()).is_some(),
        } {
            info!("{:?} No-op change: {:?}", self.our_id(), change);
        }
        self.restart_honey_badger(epoch)?;
        // TODO: This needs to be the same as `num_faulty` will be in the _new_
        // `NetworkInfo` if the change goes through. It would be safer to deduplicate.
        let threshold = (pub_keys.len() - 1) / 3;
        let sk = self.netinfo.secret_key().clone();
        let our_uid = self.our_id().clone();
        let (key_gen, propose) = SyncKeyGen::new(&our_uid, sk, pub_keys, threshold);
        self.key_gen = Some((key_gen, change));
        if let Some(propose) = propose {
            self.send_transaction(KeyGenMessage::Propose(propose))?;
        }
        Ok(())
    }

    /// Starts a new `HoneyBadger` instance and resets the vote counter.
    fn restart_honey_badger(&mut self, epoch: u64) -> Result<()> {
        // TODO: Filter out the messages for `epoch` and later.
        self.messages
            .extend_with_epoch(self.start_epoch, &mut self.honey_badger);
        self.start_epoch = epoch;
        let netinfo = Arc::new(self.netinfo.clone());
        let counter = VoteCounter::new(netinfo.clone(), epoch);
        mem::replace(&mut self.vote_counter, counter);
        self.honey_badger = HoneyBadger::builder(netinfo)
            .max_future_epochs(self.max_future_epochs)
            .build();
        Ok(())
    }

    /// Handles a `Propose` message that was output by Honey Badger.
    fn handle_propose(
        &mut self,
        sender_id: &NodeUid,
        propose: Propose,
    ) -> Result<FaultLog<NodeUid>> {
        let handle = |&mut (ref mut key_gen, _): &mut (SyncKeyGen<NodeUid>, _)| {
            key_gen.handle_propose(&sender_id, propose)
        };
        match self.key_gen.as_mut().and_then(handle) {
            Some(ProposeOutcome::Valid(accept)) => {
                self.send_transaction(KeyGenMessage::Accept(accept))?;
                Ok(FaultLog::new())
            }
            Some(ProposeOutcome::Invalid(fault_log)) => Ok(fault_log),
            None => Ok(FaultLog::new()),
        }
    }

    /// Handles an `Accept` message that was output by Honey Badger.
    fn handle_accept(&mut self, sender_id: &NodeUid, accept: Accept) -> Result<FaultLog<NodeUid>> {
        if let Some(&mut (ref mut key_gen, _)) = self.key_gen.as_mut() {
            Ok(key_gen.handle_accept(&sender_id, accept))
        } else {
            Ok(FaultLog::new())
        }
    }

    /// Signs and sends a `KeyGenMessage` and also tries to commit it.
    fn send_transaction(&mut self, kg_msg: KeyGenMessage) -> Result<()> {
        let ser = bincode::serialize(&kg_msg)?;
        let sig = Box::new(self.netinfo.secret_key().sign(ser));
        let msg = Message::KeyGen(self.start_epoch, kg_msg.clone(), sig.clone());
        self.messages.push_back(Target::All.message(msg));
        if !self.netinfo.is_validator() {
            return Ok(());
        }
        let our_uid = self.netinfo.our_uid().clone();
        let signed_msg = SignedKeyGenMsg(self.start_epoch, our_uid, kg_msg, *sig);
        self.key_gen_msg_buffer.push(signed_msg);
        Ok(())
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

    /// Returns `true` if the signature of `kg_msg` by the node with the specified ID is valid.
    /// Returns an error if the payload fails to serialize.
    fn verify_signature(
        &self,
        node_id: &NodeUid,
        sig: &Signature,
        kg_msg: &KeyGenMessage,
    ) -> Result<bool> {
        let ser = bincode::serialize(kg_msg)?;
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
}

/// The contribution for the internal `HoneyBadger` instance: this includes a user-defined
/// application-level contribution as well as internal signed messages.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Hash)]
struct InternalContrib<C, NodeUid> {
    /// A user-defined contribution.
    contrib: C,
    /// Key generation messages that get committed via Honey Badger to communicate synchronously.
    key_gen_messages: Vec<SignedKeyGenMsg<NodeUid>>,
    /// Signed votes for validator set changes.
    votes: Vec<SignedVote<NodeUid>>,
}

/// A signed internal message.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Hash, Clone)]
struct SignedKeyGenMsg<NodeUid>(u64, NodeUid, KeyGenMessage, Signature);

/// An internal message containing a vote for adding or removing a validator, or a message for key
/// generation. It gets committed via Honey Badger and is only handled after it has been output in
/// a batch, so that all nodes see these messages in the same order.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Hash, Clone)]
pub enum KeyGenMessage {
    /// A `SyncKeyGen::Propose` message for key generation.
    Propose(Propose),
    /// A `SyncKeyGen::Accept` message for key generation.
    Accept(Accept),
}

/// A message sent to or received from another node's Honey Badger instance.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message<NodeUid: Rand> {
    /// A message belonging to the `HoneyBadger` algorithm started in the given epoch.
    HoneyBadger(u64, HbMessage<NodeUid>),
    /// A transaction to be committed, signed by a node.
    KeyGen(u64, KeyGenMessage, Box<Signature>),
    /// A vote to be committed, signed by a validator.
    SignedVote(SignedVote<NodeUid>),
}

impl<NodeUid: Rand> Message<NodeUid> {
    pub fn epoch(&self) -> u64 {
        match *self {
            Message::HoneyBadger(epoch, _) => epoch,
            Message::KeyGen(epoch, _, _) => epoch,
            Message::SignedVote(ref signed_vote) => signed_vote.era(),
        }
    }
}

/// The queue of outgoing messages in a `HoneyBadger` instance.
#[derive(Deref, DerefMut)]
struct MessageQueue<NodeUid: Rand>(VecDeque<TargetedMessage<Message<NodeUid>, NodeUid>>);

impl<NodeUid> MessageQueue<NodeUid>
where
    NodeUid: Eq + Hash + Ord + Clone + Debug + Serialize + for<'r> Deserialize<'r> + Rand,
{
    /// Appends to the queue the messages from `hb`, wrapped with `epoch`.
    fn extend_with_epoch<Tx>(&mut self, epoch: u64, hb: &mut HoneyBadger<Tx, NodeUid>)
    where
        Tx: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    {
        let convert = |msg: TargetedMessage<HbMessage<NodeUid>, NodeUid>| {
            msg.map(|hb_msg| Message::HoneyBadger(epoch, hb_msg))
        };
        self.extend(hb.message_iter().map(convert));
    }
}
