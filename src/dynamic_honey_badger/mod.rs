//! # Dynamic Honey Badger
//!
//! Like Honey Badger, this protocol allows a network of _N_ nodes with at most _f_ faulty ones,
//! where _3 f < N_, to input "contributions" - any kind of data -, and to agree on a sequence of
//! _batches_ of contributions. The protocol proceeds in _epochs_, starting at number 0, and outputs
//! one batch in each epoch. It never terminates: It handles a continuous stream of incoming
//! contributions and keeps producing new batches from them. All correct nodes will output the same
//! batch for each epoch. Each validator proposes one contribution per epoch, and every batch will
//! contain the contributions of at least _N - f_ validators.
//!
//! Unlike Honey Badger, this algorithm allows dynamically adding and removing validators.
//! As a signal to initiate converting observers to validators or vice versa, it defines a special
//! `Change` input variant, which contains either a vote `Add(node_id, public_key)`, to add an
//! existing observer to the set of validators, or `Remove(node_id)` to remove it. Each
//! validator can have at most one active vote, and casting another vote revokes the previous one.
//! Once _f + 1_ validators have the same active vote, a reconfiguration process begins: They
//! create new cryptographic key shares for the new group of validators.
//!
//! The state of that process after each epoch is communicated via the `change` field in `Batch`.
//! When this contains an `InProgress(..)` value, key generation begins. The joining validator (in
//! the case of an `Add` change) must be an observer starting in the following epoch or earlier.
//! When `change` is `Complete(..)`, the following epochs will be produced by the new set of
//! validators.
//!
//! New observers can only join the network after an epoch where `change` was not `None`. These
//! epochs' batches contain a `JoinPlan`, which can be sent as an invitation to the new node: The
//! `DynamicHoneyBadger` instance created from a `JoinPlan` will start as an observer in the
//! following epoch. All `Target::All` messages from that and later epochs must be sent to the new
//! node.
//!
//! Observer nodes can leave the network at any time.
//!
//! These mechanisms create a dynamic network where you can:
//!
//! * introduce new nodes as observers,
//! * promote observer nodes to validators,
//! * demote validator nodes to observers, and
//! * remove observer nodes,
//!
//! without interrupting the consensus process.
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
//! Whenever a change receives _f + 1_ votes, the votes are reset and key generation for that
//! change begins. If key generation completes successfully, the Honey Badger instance is dropped,
//! and replaced by a new one with the new set of participants. If a different change wins a
//! vote before that happens, key generation resets again, and is attempted for the new change.

use rand::Rand;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::mem;
use std::sync::Arc;

use bincode;
use crypto::{PublicKey, PublicKeySet, Signature};
use serde::{Deserialize, Serialize};

use self::votes::{SignedVote, VoteCounter};
use fault_log::{Fault, FaultKind, FaultLog};
use honey_badger::{self, HoneyBadger, Message as HbMessage};
use messaging::{self, DistAlgorithm, NetworkInfo, Target};
use sync_key_gen::{Ack, Part, PartOutcome, SyncKeyGen};

pub use self::batch::Batch;
pub use self::builder::DynamicHoneyBadgerBuilder;
pub use self::change::{Change, ChangeState};
pub use self::error::{Error, ErrorKind, Result};

mod batch;
mod builder;
mod change;
mod error;
mod votes;

/// The user input for `DynamicHoneyBadger`.
#[derive(Clone, Debug)]
pub enum Input<C, NodeUid> {
    /// A user-defined contribution for the next epoch.
    User(C),
    /// A vote to change the set of validators.
    Change(Change<NodeUid>),
}

/// A Honey Badger instance that can handle adding and removing nodes.
#[derive(Debug)]
pub struct DynamicHoneyBadger<C, NodeUid: Rand> {
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
    key_gen_state: Option<KeyGenState<NodeUid>>,
    /// A queue for messages from future epochs that cannot be handled yet.
    incoming_queue: Vec<(NodeUid, Message<NodeUid>)>,
}

pub type Step<C, NodeUid> = messaging::Step<DynamicHoneyBadger<C, NodeUid>>;

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

    fn input(&mut self, input: Self::Input) -> Result<Step<C, NodeUid>> {
        // User contributions are forwarded to `HoneyBadger` right away. Votes are signed and
        // broadcast.
        match input {
            Input::User(contrib) => self.propose(contrib),
            Input::Change(change) => self.vote_for(change),
        }
    }

    fn handle_message(
        &mut self,
        sender_id: &NodeUid,
        message: Self::Message,
    ) -> Result<Step<C, NodeUid>> {
        let epoch = message.start_epoch();
        if epoch < self.start_epoch {
            // Obsolete message.
            Ok(Step::default())
        } else if epoch > self.start_epoch {
            // Message cannot be handled yet. Save it for later.
            let entry = (sender_id.clone(), message);
            self.incoming_queue.push(entry);
            Ok(Step::default())
        } else {
            match message {
                Message::HoneyBadger(_, hb_msg) => {
                    self.handle_honey_badger_message(sender_id, hb_msg)
                }
                Message::KeyGen(_, kg_msg, sig) => self
                    .handle_key_gen_message(sender_id, kg_msg, *sig)
                    .map(FaultLog::into),
                Message::SignedVote(signed_vote) => self
                    .vote_counter
                    .add_pending_vote(sender_id, signed_vote)
                    .map(FaultLog::into),
            }
        }
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
    /// Returns a new `DynamicHoneyBadgerBuilder`.
    pub fn builder() -> DynamicHoneyBadgerBuilder<C, NodeUid> {
        DynamicHoneyBadgerBuilder::new()
    }

    /// Returns `true` if input for the current epoch has already been provided.
    pub fn has_input(&self) -> bool {
        self.honey_badger.has_input()
    }

    /// Proposes a contribution in the current epoch.
    pub fn propose(&mut self, contrib: C) -> Result<Step<C, NodeUid>> {
        let step = self
            .honey_badger
            .input(InternalContrib {
                contrib,
                key_gen_messages: self.key_gen_msg_buffer.clone(),
                votes: self.vote_counter.pending_votes().cloned().collect(),
            })
            .map_err(ErrorKind::ProposeHoneyBadger)?;
        self.process_output(step)
    }

    /// Cast a vote to change the set of validators.
    pub fn vote_for(&mut self, change: Change<NodeUid>) -> Result<Step<C, NodeUid>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default()); // TODO: Return an error?
        }
        let signed_vote = self.vote_counter.sign_vote_for(change)?.clone();
        let msg = Message::SignedVote(signed_vote);
        Ok(Target::All.message(msg).into())
    }

    /// Returns the information about the node IDs in the network, and the cryptographic keys.
    pub fn netinfo(&self) -> &NetworkInfo<NodeUid> {
        &self.netinfo
    }

    /// Returns `true` if we should make our contribution for the next epoch, even if we don't have
    /// content ourselves, to avoid stalling the network.
    ///
    /// By proposing only if this returns `true`, you can prevent an adversary from making the
    /// network output empty baches indefinitely, but it also means that the network won't advance
    /// if fewer than _f + 1_ nodes have pending contributions.
    pub fn should_propose(&self) -> bool {
        if self.has_input() {
            return false; // We have already proposed.
        }
        if self.honey_badger.received_proposals() > self.netinfo.num_faulty() {
            return true; // At least one correct node wants to move on to the next epoch.
        }
        let is_our_vote = |signed_vote: &SignedVote<_>| signed_vote.voter() == self.our_id();
        if self.vote_counter.pending_votes().any(is_our_vote) {
            return true; // We have pending input to vote for a validator change.
        }
        let kgs = match self.key_gen_state {
            None => return false, // No ongoing key generation.
            Some(ref kgs) => kgs,
        };
        // If either we or the candidate have a pending key gen message, we should propose.
        let ours_or_candidates = |msg: &SignedKeyGenMsg<_>| {
            msg.1 == *self.our_id() || Some(&msg.1) == kgs.change.candidate()
        };
        self.key_gen_msg_buffer.iter().any(ours_or_candidates)
    }

    /// Handles a message for the `HoneyBadger` instance.
    fn handle_honey_badger_message(
        &mut self,
        sender_id: &NodeUid,
        message: HbMessage<NodeUid>,
    ) -> Result<Step<C, NodeUid>> {
        if !self.netinfo.is_node_validator(sender_id) {
            info!("Unknown sender {:?} of message {:?}", sender_id, message);
            return Err(ErrorKind::UnknownSender.into());
        }
        // Handle the message.
        let step = self
            .honey_badger
            .handle_message(sender_id, message)
            .map_err(ErrorKind::HandleHoneyBadgerMessageHoneyBadger)?;
        self.process_output(step)
    }

    /// Handles a vote or key generation message and tries to commit it as a transaction. These
    /// messages are only handled once they appear in a batch output from Honey Badger.
    fn handle_key_gen_message(
        &mut self,
        sender_id: &NodeUid,
        kg_msg: KeyGenMessage,
        sig: Signature,
    ) -> Result<FaultLog<NodeUid>> {
        if !self.verify_signature(sender_id, &sig, &kg_msg)? {
            info!("Invalid signature from {:?} for: {:?}.", sender_id, kg_msg);
            let fault_kind = FaultKind::InvalidKeyGenMessageSignature;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }
        let kgs = match self.key_gen_state {
            Some(ref mut kgs) => kgs,
            None => {
                info!(
                    "Unexpected key gen message from {:?}: {:?}.",
                    sender_id, kg_msg
                );
                return Ok(Fault::new(sender_id.clone(), FaultKind::UnexpectedKeyGenMessage).into());
            }
        };

        // If the joining node is correct, it will send at most (N + 1)² + 1 key generation
        // messages.
        if Some(sender_id) == kgs.change.candidate() {
            let n = self.netinfo.num_nodes() + 1;
            if kgs.candidate_msg_count > n * n {
                info!(
                    "Too many key gen messages from candidate {:?}: {:?}.",
                    sender_id, kg_msg
                );
                let fault_kind = FaultKind::TooManyCandidateKeyGenMessages;
                return Ok(Fault::new(sender_id.clone(), fault_kind).into());
            }
            kgs.candidate_msg_count += 1;
        }

        let tx = SignedKeyGenMsg(self.start_epoch, sender_id.clone(), kg_msg, sig);
        self.key_gen_msg_buffer.push(tx);
        Ok(FaultLog::default())
    }

    /// Processes all pending batches output by Honey Badger.
    fn process_output(
        &mut self,
        hb_step: honey_badger::Step<InternalContrib<C, NodeUid>, NodeUid>,
    ) -> Result<Step<C, NodeUid>> {
        let mut step: Step<C, NodeUid> = Step::default();
        let start_epoch = self.start_epoch;
        let output = step.extend_with(hb_step, |hb_msg| Message::HoneyBadger(start_epoch, hb_msg));
        for hb_batch in output {
            // Create the batch we output ourselves. It will contain the _user_ transactions of
            // `hb_batch`, and the current change state.
            let mut batch = Batch::new(hb_batch.epoch + self.start_epoch);

            // Add the user transactions to `batch` and handle votes and DKG messages.
            for (id, int_contrib) in hb_batch.contributions {
                let InternalContrib {
                    votes,
                    key_gen_messages,
                    contrib,
                } = int_contrib;
                step.fault_log
                    .extend(self.vote_counter.add_committed_votes(&id, votes)?);
                batch.contributions.insert(id.clone(), contrib);
                self.key_gen_msg_buffer
                    .retain(|skgm| !key_gen_messages.contains(skgm));
                for SignedKeyGenMsg(epoch, s_id, kg_msg, sig) in key_gen_messages {
                    if epoch < self.start_epoch {
                        info!("Obsolete key generation message: {:?}.", kg_msg);
                        continue;
                    }
                    if !self.verify_signature(&s_id, &sig, &kg_msg)? {
                        info!(
                            "Invalid signature in {:?}'s batch from {:?} for: {:?}.",
                            id, s_id, kg_msg
                        );
                        let fault_kind = FaultKind::InvalidKeyGenMessageSignature;
                        step.fault_log.append(id.clone(), fault_kind);
                        continue;
                    }
                    step.extend(match kg_msg {
                        KeyGenMessage::Part(part) => self.handle_part(&s_id, part)?,
                        KeyGenMessage::Ack(ack) => self.handle_ack(&s_id, ack)?.into(),
                    });
                }
            }

            if let Some(kgs) = self.take_ready_key_gen() {
                // If DKG completed, apply the change, restart Honey Badger, and inform the user.
                debug!("{:?} DKG for {:?} complete!", self.our_id(), kgs.change);
                self.netinfo = kgs.key_gen.into_network_info();
                self.restart_honey_badger(batch.epoch + 1);
                batch.set_change(ChangeState::Complete(kgs.change), &self.netinfo);
            } else if let Some(change) = self.vote_counter.compute_winner().cloned() {
                // If there is a new change, restart DKG. Inform the user about the current change.
                step.extend(self.update_key_gen(batch.epoch + 1, &change)?);
                batch.set_change(ChangeState::InProgress(change), &self.netinfo);
            }
            step.output.push_back(batch);
        }
        // If `start_epoch` changed, we can now handle some queued messages.
        if start_epoch < self.start_epoch {
            let queue = mem::replace(&mut self.incoming_queue, Vec::new());
            for (sender_id, msg) in queue {
                step.extend(self.handle_message(&sender_id, msg)?);
            }
        }
        Ok(step)
    }

    /// If the winner of the vote has changed, restarts Key Generation for the set of nodes implied
    /// by the current change.
    fn update_key_gen(&mut self, epoch: u64, change: &Change<NodeUid>) -> Result<Step<C, NodeUid>> {
        if self.key_gen_state.as_ref().map(|kgs| &kgs.change) == Some(change) {
            return Ok(Step::default()); // The change is the same as before. Continue DKG as is.
        }
        debug!("{:?} Restarting DKG for {:?}.", self.our_id(), change);
        // Use the existing key shares - with the change applied - as keys for DKG.
        let mut pub_keys = self.netinfo.public_key_map().clone();
        if match *change {
            Change::Remove(ref id) => pub_keys.remove(id).is_none(),
            Change::Add(ref id, ref pk) => pub_keys.insert(id.clone(), pk.clone()).is_some(),
        } {
            info!("{:?} No-op change: {:?}", self.our_id(), change);
        }
        self.restart_honey_badger(epoch);
        // TODO: This needs to be the same as `num_faulty` will be in the _new_
        // `NetworkInfo` if the change goes through. It would be safer to deduplicate.
        let threshold = (pub_keys.len() - 1) / 3;
        let sk = self.netinfo.secret_key().clone();
        let our_uid = self.our_id().clone();
        let (key_gen, part) = SyncKeyGen::new(our_uid, sk, pub_keys, threshold);
        self.key_gen_state = Some(KeyGenState::new(key_gen, change.clone()));
        if let Some(part) = part {
            self.send_transaction(KeyGenMessage::Part(part))
        } else {
            Ok(Step::default())
        }
    }

    /// Starts a new `HoneyBadger` instance and resets the vote counter.
    fn restart_honey_badger(&mut self, epoch: u64) {
        self.start_epoch = epoch;
        self.key_gen_msg_buffer.retain(|kg_msg| kg_msg.0 >= epoch);
        let netinfo = Arc::new(self.netinfo.clone());
        let counter = VoteCounter::new(netinfo.clone(), epoch);
        mem::replace(&mut self.vote_counter, counter);
        self.honey_badger = HoneyBadger::builder(netinfo)
            .max_future_epochs(self.max_future_epochs)
            .build();
    }

    /// Handles a `Part` message that was output by Honey Badger.
    fn handle_part(&mut self, sender_id: &NodeUid, part: Part) -> Result<Step<C, NodeUid>> {
        let handle = |kgs: &mut KeyGenState<NodeUid>| kgs.key_gen.handle_part(&sender_id, part);
        match self.key_gen_state.as_mut().and_then(handle) {
            Some(PartOutcome::Valid(ack)) => self.send_transaction(KeyGenMessage::Ack(ack)),
            Some(PartOutcome::Invalid(fault_log)) => Ok(fault_log.into()),
            None => Ok(Step::default()),
        }
    }

    /// Handles an `Ack` message that was output by Honey Badger.
    fn handle_ack(&mut self, sender_id: &NodeUid, ack: Ack) -> Result<FaultLog<NodeUid>> {
        if let Some(kgs) = self.key_gen_state.as_mut() {
            Ok(kgs.key_gen.handle_ack(sender_id, ack))
        } else {
            Ok(FaultLog::new())
        }
    }

    /// Signs and sends a `KeyGenMessage` and also tries to commit it.
    fn send_transaction(&mut self, kg_msg: KeyGenMessage) -> Result<Step<C, NodeUid>> {
        let ser =
            bincode::serialize(&kg_msg).map_err(|err| ErrorKind::SendTransactionBincode(*err))?;
        let sig = Box::new(self.netinfo.secret_key().sign(ser));
        if self.netinfo.is_validator() {
            let our_uid = self.netinfo.our_uid().clone();
            let signed_msg =
                SignedKeyGenMsg(self.start_epoch, our_uid, kg_msg.clone(), *sig.clone());
            self.key_gen_msg_buffer.push(signed_msg);
        }
        let msg = Message::KeyGen(self.start_epoch, kg_msg, sig);
        Ok(Target::All.message(msg).into())
    }

    /// If the current Key Generation process is ready, returns the `KeyGenState`.
    ///
    /// We require the minimum number of completed proposals (`SyncKeyGen::is_ready`) and if a new
    /// node is joining, we require in addition that the new node's proposal is complete. That way
    /// the new node knows that it's key is secret, without having to trust any number of nodes.
    fn take_ready_key_gen(&mut self) -> Option<KeyGenState<NodeUid>> {
        if self
            .key_gen_state
            .as_ref()
            .map_or(false, KeyGenState::is_ready)
        {
            self.key_gen_state.take()
        } else {
            None
        }
    }

    /// Returns `true` if the signature of `kg_msg` by the node with the specified ID is valid.
    /// Returns an error if the payload fails to serialize.
    ///
    /// This accepts signatures from both validators and the currently joining candidate, if any.
    fn verify_signature(
        &self,
        node_id: &NodeUid,
        sig: &Signature,
        kg_msg: &KeyGenMessage,
    ) -> Result<bool> {
        let ser =
            bincode::serialize(kg_msg).map_err(|err| ErrorKind::VerifySignatureBincode(*err))?;
        let get_candidate_key = || {
            self.key_gen_state
                .as_ref()
                .and_then(|kgs| kgs.candidate_key(node_id))
        };
        let pk_opt = self.netinfo.public_key(node_id).or_else(get_candidate_key);
        Ok(pk_opt.map_or(false, |pk| pk.verify(&sig, ser)))
    }
}

/// The contribution for the internal `HoneyBadger` instance: this includes a user-defined
/// application-level contribution as well as internal signed messages.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Hash)]
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
    /// A `SyncKeyGen::Part` message for key generation.
    Part(Part),
    /// A `SyncKeyGen::Ack` message for key generation.
    Ack(Ack),
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
    fn start_epoch(&self) -> u64 {
        match *self {
            Message::HoneyBadger(epoch, _) => epoch,
            Message::KeyGen(epoch, _, _) => epoch,
            Message::SignedVote(ref signed_vote) => signed_vote.era(),
        }
    }

    pub fn epoch(&self) -> u64 {
        match *self {
            Message::HoneyBadger(start_epoch, ref msg) => start_epoch + msg.epoch(),
            Message::KeyGen(epoch, _, _) => epoch,
            Message::SignedVote(ref signed_vote) => signed_vote.era(),
        }
    }
}

/// The information a new node requires to join the network as an observer. It contains the state
/// of voting and key generation after a specific epoch, so that the new node will be in sync if it
/// joins in the next one.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinPlan<NodeUid: Ord> {
    /// The first epoch the new node will observe.
    epoch: u64,
    /// The current change. If `InProgress`, key generation for it is beginning at `epoch`.
    change: ChangeState<NodeUid>,
    /// The current public key set for threshold cryptography.
    pub_key_set: PublicKeySet,
    /// The public keys of the nodes taking part in key generation.
    pub_keys: BTreeMap<NodeUid, PublicKey>,
}

/// The ongoing key generation, together with information about the validator change.
#[derive(Debug)]
struct KeyGenState<NodeUid> {
    /// The key generation instance.
    key_gen: SyncKeyGen<NodeUid>,
    /// The change for which key generation is performed.
    change: Change<NodeUid>,
    /// The number of key generation messages received from the candidate. At most _N² + 1_ are
    /// accepted.
    candidate_msg_count: usize,
}

impl<NodeUid: Ord + Clone + Debug> KeyGenState<NodeUid> {
    fn new(key_gen: SyncKeyGen<NodeUid>, change: Change<NodeUid>) -> Self {
        KeyGenState {
            key_gen,
            change,
            candidate_msg_count: 0,
        }
    }

    /// Returns `true` if the candidate's, if any, as well as enough validators' key generation
    /// parts have been completed.
    fn is_ready(&self) -> bool {
        let candidate_ready = |id: &NodeUid| self.key_gen.is_node_ready(id);
        self.key_gen.is_ready() && self.change.candidate().map_or(true, candidate_ready)
    }

    /// If the node `node_id` is the currently joining candidate, returns its public key.
    fn candidate_key(&self, node_id: &NodeUid) -> Option<&PublicKey> {
        match self.change {
            Change::Add(ref id, ref pk) if id == node_id => Some(pk),
            Change::Add(_, _) | Change::Remove(_) => None,
        }
    }
}
