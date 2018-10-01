use std::collections::btree_map;
use std::collections::BTreeMap;
use std::mem;
use std::sync::Arc;

use bincode;
use crypto::Signature;
use rand::Rand;
use serde::{Deserialize, Serialize};

use super::votes::{SignedVote, VoteCounter};
use super::{
    Batch, Change, ChangeState, DynamicEpoch, DynamicHoneyBadgerBuilder, Error, ErrorKind, Input,
    InternalContrib, KeyGenMessage, KeyGenState, Message, MessageContent, Result, SignedKeyGenMsg,
};
use fault_log::{Fault, FaultKind, FaultLog};
use honey_badger::{self, HoneyBadger, Message as HbMessage};
use messaging::{self, DistAlgorithm, Epoched, NetworkInfo, Target, TargetedMessage};
use sync_key_gen::{Ack, Part, PartOutcome, SyncKeyGen};
use traits::{Contribution, NodeIdT};

/// A Honey Badger instance that can handle adding and removing nodes.
#[derive(Debug)]
pub struct DynamicHoneyBadger<C, N: Rand> {
    /// Shared network data.
    pub(super) netinfo: NetworkInfo<N>,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    pub(super) max_future_epochs: usize,
    /// The first epoch after the latest node change.
    pub(super) start_epoch: u64,
    /// The buffer and counter for the pending and committed change votes.
    pub(super) vote_counter: VoteCounter<N>,
    /// Pending node transactions that we will propose in the next epoch.
    pub(super) key_gen_msg_buffer: Vec<SignedKeyGenMsg<N>>,
    /// The `HoneyBadger` instance with the current set of nodes.
    pub(super) honey_badger: HoneyBadger<InternalContrib<C, N>, N>,
    /// The current key generation process, and the change it applies to.
    pub(super) key_gen_state: Option<KeyGenState<N>>,
    /// `HoneyBadger` messages that couldn't be handled yet by remote nodes. Each key to the map
    /// contains the target node ID, the Dynamic Honey Badger start epoch and the embedded Honey
    /// Badger epoch of a vector of messages stored as the value of that key.
    pub(super) outgoing_queue_hb: BTreeMap<(N, DynamicEpoch), Vec<Message<N>>>,
    /// Messages created by `DynamicHoneyBadger` that cannot be handled yet by remove nodes. The
    /// keys are pairs of the node ID and the start epoch.
    pub(super) outgoing_queue_dhb: BTreeMap<(N, u64), Vec<Message<N>>>,
    /// Known current epochs of remote nodes.
    pub(super) remote_epochs: BTreeMap<N, DynamicEpoch>,
    /// The node which is being added using a `Change::Add` command. The command should be is ongoing.
    pub(super) node_being_added: Option<N>,
}

pub type Step<C, N> = messaging::Step<DynamicHoneyBadger<C, N>>;

impl<C, N> DistAlgorithm for DynamicHoneyBadger<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeIdT + Serialize + for<'r> Deserialize<'r> + Rand,
{
    type NodeId = N;
    type Input = Input<C, N>;
    type Output = Batch<C, N>;
    type Message = Message<N>;
    type Error = Error;

    fn handle_input(&mut self, input: Self::Input) -> Result<Step<C, N>> {
        // User contributions are forwarded to `HoneyBadger` right away. Votes are signed and
        // broadcast.
        let mut step = match input {
            Input::User(contrib) => self.propose(contrib),
            Input::Change(change) => self.vote_for(change),
        }?;
        self.defer_messages(&mut step);
        Ok(step)
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> Result<Step<C, N>> {
        let mut step = match message {
            Message::DynamicHoneyBadger(content) => self.handle_message_content(sender_id, content),
            Message::DynamicEpochStarted(epoch) => {
                self.handle_dynamic_epoch_started(sender_id, epoch)
            }
        }?;
        debug!(
            "{:?}@{} outgoing DHB messages {:?} --- queued DHB messages: {:?} --- queued HB messages: {:?} --- remote epochs: {:?}",
            self.netinfo.our_id(),
            self.start_epoch,
            step.messages,
            self.outgoing_queue_dhb,
            self.outgoing_queue_hb,
            self.remote_epochs
        );
        self.defer_messages(&mut step);
        Ok(step)
    }

    fn terminated(&self) -> bool {
        false
    }

    fn our_id(&self) -> &N {
        self.netinfo.our_id()
    }
}

impl<C, N> DynamicHoneyBadger<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeIdT + Serialize + for<'r> Deserialize<'r> + Rand,
{
    /// Returns a new `DynamicHoneyBadgerBuilder`.
    pub fn builder() -> DynamicHoneyBadgerBuilder<C, N> {
        DynamicHoneyBadgerBuilder::new()
    }

    /// Returns `true` if input for the current epoch has already been provided.
    pub fn has_input(&self) -> bool {
        self.honey_badger.has_input()
    }

    /// Handles a Dynamic Honey Badger algorithm message.
    pub fn handle_message_content(
        &mut self,
        sender_id: &N,
        content: MessageContent<N>,
    ) -> Result<Step<C, N>> {
        let start_epoch = content.start_epoch();
        if start_epoch != self.start_epoch {
            // Message epoch is out of range.
            warn!(
                "{:?}@{} discarded {:?}@{}:{:?}",
                self.netinfo.our_id(),
                self.start_epoch,
                sender_id,
                start_epoch,
                content,
            );
            return Ok(Fault::new(sender_id.clone(), FaultKind::EpochOutOfRange).into());
        }
        match content {
            MessageContent::HoneyBadger(_, hb_msg) => {
                self.handle_honey_badger_message(sender_id, hb_msg)
            }
            MessageContent::KeyGen(_, kg_msg, sig) => self
                .handle_key_gen_message(sender_id, kg_msg, *sig)
                .map(FaultLog::into),
            MessageContent::SignedVote(signed_vote) => self
                .vote_counter
                .add_pending_vote(sender_id, signed_vote)
                .map(FaultLog::into),
        }
    }

    /// Handles an epoch start announcement from a remote `DynamicHoneyBadger`.
    fn handle_dynamic_epoch_started(
        &mut self,
        sender_id: &N,
        epoch: DynamicEpoch,
    ) -> Result<Step<C, N>> {
        debug!(
            "{:?}@{} received epoch {:?}@{:?}",
            self.netinfo.our_id(),
            self.start_epoch,
            sender_id,
            epoch,
        );
        let mut obsolete = false;
        self.remote_epochs
            .entry(sender_id.clone())
            .and_modify(|e| {
                if *e < epoch {
                    // Increment the epoch.
                    *e = epoch;
                } else if *e >= epoch {
                    obsolete = true;
                }
            }).or_insert(epoch);
        if obsolete {
            return Err(ErrorKind::ObsoleteDynamicEpochStarted.into());
        }
        let step = self.process_new_epoch(sender_id, epoch);
        self.remove_messages_upto(sender_id, epoch);
        step
    }

    /// Processes an announcement of a new epoch update received from a remote node.
    fn process_new_epoch(&mut self, sender_id: &N, epoch: DynamicEpoch) -> Result<Step<C, N>> {
        // Send any DHB messages for `epoch.start_epoch`.
        let mut ready_messages = self
            .outgoing_queue_dhb
            .remove(&(sender_id.clone(), epoch.start_epoch))
            .unwrap_or_else(|| vec![]);
        // Send any HB messages for `epoch`.
        ready_messages.extend(
            self.outgoing_queue_hb
                .remove(&(sender_id.clone(), epoch))
                .unwrap_or_else(|| vec![]),
        );
        let mut step = Step::from(
            ready_messages
                .into_iter()
                .map(|msg| Target::Node(sender_id.clone()).message(msg)),
        );
        if epoch.start_epoch == self.start_epoch {
            // Forward `hb_epoch` to `HoneyBadger` if the `DynamicHoneyBadger` start epochs
            // match. Any queued messages are stored in the `HoneyBadger` instance.
            let hb_step = self
                .honey_badger
                .handle_message(sender_id, HbMessage::EpochStarted(epoch.hb_epoch))
                .map_err(ErrorKind::DynamicEpochStarted)?;
            step.extend(self.process_output(hb_step)?);
        }
        Ok(step)
    }

    /// Removes all messages queued for the remote node from epochs upto `epoch`.
    fn remove_messages_upto(&mut self, sender_id: &N, epoch: DynamicEpoch) {
        let earlier_keys_hb: Vec<_> = self
            .outgoing_queue_hb
            .keys()
            .cloned()
            .filter(|(id, e)| {
                id == sender_id
                    && (e.start_epoch < epoch.start_epoch
                        || (e.start_epoch == epoch.start_epoch && e.hb_epoch <= epoch.hb_epoch))
            }).collect();
        for key in earlier_keys_hb {
            self.outgoing_queue_hb.remove(&key);
        }
        let earlier_keys_dhb: Vec<_> = self
            .outgoing_queue_dhb
            .keys()
            .cloned()
            .filter(|(id, e)| id == sender_id && *e <= epoch.start_epoch)
            .collect();
        for key in earlier_keys_dhb {
            self.outgoing_queue_dhb.remove(&key);
        }
    }

    /// Proposes a contribution in the current epoch.
    pub fn propose(&mut self, contrib: C) -> Result<Step<C, N>> {
        let step = self
            .honey_badger
            .handle_input(InternalContrib {
                contrib,
                key_gen_messages: self.key_gen_msg_buffer.clone(),
                votes: self.vote_counter.pending_votes().cloned().collect(),
            }).map_err(ErrorKind::ProposeHoneyBadger)?;
        self.process_output(step)
    }

    /// Cast a vote to change the set of validators.
    pub fn vote_for(&mut self, change: Change<N>) -> Result<Step<C, N>> {
        info!(
            "{:?}, {}being a validator, is voting for {:?}",
            self.netinfo.our_id(),
            if self.netinfo.is_validator() {
                ""
            } else {
                "not "
            },
            change
        );
        if let Change::Add(ref id, ..) = change {
            self.set_node_being_added(id)?;
        }
        if !self.netinfo.is_validator() {
            return Ok(Step::default()); // TODO: Return an error?
        }
        let signed_vote = self.vote_counter.sign_vote_for(change)?.clone();
        let msg = Message::DynamicHoneyBadger(MessageContent::SignedVote(signed_vote));
        Ok(Target::All.message(msg).into())
    }

    /// Returns the information about the node IDs in the network, and the cryptographic keys.
    pub fn netinfo(&self) -> &NetworkInfo<N> {
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
        sender_id: &N,
        message: HbMessage<N>,
    ) -> Result<Step<C, N>> {
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
        sender_id: &N,
        kg_msg: KeyGenMessage,
        sig: Signature,
    ) -> Result<FaultLog<N>> {
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

    /// Processes all pending batches output by Honey Badger and annotates epoch update
    /// announcements with the Dynamic Honey Badger start epoch.
    pub(super) fn process_output(
        &mut self,
        hb_step: honey_badger::Step<InternalContrib<C, N>, N>,
    ) -> Result<Step<C, N>> {
        let mut step: Step<C, N> = Step::default();
        let output = step.extend_with(hb_step, |hb_msg| from_hb_message(hb_msg, self.start_epoch));
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
                debug!(
                    "{:?}@{} DKG for {:?} complete!",
                    self.our_id(),
                    self.start_epoch,
                    kgs.change
                );
                if let Change::Add(ref id, ..) = kgs.change {
                    if let Some(ref add_id) = self.node_being_added {
                        if add_id != id {
                            return Err(ErrorKind::AddedNodeDiffersFromProposed.into());
                        }
                    } else {
                        return Err(ErrorKind::NoNodeBeingAdded.into());
                    }
                    self.node_being_added = None;
                }
                self.netinfo = kgs.key_gen.into_network_info()?;
                step.extend(self.restart_honey_badger(batch.epoch + 1)?);
                batch.set_change(ChangeState::Complete(kgs.change), &self.netinfo);
            } else if let Some(change) = self.vote_counter.compute_winner().cloned() {
                // If there is a new change, restart DKG. Inform the user about the current change.
                step.extend(self.update_key_gen(batch.epoch + 1, &change)?);
                batch.set_change(ChangeState::InProgress(change), &self.netinfo);
            }
            step.output.push_back(batch);
        }
        Ok(step)
    }

    /// If the winner of the vote has changed, restarts Key Generation for the set of nodes implied
    /// by the current change.
    pub(super) fn update_key_gen(&mut self, epoch: u64, change: &Change<N>) -> Result<Step<C, N>> {
        if self.key_gen_state.as_ref().map(|kgs| &kgs.change) == Some(change) {
            return Ok(Step::default()); // The change is the same as before. Continue DKG as is.
        }
        debug!(
            "{:?}@{} Restarting DKG for {:?}.",
            self.our_id(),
            self.start_epoch,
            change
        );
        // Use the existing key shares - with the change applied - as keys for DKG.
        let mut pub_keys = self.netinfo.public_key_map().clone();
        if match *change {
            Change::Remove(ref id) => pub_keys.remove(id).is_none(),
            Change::Add(ref id, ref pk) => {
                self.set_node_being_added(id)?;
                pub_keys.insert(id.clone(), pk.clone()).is_some()
            }
        } {
            info!("{:?} No-op change: {:?}", self.our_id(), change);
        }
        let mut step = self.restart_honey_badger(epoch)?;
        // TODO: This needs to be the same as `num_faulty` will be in the _new_
        // `NetworkInfo` if the change goes through. It would be safer to deduplicate.
        let threshold = (pub_keys.len() - 1) / 3;
        let sk = self.netinfo.secret_key().clone();
        let our_id = self.our_id().clone();
        let (key_gen, part) = SyncKeyGen::new(our_id, sk, pub_keys, threshold)?;
        self.key_gen_state = Some(KeyGenState::new(key_gen, change.clone()));
        if let Some(part) = part {
            step.extend(self.send_transaction(KeyGenMessage::Part(part))?);
        }
        Ok(step)
    }

    /// Sets the node  which is currently being added as validator.
    fn set_node_being_added(&mut self, id: &N) -> Result<()> {
        let mut add = false;
        if let Some(ref add_id) = self.node_being_added {
            if add_id != id {
                return Err(ErrorKind::AddedNodeDiffersFromProposed.into());
            }
        } else {
            add = true;
        }
        if add {
            self.node_being_added = Some(id.clone());
        }
        Ok(())
    }

    /// Moves queued messages from Honey Badger to Dynamic Honey Badger.
    fn move_queued_hb_messages(&mut self) {
        for (key, hb_msgs) in self.honey_badger.outgoing_queue() {
            let (id, hb_epoch) = key;
            for hb_msg in hb_msgs.drain(..) {
                let msg = from_hb_message(hb_msg, self.start_epoch);
                let e = self
                    .outgoing_queue_hb
                    .entry((id.clone(), DynamicEpoch::new(self.start_epoch, *hb_epoch)));
                match e {
                    btree_map::Entry::Occupied(e) => {
                        e.into_mut().push(msg);
                    }
                    btree_map::Entry::Vacant(e) => {
                        e.insert(vec![msg]);
                    }
                }
            }
        }
    }

    /// Starts a new `HoneyBadger` instance and resets the vote counter.
    fn restart_honey_badger(&mut self, epoch: u64) -> Result<Step<C, N>> {
        self.move_queued_hb_messages();
        self.start_epoch = epoch;
        self.key_gen_msg_buffer.retain(|kg_msg| kg_msg.0 >= epoch);
        let netinfo = Arc::new(self.netinfo.clone());
        let counter = VoteCounter::new(netinfo.clone(), epoch);
        mem::replace(&mut self.vote_counter, counter);
        let (hb, hb_step) = HoneyBadger::builder(netinfo)
            .max_future_epochs(self.max_future_epochs)
            .node_being_added(self.node_being_added.clone())
            .build();
        self.honey_badger = hb;
        self.process_output(hb_step)
    }

    /// Handles a `Part` message that was output by Honey Badger.
    fn handle_part(&mut self, sender_id: &N, part: Part) -> Result<Step<C, N>> {
        let handle = |kgs: &mut KeyGenState<N>| kgs.key_gen.handle_part(&sender_id, part);
        match self.key_gen_state.as_mut().and_then(handle) {
            Some(PartOutcome::Valid(ack)) => self.send_transaction(KeyGenMessage::Ack(ack)),
            Some(PartOutcome::Invalid(fault_log)) => Ok(fault_log.into()),
            None => Ok(Step::default()),
        }
    }

    /// Handles an `Ack` message that was output by Honey Badger.
    fn handle_ack(&mut self, sender_id: &N, ack: Ack) -> Result<FaultLog<N>> {
        if let Some(kgs) = self.key_gen_state.as_mut() {
            Ok(kgs.key_gen.handle_ack(sender_id, ack))
        } else {
            Ok(FaultLog::new())
        }
    }

    /// Signs and sends a `KeyGenMessage` and also tries to commit it.
    fn send_transaction(&mut self, kg_msg: KeyGenMessage) -> Result<Step<C, N>> {
        let ser =
            bincode::serialize(&kg_msg).map_err(|err| ErrorKind::SendTransactionBincode(*err))?;
        let sig = Box::new(self.netinfo.secret_key().sign(ser));
        if self.netinfo.is_validator() {
            let our_id = self.netinfo.our_id().clone();
            let signed_msg =
                SignedKeyGenMsg(self.start_epoch, our_id, kg_msg.clone(), *sig.clone());
            self.key_gen_msg_buffer.push(signed_msg);
        }
        let msg =
            Message::DynamicHoneyBadger(MessageContent::KeyGen(self.start_epoch, kg_msg, sig));
        Ok(Target::All.message(msg).into())
    }

    /// If the current Key Generation process is ready, returns the `KeyGenState`.
    ///
    /// We require the minimum number of completed proposals (`SyncKeyGen::is_ready`) and if a new
    /// node is joining, we require in addition that the new node's proposal is complete. That way
    /// the new node knows that its key is secret, without having to trust any number of nodes.
    fn take_ready_key_gen(&mut self) -> Option<KeyGenState<N>> {
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
        node_id: &N,
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

    /// Removes any messages to nodes at earlier epochs from the given `Step`. This may involve
    /// decomposing a `Target::All` message into `Target::Node` messages and sending some of the
    /// resulting messages while placing onto the queue those remaining messages whose recipient is
    /// currently at an earlier epoch.
    fn defer_messages(&mut self, step: &mut Step<C, N>) {
        let max_future_epochs = self.max_future_epochs;
        let is_accepting_epoch = |us: &Message<N>, them: DynamicEpoch| {
            let our_epoch = us.epoch();
            our_epoch.start_epoch == them.start_epoch
                && (us.is_dynamic()
                    || (our_epoch.hb_epoch >= them.hb_epoch
                        && our_epoch.hb_epoch <= them.hb_epoch + max_future_epochs as u64))
        };
        let is_later_epoch = |us: &Message<N>, them: DynamicEpoch| {
            let our_epoch = us.epoch();
            our_epoch.start_epoch < them.start_epoch
                || (them.start_epoch == our_epoch.start_epoch
                    && !us.is_dynamic()
                    && our_epoch.hb_epoch < them.hb_epoch)
        };
        let remote_epochs = &self.remote_epochs;
        let is_passed_unchanged = |msg: &TargetedMessage<_, _>| match &msg.message {
            Message::DynamicHoneyBadger(..) => {
                let pass = |&them: &DynamicEpoch| is_accepting_epoch(&msg.message, them);
                match &msg.target {
                    Target::All => remote_epochs.values().all(pass),
                    Target::Node(id) => remote_epochs.get(&id).map_or(false, pass),
                }
            }
            Message::DynamicEpochStarted(_) => true,
        };
        let our_id = self.netinfo.our_id();
        let all_remote_nodes = self
            .netinfo
            .all_ids()
            .chain(self.node_being_added.iter())
            .filter(|&id| id != our_id)
            .into_iter();
        let deferred_msgs = step.defer_messages(
            &self.remote_epochs,
            all_remote_nodes,
            is_accepting_epoch,
            is_later_epoch,
            is_passed_unchanged,
        );
        // Append the deferred messages onto the queues.
        for (id, message) in deferred_msgs {
            let epoch = message.epoch();
            if message.is_dynamic() {
                self.outgoing_queue_dhb
                    .entry((id, epoch.start_epoch))
                    .and_modify(|e| e.push(message.clone()))
                    .or_insert_with(|| vec![message.clone()]);
            } else {
                self.outgoing_queue_hb
                    .entry((id, epoch))
                    .and_modify(|e| e.push(message.clone()))
                    .or_insert_with(|| vec![message.clone()]);
            }
        }
        debug!(
            "{:?}: node being added is {:?}",
            self.netinfo.our_id(),
            self.node_being_added
        );
    }
}

/// Maps HB messages to DHB messages.
fn from_hb_message<N>(hb_msg: honey_badger::Message<N>, start_epoch: u64) -> Message<N>
where
    N: Rand,
{
    match hb_msg {
        HbMessage::EpochStarted(hb_epoch) => {
            Message::DynamicEpochStarted(DynamicEpoch::new(start_epoch, hb_epoch))
        }
        msg => Message::DynamicHoneyBadger(MessageContent::HoneyBadger(start_epoch, msg)),
    }
}
