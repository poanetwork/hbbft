use std::collections::BTreeMap;
use std::sync::Arc;
use std::{fmt, mem};

use bincode;
use crypto::Signature;
use rand::{self, Rand};
use serde::{Deserialize, Serialize};

use super::votes::{SignedVote, VoteCounter};
use super::{
    Batch, Change, ChangeState, DynamicHoneyBadgerBuilder, Error, ErrorKind, Input,
    InternalContrib, KeyGenMessage, KeyGenState, Message, NodeChange, Result, SignedKeyGenMsg,
    Step,
};
use fault_log::{Fault, FaultKind, FaultLog};
use honey_badger::{self, HoneyBadger, Message as HbMessage};
use sync_key_gen::{Ack, Part, PartOutcome, SyncKeyGen};
use threshold_decryption::EncryptionSchedule;
use util::SubRng;
use {Contribution, DistAlgorithm, NetworkInfo, NodeIdT, Target};

/// A Honey Badger instance that can handle adding and removing nodes.
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
    /// A queue for messages from future epochs that cannot be handled yet.
    pub(super) incoming_queue: Vec<(N, Message<N>)>,
    /// A random number generator used for secret key generation.
    // Boxed to avoid overloading the algorithm's type with more generics.
    pub(super) rng: Box<dyn rand::Rng + Send + Sync>,
}

impl<C, N> fmt::Debug for DynamicHoneyBadger<C, N>
where
    C: fmt::Debug,
    N: Rand + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DynamicHoneyBadger")
            .field("netinfo", &self.netinfo)
            .field("max_future_epochs", &self.max_future_epochs)
            .field("start_epoch", &self.start_epoch)
            .field("vote_counter", &self.vote_counter)
            .field("key_gen_msg_buffer", &self.key_gen_msg_buffer)
            .field("honey_badger", &self.honey_badger)
            .field("key_gen_state", &self.key_gen_state)
            .field("incoming_queue", &self.incoming_queue)
            .field("rng", &"<RNG>")
            .finish()
    }
}

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
        match input {
            Input::User(contrib) => self.propose(contrib),
            Input::Change(change) => self.vote_for(change),
        }
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> Result<Step<C, N>> {
        self.handle_message(sender_id, message)
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

    /// Proposes a contribution in the current epoch.
    pub fn propose(&mut self, contrib: C) -> Result<Step<C, N>> {
        let key_gen_messages = self
            .key_gen_msg_buffer
            .iter()
            .filter(|kg_msg| kg_msg.epoch() == self.start_epoch)
            .cloned()
            .collect();
        let step = self
            .honey_badger
            .handle_input(InternalContrib {
                contrib,
                key_gen_messages,
                votes: self.vote_counter.pending_votes().cloned().collect(),
            }).map_err(ErrorKind::ProposeHoneyBadger)?;
        self.process_output(step)
    }

    /// Casts a vote to change the set of validators.
    pub fn vote_for(&mut self, change: Change<N>) -> Result<Step<C, N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default()); // TODO: Return an error?
        }
        let signed_vote = self.vote_counter.sign_vote_for(change)?.clone();
        let msg = Message::SignedVote(signed_vote);
        Ok(Target::All.message(msg).into())
    }

    /// Handles an incoming message.
    pub fn handle_message(&mut self, sender_id: &N, message: Message<N>) -> Result<Step<C, N>> {
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

        // If the sender is correct, it will send at most _N + 1_ key generation messages:
        // one `Part`, and for each validator an `Ack`. _N_ is the node number _after_ the change.
        if kgs.count_messages(sender_id) > kgs.key_gen.num_nodes() + 1 {
            let fault_kind = FaultKind::TooManyKeyGenMessages;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }

        let tx = SignedKeyGenMsg(self.start_epoch, sender_id.clone(), kg_msg, sig);
        self.key_gen_msg_buffer.push(tx);
        Ok(FaultLog::default())
    }

    /// Processes all pending batches output by Honey Badger.
    fn process_output(
        &mut self,
        hb_step: honey_badger::Step<InternalContrib<C, N>, N>,
    ) -> Result<Step<C, N>> {
        let mut step: Step<C, N> = Step::default();
        let start_epoch = self.start_epoch;
        let output = step.extend_with(hb_step, |hb_msg| Message::HoneyBadger(start_epoch, hb_msg));
        for hb_batch in output {
            let batch_epoch = hb_batch.epoch + self.start_epoch;
            let mut batch_contributions = BTreeMap::new();

            // Add the user transactions to `batch` and handle votes and DKG messages.
            for (id, int_contrib) in hb_batch.contributions {
                let InternalContrib {
                    votes,
                    key_gen_messages,
                    contrib,
                } = int_contrib;
                step.fault_log
                    .extend(self.vote_counter.add_committed_votes(&id, votes)?);
                batch_contributions.insert(id.clone(), contrib);
                self.key_gen_msg_buffer
                    .retain(|skgm| !key_gen_messages.contains(skgm));
                for SignedKeyGenMsg(epoch, s_id, kg_msg, sig) in key_gen_messages {
                    if epoch != self.start_epoch {
                        let fault_kind = FaultKind::InvalidKeyGenMessageEpoch;
                        step.fault_log.append(id.clone(), fault_kind);
                    } else if !self.verify_signature(&s_id, &sig, &kg_msg)? {
                        let fault_kind = FaultKind::InvalidKeyGenMessageSignature;
                        step.fault_log.append(id.clone(), fault_kind);
                    } else {
                        step.extend(match kg_msg {
                            KeyGenMessage::Part(part) => self.handle_part(&s_id, part)?,
                            KeyGenMessage::Ack(ack) => self.handle_ack(&s_id, ack)?.into(),
                        });
                    }
                }
            }

            let change = if let Some(kgs) = self.take_ready_key_gen() {
                // If DKG completed, apply the change, restart Honey Badger, and inform the user.
                debug!("{:?} DKG for {:?} complete!", self.our_id(), kgs.change);
                self.netinfo = kgs.key_gen.into_network_info()?;
                self.restart_honey_badger(batch_epoch + 1, None);
                ChangeState::Complete(Change::NodeChange(kgs.change))
            } else if let Some(change) = self.vote_counter.compute_winner().cloned() {
                // If there is a new change, restart DKG. Inform the user about the current change.
                step.extend(match &change {
                    Change::NodeChange(change) => self.update_key_gen(batch_epoch + 1, &change)?,
                    Change::EncryptionSchedule(schedule) => {
                        self.update_encryption_schedule(batch_epoch + 1, *schedule)?
                    }
                });
                ChangeState::InProgress(change)
            } else {
                ChangeState::None
            };
            step.output.push_back(Batch {
                epoch: batch_epoch,
                change,
                netinfo: Arc::new(self.netinfo.clone()),
                contributions: batch_contributions,
            });
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

    pub(super) fn update_encryption_schedule(
        &mut self,
        epoch: u64,
        encryption_schedule: EncryptionSchedule,
    ) -> Result<Step<C, N>> {
        self.restart_honey_badger(epoch, Some(encryption_schedule));
        Ok(Step::default())
    }

    /// If the winner of the vote has changed, restarts Key Generation for the set of nodes implied
    /// by the current change.
    pub(super) fn update_key_gen(
        &mut self,
        epoch: u64,
        change: &NodeChange<N>,
    ) -> Result<Step<C, N>> {
        if self.key_gen_state.as_ref().map(|kgs| &kgs.change) == Some(change) {
            return Ok(Step::default()); // The change is the same as before. Continue DKG as is.
        }
        debug!("{:?} Restarting DKG for {:?}.", self.our_id(), change);
        // Use the existing key shares - with the change applied - as keys for DKG.
        let mut pub_keys = self.netinfo.public_key_map().clone();
        if match *change {
            NodeChange::Remove(ref id) => pub_keys.remove(id).is_none(),
            NodeChange::Add(ref id, ref pk) => pub_keys.insert(id.clone(), pk.clone()).is_some(),
        } {
            info!("{:?} No-op change: {:?}", self.our_id(), change);
        }
        self.restart_honey_badger(epoch, None);
        // TODO: This needs to be the same as `num_faulty` will be in the _new_
        // `NetworkInfo` if the change goes through. It would be safer to deduplicate.
        let threshold = (pub_keys.len() - 1) / 3;
        let sk = self.netinfo.secret_key().clone();
        let our_id = self.our_id().clone();
        let (key_gen, part) = SyncKeyGen::new(&mut self.rng, our_id, sk, pub_keys, threshold)?;
        self.key_gen_state = Some(KeyGenState::new(key_gen, change.clone()));
        if let Some(part) = part {
            self.send_transaction(KeyGenMessage::Part(part))
        } else {
            Ok(Step::default())
        }
    }

    /// Starts a new `HoneyBadger` instance and resets the vote counter.
    fn restart_honey_badger(
        &mut self,
        epoch: u64,
        encryption_schedule: Option<EncryptionSchedule>,
    ) {
        self.start_epoch = epoch;
        self.key_gen_msg_buffer.retain(|kg_msg| kg_msg.0 >= epoch);
        let netinfo = Arc::new(self.netinfo.clone());
        self.vote_counter = VoteCounter::new(netinfo.clone(), epoch);
        self.honey_badger = HoneyBadger::builder(netinfo)
            .max_future_epochs(self.max_future_epochs)
            .rng(self.rng.sub_rng())
            .encryption_schedule(if let Some(schedule) = encryption_schedule {
                schedule
            } else {
                self.honey_badger.encryption_schedule
            }).build();
    }

    /// Handles a `Part` message that was output by Honey Badger.
    fn handle_part(&mut self, sender_id: &N, part: Part) -> Result<Step<C, N>> {
        let outcome = if let Some(kgs) = self.key_gen_state.as_mut() {
            kgs.key_gen.handle_part(&mut self.rng, &sender_id, part)
        } else {
            // No key generation ongoing.
            let fault_kind = FaultKind::UnexpectedKeyGenPart;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        };

        match outcome {
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
            // No key generation ongoing.
            let fault_kind = FaultKind::UnexpectedKeyGenAck;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
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
        let msg = Message::KeyGen(self.start_epoch, kg_msg, sig);
        Ok(Target::All.message(msg).into())
    }

    /// If the current Key Generation process is ready, returns the `KeyGenState`.
    ///
    /// We require the minimum number of completed proposals (`SyncKeyGen::is_ready`) and if a new
    /// node is joining, we require in addition that the new node's proposal is complete. That way
    /// the new node knows that it's key is secret, without having to trust any number of nodes.
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
}
