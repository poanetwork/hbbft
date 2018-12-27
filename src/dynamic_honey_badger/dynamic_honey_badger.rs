use std::collections::BTreeMap;
use std::sync::Arc;
use std::{fmt, result};

use crate::crypto::{PublicKey, SecretKey, Signature};
use bincode;
use derivative::Derivative;
use log::debug;
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};

use super::votes::{SignedVote, VoteCounter};
use super::{
    Batch, Change, ChangeState, DynamicHoneyBadgerBuilder, EncryptionSchedule, Error, FaultKind,
    Input, InternalContrib, JoinPlan, KeyGenMessage, KeyGenState, Message, Params, Result,
    SignedKeyGenMsg, Step,
};
use crate::fault_log::{Fault, FaultLog};
use crate::honey_badger::{self, HoneyBadger, Message as HbMessage};

use crate::sync_key_gen::{Ack, AckOutcome, Part, PartOutcome, SyncKeyGen};
use crate::util;
use crate::{Contribution, DistAlgorithm, Epoched, NetworkInfo, NodeIdT, Target};

/// A Honey Badger instance that can handle adding and removing nodes.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct DynamicHoneyBadger<C, N: Ord> {
    /// Shared network data.
    pub(super) netinfo: NetworkInfo<N>,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    pub(super) max_future_epochs: u64,
    /// The first epoch after the latest node change.
    pub(super) era: u64,
    /// The buffer and counter for the pending and committed change votes.
    pub(super) vote_counter: VoteCounter<N>,
    /// Pending node transactions that we will propose in the next epoch.
    pub(super) key_gen_msg_buffer: Vec<SignedKeyGenMsg<N>>,
    /// The `HoneyBadger` instance with the current set of nodes.
    pub(super) honey_badger: HoneyBadger<InternalContrib<C, N>, N>,
    /// The current key generation process, and the change it applies to.
    pub(super) key_gen_state: Option<KeyGenState<N>>,
}

impl<C, N> DistAlgorithm for DynamicHoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned,
{
    type NodeId = N;
    type Input = Input<C, N>;
    type Output = Batch<C, N>;
    type Message = Message<N>;
    type Error = Error;
    type FaultKind = FaultKind;

    fn handle_input<R: Rng>(&mut self, input: Self::Input, rng: &mut R) -> Result<Step<C, N>> {
        // User contributions are forwarded to `HoneyBadger` right away. Votes are signed and
        // broadcast.
        match input {
            Input::User(contrib) => self.propose(contrib, rng),
            Input::Change(change) => self.vote_for(change),
        }
    }

    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &Self::NodeId,
        msg: Self::Message,
        rng: &mut R,
    ) -> Result<Step<C, N>> {
        self.handle_message(sender_id, msg, rng)
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
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned,
{
    /// Returns a new `DynamicHoneyBadgerBuilder`.
    pub fn builder() -> DynamicHoneyBadgerBuilder<C, N> {
        DynamicHoneyBadgerBuilder::new()
    }

    /// Creates a new `DynamicHoneyBadger` ready to join the network specified in the `JoinPlan`.
    pub fn new_joining<R: Rng>(
        our_id: N,
        secret_key: SecretKey,
        join_plan: JoinPlan<N>,
        rng: &mut R,
    ) -> Result<(Self, Step<C, N>)> {
        let netinfo = NetworkInfo::new(
            our_id,
            None,
            join_plan.pub_key_set,
            secret_key,
            join_plan.pub_keys,
        );
        let max_future_epochs = join_plan.params.max_future_epochs;
        let arc_netinfo = Arc::new(netinfo.clone());
        let honey_badger = HoneyBadger::builder(arc_netinfo.clone())
            .session_id(join_plan.era)
            .params(join_plan.params)
            .build();
        let mut dhb = DynamicHoneyBadger {
            netinfo,
            max_future_epochs,
            era: join_plan.era,
            vote_counter: VoteCounter::new(arc_netinfo, join_plan.era),
            key_gen_msg_buffer: Vec::new(),
            honey_badger,
            key_gen_state: None,
        };
        let step = match join_plan.change {
            ChangeState::InProgress(ref change) => match change {
                Change::NodeChange(change) => dhb.update_key_gen(join_plan.era, change, rng)?,
                _ => Step::default(),
            },
            ChangeState::None | ChangeState::Complete(..) => Step::default(),
        };
        Ok((dhb, step))
    }

    /// Returns `true` if input for the current epoch has already been provided.
    pub fn has_input(&self) -> bool {
        self.honey_badger.has_input()
    }

    /// Proposes a contribution in the current epoch.
    ///
    /// Returns an error if we already made a proposal in this epoch.
    ///
    /// If we are the only validator, this will immediately output a batch, containing our
    /// proposal.
    pub fn propose<R: Rng>(&mut self, contrib: C, rng: &mut R) -> Result<Step<C, N>> {
        let key_gen_messages = self
            .key_gen_msg_buffer
            .iter()
            .filter(|kg_msg| kg_msg.era() == self.era)
            .cloned()
            .collect();

        let contrib = InternalContrib {
            contrib,
            key_gen_messages,
            votes: self.vote_counter.pending_votes().cloned().collect(),
        };

        let step = self
            .honey_badger
            .propose(&contrib, rng)
            .map_err(Error::ProposeHoneyBadger)?;
        self.process_output(step, rng)
    }

    /// Casts a vote to change the set of validators or parameters.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_for(&mut self, change: Change<N>) -> Result<Step<C, N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default()); // TODO: Return an error?
        }
        let signed_vote = self.vote_counter.sign_vote_for(change)?.clone();
        let msg = Message::SignedVote(signed_vote);
        Ok(Target::All.message(msg).into())
    }

    /// Casts a vote to add a node as a validator.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_add(&mut self, node_id: N, pub_key: PublicKey) -> Result<Step<C, N>> {
        let mut pub_keys = self.netinfo.public_key_map().clone();
        pub_keys.insert(node_id, pub_key);
        self.vote_for(Change::NodeChange(pub_keys))
    }

    /// Casts a vote to demote a validator to observer.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_remove(&mut self, node_id: &N) -> Result<Step<C, N>> {
        let mut pub_keys = self.netinfo.public_key_map().clone();
        pub_keys.remove(node_id);
        self.vote_for(Change::NodeChange(pub_keys))
    }

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message<R: Rng>(
        &mut self,
        sender_id: &N,
        message: Message<N>,
        rng: &mut R,
    ) -> Result<Step<C, N>> {
        if message.era() == self.era {
            match message {
                Message::HoneyBadger(_, hb_msg) => {
                    self.handle_honey_badger_message(sender_id, hb_msg, rng)
                }
                Message::KeyGen(_, kg_msg, sig) => self
                    .handle_key_gen_message(sender_id, kg_msg, *sig)
                    .map(FaultLog::into),
                Message::SignedVote(signed_vote) => self
                    .vote_counter
                    .add_pending_vote(sender_id, signed_vote)
                    .map(FaultLog::into),
            }
        } else if message.era() > self.era {
            Ok(Fault::new(sender_id.clone(), FaultKind::UnexpectedDhbMessageEra).into())
        } else {
            // The message is late; discard it.
            Ok(Step::default())
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
        // If we have a pending key gen message, we should propose.
        !self.key_gen_msg_buffer.is_empty()
    }

    /// The epoch of the next batch that will be output.
    pub fn next_epoch(&self) -> u64 {
        self.era + self.honey_badger.next_epoch()
    }

    /// Handles a message for the `HoneyBadger` instance.
    fn handle_honey_badger_message<R: Rng>(
        &mut self,
        sender_id: &N,
        message: HbMessage<N>,
        rng: &mut R,
    ) -> Result<Step<C, N>> {
        if !self.netinfo.is_node_validator(sender_id) {
            return Err(Error::UnknownSender);
        }
        // Handle the message.
        let step = self
            .honey_badger
            .handle_message(sender_id, message)
            .map_err(Error::HandleHoneyBadgerMessage)?;
        self.process_output(step, rng)
    }

    /// Handles a vote or key generation message and tries to commit it as a transaction. These
    /// messages are only handled once they appear in a batch output from Honey Badger.
    fn handle_key_gen_message(
        &mut self,
        sender_id: &N,
        kg_msg: KeyGenMessage,
        sig: Signature,
    ) -> Result<FaultLog<N, FaultKind>> {
        if !self.verify_signature(sender_id, &sig, &kg_msg)? {
            let fault_kind = FaultKind::InvalidKeyGenMessageSignature;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }
        let kgs = match self.key_gen_state {
            Some(ref mut kgs) => kgs,
            None => {
                return Ok(Fault::new(sender_id.clone(), FaultKind::UnexpectedKeyGenMessage).into());
            }
        };

        // If the sender is correct, it will send at most _N + 1_ key generation messages:
        // one `Part`, and for each validator an `Ack`. _N_ is the node number _after_ the change.
        if kgs.count_messages(sender_id) > kgs.key_gen.num_nodes() + 1 {
            let fault_kind = FaultKind::TooManyKeyGenMessages;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }

        let tx = SignedKeyGenMsg(self.era, sender_id.clone(), kg_msg, sig);
        self.key_gen_msg_buffer.push(tx);
        Ok(FaultLog::default())
    }

    /// Processes all pending batches output by Honey Badger.
    fn process_output<R: Rng>(
        &mut self,
        hb_step: honey_badger::Step<InternalContrib<C, N>, N>,
        rng: &mut R,
    ) -> Result<Step<C, N>> {
        let mut step: Step<C, N> = Step::default();
        let output = step.extend_with(hb_step, FaultKind::HbFault, |hb_msg| {
            Message::HoneyBadger(self.era, hb_msg)
        });
        for hb_batch in output {
            let batch_era = self.era;
            let batch_epoch = hb_batch.epoch + batch_era;
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
                for SignedKeyGenMsg(era, s_id, kg_msg, sig) in key_gen_messages {
                    if era != self.era {
                        let fault_kind = FaultKind::InvalidKeyGenMessageEra;
                        step.fault_log.append(id.clone(), fault_kind);
                    } else if !self.verify_signature(&s_id, &sig, &kg_msg)? {
                        let fault_kind = FaultKind::InvalidKeyGenMessageSignature;
                        step.fault_log.append(id.clone(), fault_kind);
                    } else {
                        step.extend(match kg_msg {
                            KeyGenMessage::Part(part) => self.handle_part(&s_id, part, rng)?,
                            KeyGenMessage::Ack(ack) => self.handle_ack(&s_id, ack)?,
                        });
                    }
                }
            }
            let change = if let Some(kgs) = self.take_ready_key_gen() {
                // If DKG completed, apply the change, restart Honey Badger, and inform the user.
                debug!("{}: DKG for complete for: {:?}", self, kgs.public_keys());
                self.netinfo = kgs.key_gen.into_network_info().map_err(Error::SyncKeyGen)?;
                let params = self.honey_badger.params().clone();
                self.restart_honey_badger(batch_epoch + 1, params);
                ChangeState::Complete(Change::NodeChange(self.netinfo.public_key_map().clone()))
            } else if let Some(change) = self.vote_counter.compute_winner().cloned() {
                // If there is a new change, restart DKG. Inform the user about the current change.
                match change {
                    Change::NodeChange(ref pub_keys) => {
                        step.extend(self.update_key_gen(batch_epoch + 1, pub_keys, rng)?);
                    }
                    Change::EncryptionSchedule(schedule) => {
                        self.update_encryption_schedule(batch_epoch + 1, schedule);
                    }
                }
                match change {
                    Change::NodeChange(_) => ChangeState::InProgress(change),
                    Change::EncryptionSchedule(_) => ChangeState::Complete(change),
                }
            } else {
                ChangeState::None
            };
            step.output.push(Batch {
                epoch: batch_epoch,
                era: batch_era,
                change,
                netinfo: Arc::new(self.netinfo.clone()),
                contributions: batch_contributions,
                params: self.honey_badger.params().clone(),
            });
        }
        Ok(step)
    }

    /// Restarts Honey Badger with the new encryption schedule.
    pub(super) fn update_encryption_schedule(&mut self, era: u64, schedule: EncryptionSchedule) {
        let mut params = self.honey_badger.params().clone();
        params.encryption_schedule = schedule;
        self.restart_honey_badger(era, params);
    }

    /// If the winner of the vote has changed, restarts Key Generation for the set of nodes implied
    /// by the current change.
    pub(super) fn update_key_gen<R: Rng>(
        &mut self,
        era: u64,
        pub_keys: &BTreeMap<N, PublicKey>,
        rng: &mut R,
    ) -> Result<Step<C, N>> {
        if self.key_gen_state.as_ref().map(KeyGenState::public_keys) == Some(pub_keys) {
            return Ok(Step::default()); // The change is the same as before. Continue DKG as is.
        }
        debug!("{}: Restarting DKG for {:?}.", self, pub_keys);
        let params = self.honey_badger.params().clone();
        self.restart_honey_badger(era, params);
        let threshold = util::max_faulty(pub_keys.len());
        let sk = self.netinfo.secret_key().clone();
        let our_id = self.our_id().clone();
        let (key_gen, part) = SyncKeyGen::new(our_id, sk, pub_keys.clone(), threshold, rng)
            .map_err(Error::SyncKeyGen)?;
        self.key_gen_state = Some(KeyGenState::new(key_gen));
        if let Some(part) = part {
            self.send_transaction(KeyGenMessage::Part(part))
        } else {
            Ok(Step::default())
        }
    }

    /// Starts a new `HoneyBadger` instance and resets the vote counter.
    fn restart_honey_badger(&mut self, era: u64, params: Params) {
        self.era = era;
        self.key_gen_msg_buffer.retain(|kg_msg| kg_msg.0 >= era);
        let netinfo = Arc::new(self.netinfo.clone());
        self.vote_counter = VoteCounter::new(netinfo.clone(), era);
        self.honey_badger = HoneyBadger::builder(netinfo)
            .session_id(era)
            .params(params)
            .build();
    }

    /// Handles a `Part` message that was output by Honey Badger.
    fn handle_part<R: Rng>(
        &mut self,
        sender_id: &N,
        part: Part,
        rng: &mut R,
    ) -> Result<Step<C, N>> {
        let outcome = if let Some(kgs) = self.key_gen_state.as_mut() {
            kgs.key_gen
                .handle_part(&sender_id, part, rng)
                .map_err(Error::SyncKeyGen)?
        } else {
            // No key generation ongoing.
            let fault_kind = FaultKind::UnexpectedKeyGenPart;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        };

        match outcome {
            PartOutcome::Valid(Some(ack)) => self.send_transaction(KeyGenMessage::Ack(ack)),
            PartOutcome::Valid(None) => Ok(Step::default()),
            PartOutcome::Invalid(fault) => {
                let fault_kind = FaultKind::SyncKeyGenPart(fault);
                Ok(Fault::new(sender_id.clone(), fault_kind).into())
            }
        }
    }

    /// Handles an `Ack` message that was output by Honey Badger.
    fn handle_ack(&mut self, sender_id: &N, ack: Ack) -> Result<Step<C, N>> {
        let outcome = if let Some(kgs) = self.key_gen_state.as_mut() {
            kgs.key_gen
                .handle_ack(sender_id, ack)
                .map_err(Error::SyncKeyGen)?
        } else {
            // No key generation ongoing.
            let fault_kind = FaultKind::UnexpectedKeyGenAck;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        };

        match outcome {
            AckOutcome::Valid => Ok(Step::default()),
            AckOutcome::Invalid(fault) => {
                let fault_kind = FaultKind::SyncKeyGenAck(fault);
                Ok(Fault::new(sender_id.clone(), fault_kind).into())
            }
        }
    }

    /// Signs and sends a `KeyGenMessage` and also tries to commit it.
    fn send_transaction(&mut self, kg_msg: KeyGenMessage) -> Result<Step<C, N>> {
        let ser = bincode::serialize(&kg_msg).map_err(|err| Error::SerializeKeyGen(*err))?;
        let sig = Box::new(self.netinfo.secret_key().sign(ser));
        if self.netinfo.is_validator() {
            let our_id = self.our_id().clone();
            let signed_msg = SignedKeyGenMsg(self.era, our_id, kg_msg.clone(), *sig.clone());
            self.key_gen_msg_buffer.push(signed_msg);
        }
        let msg = Message::KeyGen(self.era, kg_msg, sig);
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
    /// This accepts signatures from both validators and currently joining candidates, if any.
    fn verify_signature(
        &self,
        node_id: &N,
        sig: &Signature,
        kg_msg: &KeyGenMessage,
    ) -> Result<bool> {
        let ser = bincode::serialize(kg_msg).map_err(|err| Error::SerializeKeyGen(*err))?;
        let verify = |opt_pk: Option<&PublicKey>| opt_pk.map_or(false, |pk| pk.verify(&sig, &ser));
        let kgs = self.key_gen_state.as_ref();
        let current_key = self.netinfo.public_key(node_id);
        let candidate_key = kgs.and_then(|kgs| kgs.public_keys().get(node_id));
        Ok(verify(current_key) || verify(candidate_key))
    }

    /// Returns the maximum future epochs of the Honey Badger algorithm instance.
    pub fn max_future_epochs(&self) -> u64 {
        self.max_future_epochs
    }
}

impl<C, N> fmt::Display for DynamicHoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{:?} DHB(era: {})", self.our_id(), self.era)
    }
}

impl<C, N> Epoched for DynamicHoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned,
{
    type Epoch = (u64, u64);

    fn epoch(&self) -> (u64, u64) {
        (self.era, self.honey_badger.epoch())
    }
}
