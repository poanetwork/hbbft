//! Convenience methods for a `SenderQueue` wrapping a `DynamicHoneyBadger`.

use std::collections::BTreeSet;
use std::result;

use crate::crypto::PublicKey;
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};

use super::{
    Message, SenderQueue, SenderQueueableDistAlgorithm, SenderQueueableMessage,
    SenderQueueableOutput, Step,
};
use crate::{Contribution, DaStep, NodeIdT};

use crate::dynamic_honey_badger::{
    Batch, Change, ChangeState, DynamicHoneyBadger, Error as DhbError, JoinPlan,
    Message as DhbMessage,
};

impl<C, N> SenderQueueableOutput<N, (u64, u64)> for Batch<C, N>
where
    C: Contribution,
    N: NodeIdT,
{
    fn participant_change(&self) -> Option<BTreeSet<N>> {
        if let ChangeState::InProgress(Change::NodeChange(pub_keys)) = self.change() {
            let candidates = pub_keys.keys();
            let current_validators: BTreeSet<&N> =
                self.network_info().public_key_map().keys().collect();
            let participants = candidates.chain(current_validators).cloned().collect();
            Some(participants)
        } else if let ChangeState::Complete(Change::NodeChange(pub_keys)) = self.change() {
            let next_validators = pub_keys.keys().cloned().collect();
            Some(next_validators)
        } else {
            None
        }
    }

    fn output_epoch(&self) -> (u64, u64) {
        let hb_epoch = self.epoch() - self.era();
        (self.era(), hb_epoch)
    }
}

impl<N: Ord> SenderQueueableMessage for DhbMessage<N> {
    type Epoch = (u64, u64);

    fn is_premature(&self, (them_era, them): (u64, u64), max_future_epochs: u64) -> bool {
        match *self {
            DhbMessage::HoneyBadger(era, ref msg) => {
                era > them_era || (era == them_era && msg.epoch() > them + max_future_epochs)
            }
            DhbMessage::KeyGen(era, _, _) => era > them_era,
            DhbMessage::SignedVote(ref signed_vote) => signed_vote.era() > them_era,
        }
    }

    fn is_obsolete(&self, (them_era, them): (u64, u64)) -> bool {
        match *self {
            DhbMessage::HoneyBadger(era, ref msg) => {
                era < them_era || (era == them_era && msg.epoch() < them)
            }
            DhbMessage::KeyGen(era, _, _) => era < them_era,
            DhbMessage::SignedVote(ref signed_vote) => signed_vote.era() < them_era,
        }
    }

    fn first_epoch(&self) -> (u64, u64) {
        match *self {
            DhbMessage::HoneyBadger(era, ref msg) => (era, msg.epoch()),
            DhbMessage::KeyGen(era, _, _) => (era, 0),
            DhbMessage::SignedVote(ref signed_vote) => (signed_vote.era(), 0),
        }
    }
}

impl<C, N> SenderQueueableDistAlgorithm for DynamicHoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned,
{
    fn max_future_epochs(&self) -> u64 {
        self.max_future_epochs()
    }
}

type Result<C, N> = result::Result<DaStep<SenderQueue<DynamicHoneyBadger<C, N>>>, DhbError>;

impl<C, N> SenderQueue<DynamicHoneyBadger<C, N>>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned,
{
    /// Proposes a contribution in the current epoch.
    ///
    /// Returns an error if we already made a proposal in this epoch.
    ///
    /// If we are the only validator, this will immediately output a batch, containing our
    /// proposal.
    pub fn propose<R: Rng>(&mut self, rng: &mut R, contrib: C) -> Result<C, N> {
        self.apply(|algo| algo.propose(contrib, rng))
    }

    /// Casts a vote to change the set of validators or parameters.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_for(&mut self, change: Change<N>) -> Result<C, N> {
        self.apply(|algo| algo.vote_for(change))
    }

    /// Casts a vote to add a node as a validator.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_add(&mut self, node_id: N, pub_key: PublicKey) -> Result<C, N> {
        self.apply(|algo| algo.vote_to_add(node_id, pub_key))
    }

    /// Casts a vote to demote a validator to observer.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_remove(&mut self, node_id: &N) -> Result<C, N> {
        self.apply(|algo| algo.vote_to_remove(node_id))
    }

    /// Restarts the managed algorithm with the given join plan with a new list of peers and with
    /// the same secret key. In order to be restarted, the node should have completed the process of
    /// removing itself from the network. The node may not output a batch if it were not properly
    /// removed.
    pub fn restart<I, R: Rng>(
        &mut self,
        join_plan: JoinPlan<N>,
        peer_ids: I,
        rng: &mut R,
    ) -> Result<C, N>
    where
        I: Iterator<Item = N>,
    {
        if !self.is_removed {
            // TODO: return an error?
            return Ok(Step::<DynamicHoneyBadger<C, N>>::default());
        }
        let secret_key = self.algo().netinfo().secret_key().clone();
        let id = self.algo().netinfo().our_id().clone();
        let (dhb, dhb_step) =
            DynamicHoneyBadger::new_joining(id.clone(), secret_key, join_plan, rng)?;
        let (sq, mut sq_step) = SenderQueue::builder(dhb, peer_ids.into_iter()).build(id);
        sq_step.extend(dhb_step.map(|output| output, Message::from));
        *self = sq;
        Ok(sq_step)
    }
}
