//! Convenience methods for a `SenderQueue` wrapping a `DynamicHoneyBadger`.

use std::result;

use crypto::PublicKey;
use rand::Rand;
use serde::{de::DeserializeOwned, Serialize};

use super::{
    SenderQueue, SenderQueueableDistAlgorithm, SenderQueueableMessage, SenderQueueableOutput,
};
use {Contribution, DaStep, NodeIdT};

use dynamic_honey_badger::{
    Batch, Change, ChangeState, DynamicHoneyBadger, Error as DhbError, Message,
};

impl<C, N> SenderQueueableOutput<N, Message<N>> for Batch<C, N>
where
    C: Contribution,
    N: NodeIdT + Rand,
{
    fn added_peers(&self) -> Vec<N> {
        if let ChangeState::InProgress(Change::NodeChange(pub_keys)) = self.change() {
            // Register the new node to send broadcast messages to it from now on.
            pub_keys.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }
}

impl<N> SenderQueueableMessage for Message<N>
where
    N: Rand + Ord,
{
    type Epoch = (u64, u64);

    fn is_premature(&self, (them_era, them): (u64, u64), max_future_epochs: u64) -> bool {
        match *self {
            Message::HoneyBadger(era, ref msg) => {
                era > them_era || (era == them_era && msg.epoch() > them + max_future_epochs)
            }
            Message::KeyGen(era, _, _) => era > them_era,
            Message::SignedVote(ref signed_vote) => signed_vote.era() > them_era,
        }
    }

    fn is_obsolete(&self, (them_era, them): (u64, u64)) -> bool {
        match *self {
            Message::HoneyBadger(era, ref msg) => {
                era < them_era || (era == them_era && msg.epoch() < them)
            }
            Message::KeyGen(era, _, _) => era < them_era,
            Message::SignedVote(ref signed_vote) => signed_vote.era() < them_era,
        }
    }

    fn first_epoch(&self) -> (u64, u64) {
        match *self {
            Message::HoneyBadger(era, ref msg) => (era, msg.epoch()),
            Message::KeyGen(era, _, _) => (era, 0),
            Message::SignedVote(ref signed_vote) => (signed_vote.era(), 0),
        }
    }
}

impl<C, N> SenderQueueableDistAlgorithm for DynamicHoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned + Rand,
{
    fn max_future_epochs(&self) -> u64 {
        self.max_future_epochs()
    }
}

type Result<C, N> = result::Result<DaStep<SenderQueue<DynamicHoneyBadger<C, N>>>, DhbError>;

impl<C, N> SenderQueue<DynamicHoneyBadger<C, N>>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned + Rand,
{
    /// Proposes a contribution in the current epoch.
    ///
    /// Returns an error if we already made a proposal in this epoch.
    ///
    /// If we are the only validator, this will immediately output a batch, containing our
    /// proposal.
    pub fn propose(&mut self, contrib: C) -> Result<C, N> {
        self.apply(|algo| algo.propose(contrib))
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
}
