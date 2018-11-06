//! Convenience methods for a `SenderQueue` wrapping a `DynamicHoneyBadger`.

use crypto::PublicKey;
use rand::Rand;
use serde::{de::DeserializeOwned, Serialize};

use super::{SenderQueue, Step};
use dynamic_honey_badger::{Change, DynamicHoneyBadger};
use {Contribution, NodeIdT};

type Result<C, N> = super::Result<Step<DynamicHoneyBadger<C, N>>, DynamicHoneyBadger<C, N>>;

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
    pub fn vote_to_remove(&mut self, node_id: N) -> Result<C, N> {
        self.apply(|algo| algo.vote_to_remove(node_id))
    }
}
