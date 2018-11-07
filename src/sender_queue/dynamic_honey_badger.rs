//! Convenience methods for a `SenderQueue` wrapping a `DynamicHoneyBadger`.

use std::result;

use crypto::PublicKey;
use rand::Rand;
use serde::{de::DeserializeOwned, Serialize};

use super::{
    SenderQueue, SenderQueueableDistAlgorithm, SenderQueueableEpoch, SenderQueueableMessage,
    SenderQueueableOutput,
};
use {Contribution, DaStep, Epoched, NodeIdT};

use dynamic_honey_badger::{
    Batch, Change, ChangeState, DynamicHoneyBadger, Epoch, Error as DhbError, Message, NodeChange,
};

impl<C, N> SenderQueueableOutput<N, Message<N>> for Batch<C, N>
where
    C: Contribution,
    N: NodeIdT + Rand,
{
    fn added_node(&self) -> Option<N> {
        if let ChangeState::InProgress(Change::NodeChange(NodeChange::Add(ref id, _))) =
            self.change()
        {
            // Register the new node to send broadcast messages to it from now on.
            Some(id.clone())
        } else {
            None
        }
    }

    fn next_epoch(&self) -> (u64, u64) {
        let epoch = self.epoch();
        let era = self.era();
        if *self.change() == ChangeState::None {
            (era, epoch - era + 1)
        } else {
            (epoch + 1, 0)
        }
    }
}

impl<N> SenderQueueableMessage for Message<N>
where
    N: Rand,
{
    fn is_accepted(&self, (them_era, them): (u64, u64), max_future_epochs: u64) -> bool {
        let Epoch(era, us) = self.epoch();
        if era != them_era {
            return false;
        }
        if let Some(us) = us {
            them <= us && us <= them + max_future_epochs
        } else {
            true
        }
    }

    fn is_obsolete(&self, (them_era, them): (u64, u64)) -> bool {
        let Epoch(era, us) = self.epoch();
        if era < them_era {
            return true;
        }
        if let Some(us) = us {
            era == them_era && us < them
        } else {
            false
        }
    }
}

impl SenderQueueableEpoch for Epoch {
    fn spanning_epochs(&self) -> Vec<Self> {
        if let Epoch(era, Some(_)) = *self {
            vec![Epoch(era, None)]
        } else {
            vec![]
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
    pub fn vote_to_remove(&mut self, node_id: N) -> Result<C, N> {
        self.apply(|algo| algo.vote_to_remove(node_id))
    }
}
