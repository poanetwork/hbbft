use rand::Rand;
use serde::{de::DeserializeOwned, Serialize};

use super::{SenderQueueableDistAlgorithm, SenderQueueableMessage, SenderQueueableOutput};
use honey_badger::{Batch, HoneyBadger, Message};
use {Contribution, Epoched, NodeIdT};

impl<C, N> SenderQueueableOutput<N, Message<N>> for Batch<C, N>
where
    C: Contribution,
    N: NodeIdT + Rand,
{
    fn new_nodes(&self) -> Vec<N> {
        Vec::new()
    }
}

impl<N> SenderQueueableMessage for Message<N>
where
    N: Rand,
{
    type Epoch = u64;

    fn is_premature(&self, them: u64, max_future_epochs: u64) -> bool {
        self.epoch() > them + max_future_epochs
    }

    fn is_obsolete(&self, them: u64) -> bool {
        self.epoch() < them
    }

    fn first_epoch(&self) -> u64 {
        self.epoch()
    }
}

impl<C, N> Epoched for HoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Rand,
{
    type Epoch = u64;

    fn epoch(&self) -> u64 {
        self.epoch()
    }
}

impl<C, N> SenderQueueableDistAlgorithm for HoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Rand,
{
    fn max_future_epochs(&self) -> u64 {
        self.max_future_epochs()
    }
}
