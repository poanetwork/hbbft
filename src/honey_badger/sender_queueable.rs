use rand::Rand;
use serde::{de::DeserializeOwned, Serialize};

use super::{Batch, HoneyBadger, Message};
use sender_queue::{
    SenderQueueableDistAlgorithm, SenderQueueableEpoch, SenderQueueableMessage,
    SenderQueueableOutput,
};
use {Contribution, Epoched, NodeIdT};

impl<C, N> SenderQueueableOutput<N, Message<N>> for Batch<C, N>
where
    C: Contribution,
    N: NodeIdT + Rand,
{
    fn added_node(&self) -> Option<N> {
        None
    }

    fn convert_epoch(&self) -> u64 {
        self.epoch()
    }
}

impl<N> SenderQueueableMessage for Message<N>
where
    N: Rand,
{
    fn is_accepted(&self, them: u64, max_future_epochs: u64) -> bool {
        let our_epoch = self.epoch();
        them <= our_epoch && our_epoch <= them + max_future_epochs
    }

    fn is_obsolete(&self, them: u64) -> bool {
        self.epoch() < them
    }
}

impl SenderQueueableEpoch for u64 {
    fn spanning_epochs(&self) -> Vec<Self> {
        vec![]
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
