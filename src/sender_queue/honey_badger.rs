use std::collections::BTreeSet;

use serde::{de::DeserializeOwned, Serialize};

use super::{SenderQueueableConsensusProtocol, SenderQueueableMessage, SenderQueueableOutput};
use crate::honey_badger::{Batch, HoneyBadger, Message};
use crate::{Contribution, Epoched, NodeIdT};

impl<C, N> SenderQueueableOutput<N, u64> for Batch<C, N>
where
    C: Contribution,
    N: NodeIdT,
{
    fn participant_change(&self) -> Option<BTreeSet<N>> {
        None
    }

    fn output_epoch(&self) -> u64 {
        self.epoch
    }
}

impl<N> SenderQueueableMessage for Message<N> {
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
    N: NodeIdT,
{
    type Epoch = u64;

    fn epoch(&self) -> u64 {
        self.next_epoch()
    }
}

impl<C, N> SenderQueueableConsensusProtocol for HoneyBadger<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT,
{
    fn max_future_epochs(&self) -> u64 {
        self.max_future_epochs()
    }
}
