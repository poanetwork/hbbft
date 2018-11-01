use rand::Rand;
use serde::{de::DeserializeOwned, Serialize};

use super::{Batch, Change, ChangeState, DynamicHoneyBadger, Epoch, Message, NodeChange};
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
        if let ChangeState::InProgress(Change::NodeChange(NodeChange::Add(ref id, _))) = self.change
        {
            // Register the new node to send broadcast messages to it from now on.
            Some(id.clone())
        } else {
            None
        }
    }

    fn next_epoch(&self) -> (u64, u64) {
        let epoch = self.epoch;
        let era = self.era;
        if self.change == ChangeState::None {
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
