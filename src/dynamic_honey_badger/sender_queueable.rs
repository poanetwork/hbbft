use log::error;
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

    fn next_epoch(&self) -> Epoch {
        let epoch = self.epoch;
        let era = self.era;
        if self.change == ChangeState::None {
            Epoch(era, Some(epoch - era + 1))
        } else {
            Epoch(epoch + 1, Some(0))
        }
    }
}

impl<N> SenderQueueableMessage for Message<N>
where
    N: Rand,
{
    fn is_accepted(&self, Epoch(them_era, them_hb_epoch): Epoch, max_future_epochs: u64) -> bool {
        let Epoch(era, hb_epoch) = self.epoch();
        if era != them_era {
            return false;
        }
        match (hb_epoch, them_hb_epoch) {
            (Some(us), Some(them)) => them <= us && us <= them + max_future_epochs,
            (None, Some(_)) => true,
            (_, None) => {
                // TODO: return a Fault.
                error!("Peer's Honey Badger epoch undefined");
                false
            }
        }
    }

    fn is_obsolete(&self, Epoch(them_era, them_hb_epoch): Epoch) -> bool {
        let Epoch(era, hb_epoch) = self.epoch();
        era < them_era || (era == them_era && hb_epoch.is_some() && hb_epoch < them_hb_epoch)
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
