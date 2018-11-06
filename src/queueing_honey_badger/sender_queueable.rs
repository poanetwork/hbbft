use rand::Rand;
use serde::{de::DeserializeOwned, Serialize};

use super::QueueingHoneyBadger;
use sender_queue::SenderQueueableDistAlgorithm;
use transaction_queue::TransactionQueue;
use {Contribution, NodeIdT};

impl<T, N, Q> SenderQueueableDistAlgorithm for QueueingHoneyBadger<T, N, Q>
where
    T: Contribution + Serialize + DeserializeOwned + Clone,
    N: NodeIdT + Serialize + DeserializeOwned + Rand,
    Q: TransactionQueue<T>,
{
    fn max_future_epochs(&self) -> u64 {
        self.dyn_hb.max_future_epochs()
    }
}
