//! Convenience methods for a `SenderQueue` wrapping a `QueueingHoneyBadger`.

use std::result;

use crate::crypto::PublicKey;
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};

use super::{Error, SenderQueue, SenderQueueableDistAlgorithm};
use crate::queueing_honey_badger::{Change, Error as QhbError, QueueingHoneyBadger};
use crate::transaction_queue::TransactionQueue;
use crate::{Contribution, DaStep, Epoched, NodeIdT};

impl<T, N, Q> Epoched for QueueingHoneyBadger<T, N, Q>
where
    T: Contribution + Serialize + DeserializeOwned + Clone,
    N: NodeIdT + Serialize + DeserializeOwned,
    Q: TransactionQueue<T>,
    Standard: Distribution<N>,
{
    type Epoch = (u64, u64);

    fn epoch(&self) -> (u64, u64) {
        self.dyn_hb().epoch()
    }
}

impl<T, N, Q> SenderQueueableDistAlgorithm for QueueingHoneyBadger<T, N, Q>
where
    T: Contribution + Serialize + DeserializeOwned + Clone,
    N: NodeIdT + Serialize + DeserializeOwned,
    Q: TransactionQueue<T>,
    Standard: Distribution<N>,
{
    fn max_future_epochs(&self) -> u64 {
        self.dyn_hb().max_future_epochs()
    }
}

type Result<T, N, Q> =
    result::Result<DaStep<SenderQueue<QueueingHoneyBadger<T, N, Q>>>, Error<QhbError>>;

impl<T, N, Q> SenderQueue<QueueingHoneyBadger<T, N, Q>>
where
    T: Contribution + Serialize + DeserializeOwned + Clone,
    N: NodeIdT + Serialize + DeserializeOwned,
    Q: TransactionQueue<T>,
    Standard: Distribution<N>,
{
    /// Adds a transaction to the queue.
    ///
    /// This can be called at any time to append to the transaction queue. The new transaction will
    /// be proposed in some future epoch.
    ///
    /// If no proposal has yet been made for the current epoch, this may trigger one. In this case,
    /// a nonempty step will returned, with the corresponding messages. (Or, if we are the only
    /// validator, even with the completed batch as an output.)
    pub fn push_transaction<R: Rng>(&mut self, tx: T, rng: &mut R) -> Result<T, N, Q> {
        self.apply(|algo| algo.push_transaction(tx, rng))
    }

    /// Casts a vote to change the set of validators or parameters.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_for<R: Rng>(&mut self, change: Change<N>, rng: &mut R) -> Result<T, N, Q> {
        self.apply(|algo| algo.vote_for(change, rng))
    }

    /// Casts a vote to add a node as a validator.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_add<R: Rng>(
        &mut self,
        node_id: N,
        pub_key: PublicKey,
        rng: &mut R,
    ) -> Result<T, N, Q> {
        self.apply(|algo| algo.vote_to_add(node_id, pub_key, rng))
    }

    /// Casts a vote to demote a validator to observer.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_remove<R: Rng>(&mut self, node_id: &N, rng: &mut R) -> Result<T, N, Q> {
        self.apply(|algo| algo.vote_to_remove(node_id, rng))
    }
}
