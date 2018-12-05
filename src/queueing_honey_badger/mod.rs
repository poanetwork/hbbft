//! # Queueing Honey Badger
//!
//! This works exactly like Dynamic Honey Badger, but it has a transaction queue built in. Whenever
//! an epoch is output, it will automatically select a list of pending transactions and propose it
//! for the next one. The user can continuously add more pending transactions to the queue.
//!
//! If there are no pending transactions, no validators in the process of being added or
//! removed and not enough other nodes have proposed yet, no automatic proposal will be made: The
//! network then waits until at least _f + 1_ have any content for the next epoch.
//!
//! ## How it works
//!
//! Queueing Honey Badger runs a Dynamic Honey Badger internally, and automatically inputs a list
//! of pending transactions as its contribution at the beginning of each epoch. These are selected
//! by making a random choice of _B / N_ out of the first _B_ entries in the queue, where _B_ is the
//! configurable `batch_size` parameter, and _N_ is the current number of validators.
//!
//! After each output, the transactions that made it into the new batch are removed from the queue.
//!
//! The random choice of transactions is made to reduce redundancy even if all validators have
//! roughly the same entries in their queues. By selecting a random fraction of the first _B_
//! entries, any two nodes will likely make almost disjoint contributions instead of proposing
//! the same transaction multiple times.

use std::marker::PhantomData;
use std::{cmp, iter};

use crate::crypto::PublicKey;
use derivative::Derivative;
use failure::Fail;
use rand::{Rand, Rng};
use serde::{de::DeserializeOwned, Serialize};

use crate::dynamic_honey_badger::{self, Batch as DhbBatch, DynamicHoneyBadger, Message};
use crate::transaction_queue::TransactionQueue;
use crate::{Contribution, DistAlgorithm, NetworkInfo, NodeIdT};

pub use crate::dynamic_honey_badger::{Change, ChangeState, Input};

/// Queueing honey badger error variants.
#[derive(Debug, Fail)]
pub enum Error {
    /// Failed to handle input.
    #[fail(display = "Input error: {}", _0)]
    Input(dynamic_honey_badger::Error),
    /// Failed to handle a message.
    #[fail(display = "Handle message error: {}", _0)]
    HandleMessage(dynamic_honey_badger::Error),
    /// Failed to propose a contribution.
    #[fail(display = "Propose error: {}", _0)]
    Propose(dynamic_honey_badger::Error),
}

/// The result of `QueueingHoneyBadger` handling an input or message.
pub type Result<T> = ::std::result::Result<T, Error>;

/// A Queueing Honey Badger builder, to configure the parameters and create new instances of
/// `QueueingHoneyBadger`.
pub struct QueueingHoneyBadgerBuilder<T, N: Rand + Ord, Q> {
    /// Shared network data.
    dyn_hb: DynamicHoneyBadger<Vec<T>, N>,
    /// The target number of transactions to be included in each batch.
    batch_size: usize,
    /// The queue of pending transactions that haven't been output in a batch yet.
    queue: Q,
    _phantom: PhantomData<T>,
}

type QueueingHoneyBadgerWithStep<T, N, Q> = (QueueingHoneyBadger<T, N, Q>, Step<T, N>);

impl<T, N, Q> QueueingHoneyBadgerBuilder<T, N, Q>
where
    T: Contribution + Serialize + DeserializeOwned + Clone,
    N: NodeIdT + Serialize + DeserializeOwned + Rand,
    Q: TransactionQueue<T>,
{
    /// Returns a new `QueueingHoneyBadgerBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    // TODO: Make it easier to build a `QueueingHoneyBadger` with a `JoinPlan`. Handle `Step`
    // conversion internally.
    pub fn new(dyn_hb: DynamicHoneyBadger<Vec<T>, N>) -> Self {
        // TODO: Use the defaults from `HoneyBadgerBuilder`.
        QueueingHoneyBadgerBuilder {
            dyn_hb,
            batch_size: 100,
            queue: Default::default(),
            _phantom: PhantomData,
        }
    }

    /// Sets the target number of transactions per batch.
    pub fn batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Sets the transaction queue object.
    pub fn queue(mut self, queue: Q) -> Self {
        self.queue = queue;
        self
    }

    /// Creates a new Queueing Honey Badger instance with an empty buffer.
    pub fn build<R: Rng>(self, rng: &mut R) -> QueueingHoneyBadgerWithStep<T, N, Q> {
        self.build_with_transactions(rng, None)
            .expect("building without transactions cannot fail")
    }

    /// Returns a new Queueing Honey Badger instance that starts with the given transactions in its
    /// buffer.
    pub fn build_with_transactions<TI, R>(
        mut self,
        rng: &mut R,
        txs: TI,
    ) -> Result<QueueingHoneyBadgerWithStep<T, N, Q>>
    where
        TI: IntoIterator<Item = T>,
        R: Rng,
    {
        self.queue.extend(txs);
        let mut qhb = QueueingHoneyBadger {
            dyn_hb: self.dyn_hb,
            batch_size: self.batch_size,
            queue: self.queue,
        };
        let step = qhb.propose(rng)?;
        Ok((qhb, step))
    }
}

/// A Honey Badger instance that can handle adding and removing nodes and manages a transaction
/// queue.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct QueueingHoneyBadger<T, N: Rand + Ord, Q> {
    /// The target number of transactions to be included in each batch.
    batch_size: usize,
    /// The internal managed `DynamicHoneyBadger` instance.
    dyn_hb: DynamicHoneyBadger<Vec<T>, N>,
    /// The queue of pending transactions that haven't been output in a batch yet.
    queue: Q,
}

/// A `QueueingHoneyBadger` step, possibly containing multiple outputs.
pub type Step<T, N> = crate::Step<Message<N>, Batch<T, N>, N>;

impl<T, N, Q> DistAlgorithm for QueueingHoneyBadger<T, N, Q>
where
    T: Contribution + Serialize + DeserializeOwned + Clone,
    N: NodeIdT + Serialize + DeserializeOwned + Rand,
    Q: TransactionQueue<T>,
{
    type NodeId = N;
    type Input = Input<T, N>;
    type Output = Batch<T, N>;
    type Message = Message<N>;
    type Error = Error;

    fn handle_input<R: Rng>(&mut self, rng: &mut R, input: Self::Input) -> Result<Step<T, N>> {
        // User transactions are forwarded to `HoneyBadger` right away. Internal messages are
        // in addition signed and broadcast.

        match input {
            Input::User(tx) => self.push_transaction(rng, tx),
            Input::Change(change) => self.vote_for(rng, change),
        }
    }

    fn handle_message<R: Rng>(
        &mut self,
        rng: &mut R,
        sender_id: &N,
        message: Self::Message,
    ) -> Result<Step<T, N>> {
        self.handle_message(rng, sender_id, message)
    }

    fn terminated(&self) -> bool {
        false
    }

    fn our_id(&self) -> &N {
        self.dyn_hb.our_id()
    }
}

impl<T, N, Q> QueueingHoneyBadger<T, N, Q>
where
    T: Contribution + Serialize + DeserializeOwned + Clone,
    N: NodeIdT + Serialize + DeserializeOwned + Rand,
    Q: TransactionQueue<T>,
{
    /// Returns a new `QueueingHoneyBadgerBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    pub fn builder(dyn_hb: DynamicHoneyBadger<Vec<T>, N>) -> QueueingHoneyBadgerBuilder<T, N, Q> {
        QueueingHoneyBadgerBuilder::new(dyn_hb)
    }

    /// Adds a transaction to the queue.
    ///
    /// This can be called at any time to append to the transaction queue. The new transaction will
    /// be proposed in some future epoch.
    ///
    /// If no proposal has yet been made for the current epoch, this may trigger one. In this case,
    /// a nonempty step will returned, with the corresponding messages. (Or, if we are the only
    /// validator, even with the completed batch as an output.)
    pub fn push_transaction<R: Rng>(&mut self, rng: &mut R, tx: T) -> Result<Step<T, N>> {
        self.queue.extend(iter::once(tx));
        self.propose(rng)
    }

    /// Casts a vote to change the set of validators.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_for<R: Rng>(&mut self, rng: &mut R, change: Change<N>) -> Result<Step<T, N>> {
        self.apply(rng, |_, dyn_hb| dyn_hb.vote_for(change))
    }

    /// Casts a vote to add a node as a validator.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_add<R: Rng>(
        &mut self,
        rng: &mut R,
        node_id: N,
        pub_key: PublicKey,
    ) -> Result<Step<T, N>> {
        self.apply(rng, |_, dyn_hb| dyn_hb.vote_to_add(node_id, pub_key))
    }

    /// Casts a vote to demote a validator to observer.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_remove<R: Rng>(&mut self, rng: &mut R, node_id: &N) -> Result<Step<T, N>> {
        self.apply(rng, |_, dyn_hb| dyn_hb.vote_to_remove(node_id))
    }

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message<R: Rng>(
        &mut self,
        rng: &mut R,
        sender_id: &N,
        message: Message<N>,
    ) -> Result<Step<T, N>> {
        self.apply(rng, |rng, dyn_hb| {
            dyn_hb.handle_message(rng, sender_id, message)
        })
    }

    /// Returns a reference to the internal managed `DynamicHoneyBadger` instance.
    pub fn dyn_hb(&self) -> &DynamicHoneyBadger<Vec<T>, N> {
        &self.dyn_hb
    }

    /// Returns the information about the node IDs in the network, and the cryptographic keys.
    pub fn netinfo(&self) -> &NetworkInfo<N> {
        self.dyn_hb.netinfo()
    }

    /// Applies a function `f` to the `DynamicHoneyBadger` instance and processes the step.
    fn apply<R, F>(&mut self, rng: &mut R, f: F) -> Result<Step<T, N>>
    where
        F: FnOnce(&mut R, &mut DynamicHoneyBadger<Vec<T>, N>)
            -> dynamic_honey_badger::Result<Step<T, N>>,
        R: Rng,
    {
        let step = f(rng, &mut self.dyn_hb).map_err(Error::Input)?;
        self.queue
            .remove_multiple(step.output.iter().flat_map(Batch::iter));
        Ok(step.join(self.propose(rng)?))
    }

    /// Returns the epoch of the next batch that will be output.
    pub fn next_epoch(&self) -> u64 {
        self.dyn_hb.next_epoch()
    }

    /// Returns `true` if we are ready to propose our contribution for the next epoch, i.e. if the
    /// previous epoch has completed and we have either pending transactions or we are required to
    /// make a proposal to avoid stalling the network.
    fn can_propose(&self) -> bool {
        if self.dyn_hb.has_input() {
            return false; // Previous epoch is still in progress.
        }
        !self.queue.is_empty() || self.dyn_hb.should_propose()
    }

    /// Initiates the next epoch by proposing a batch from the queue.
    fn propose<R: Rng>(&mut self, rng: &mut R) -> Result<Step<T, N>> {
        let mut step = Step::default();
        while self.can_propose() {
            let amount = cmp::max(1, self.batch_size / self.dyn_hb.netinfo().num_nodes());
            let proposal = self.queue.choose(rng, amount, self.batch_size);
            step.extend(
                self.dyn_hb
                    .handle_input(rng, Input::User(proposal))
                    .map_err(Error::Propose)?,
            );
        }
        Ok(step)
    }
}

/// A batch containing a list of transactions from at least two thirds of the validators.
pub type Batch<T, N> = DhbBatch<Vec<T>, N>;
