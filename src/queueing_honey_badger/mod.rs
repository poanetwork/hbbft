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

use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::{cmp, iter};

use crypto::PublicKey;
use derivative::Derivative;
use failure::{Backtrace, Context, Fail};
use rand::{Rand, Rng};
use serde::{de::DeserializeOwned, Serialize};

use dynamic_honey_badger::{self, Batch as DhbBatch, DynamicHoneyBadger, Message};
use transaction_queue::TransactionQueue;
use {util, Contribution, DistAlgorithm, NodeIdT};

pub use dynamic_honey_badger::{Change, ChangeState, Input, NodeChange};

/// Queueing honey badger error variants.
#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Input error: {}", _0)]
    Input(dynamic_honey_badger::Error),
    #[fail(display = "Handle message error: {}", _0)]
    HandleMessage(dynamic_honey_badger::Error),
    #[fail(display = "Propose error: {}", _0)]
    Propose(dynamic_honey_badger::Error),
}

/// A queueing honey badger error.
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

/// A Queueing Honey Badger builder, to configure the parameters and create new instances of
/// `QueueingHoneyBadger`.
pub struct QueueingHoneyBadgerBuilder<T, N: Rand, Q> {
    /// Shared network data.
    dyn_hb: DynamicHoneyBadger<Vec<T>, N>,
    /// The target number of transactions to be included in each batch.
    batch_size: usize,
    /// The queue of pending transactions that haven't been output in a batch yet.
    queue: Q,
    _phantom: PhantomData<T>,
}

pub type QueueingHoneyBadgerWithStep<T, N, Q> = (QueueingHoneyBadger<T, N, Q>, Step<T, N>);

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
    pub fn build<R>(self, rng: R) -> QueueingHoneyBadgerWithStep<T, N, Q>
    where
        R: 'static + Rng + Send + Sync,
    {
        self.build_with_transactions(None, rng)
            .expect("building without transactions cannot fail")
    }

    /// Returns a new Queueing Honey Badger instance that starts with the given transactions in its
    /// buffer.
    pub fn build_with_transactions<TI, R>(
        mut self,
        txs: TI,
        rng: R,
    ) -> Result<QueueingHoneyBadgerWithStep<T, N, Q>>
    where
        TI: IntoIterator<Item = T>,
        R: 'static + Rng + Send + Sync,
    {
        self.queue.extend(txs);
        let mut qhb = QueueingHoneyBadger {
            dyn_hb: self.dyn_hb,
            batch_size: self.batch_size,
            queue: self.queue,
            rng: Box::new(rng),
        };
        let step = qhb.propose()?;
        Ok((qhb, step))
    }
}

/// A Honey Badger instance that can handle adding and removing nodes and manages a transaction
/// queue.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct QueueingHoneyBadger<T, N: Rand, Q> {
    /// The target number of transactions to be included in each batch.
    batch_size: usize,
    /// The internal managed `DynamicHoneyBadger` instance.
    dyn_hb: DynamicHoneyBadger<Vec<T>, N>,
    /// The queue of pending transactions that haven't been output in a batch yet.
    queue: Q,
    /// Random number generator used for choosing transactions from the queue.
    #[derivative(Debug(format_with = "util::fmt_rng"))]
    rng: Box<dyn Rng + Send + Sync>,
}

pub type Step<T, N> = ::Step<Message<N>, Batch<T, N>, N>;

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

    fn handle_input(&mut self, input: Self::Input) -> Result<Step<T, N>> {
        // User transactions are forwarded to `HoneyBadger` right away. Internal messages are
        // in addition signed and broadcast.
        match input {
            Input::User(tx) => self.push_transaction(tx),
            Input::Change(change) => self.vote_for(change),
        }
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> Result<Step<T, N>> {
        self.handle_message(sender_id, message)
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
    pub fn push_transaction(&mut self, tx: T) -> Result<Step<T, N>> {
        self.queue.extend(iter::once(tx));
        self.propose()
    }

    /// Casts a vote to change the set of validators.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_for(&mut self, change: Change<N>) -> Result<Step<T, N>> {
        Ok(self
            .dyn_hb
            .handle_input(Input::Change(change))
            .map_err(ErrorKind::Input)?
            .join(self.propose()?))
    }

    /// Casts a vote to add a node as a validator.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_add(&mut self, node_id: N, pub_key: PublicKey) -> Result<Step<T, N>> {
        self.vote_for(Change::NodeChange(NodeChange::Add(node_id, pub_key)))
    }

    /// Casts a vote to demote a validator to observer.
    ///
    /// This stores a pending vote for the change. It will be included in some future batch, and
    /// once enough validators have been voted for the same change, it will take effect.
    pub fn vote_to_remove(&mut self, node_id: N) -> Result<Step<T, N>> {
        self.vote_for(Change::NodeChange(NodeChange::Remove(node_id)))
    }

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message(&mut self, sender_id: &N, message: Message<N>) -> Result<Step<T, N>> {
        let step = self
            .dyn_hb
            .handle_message(sender_id, message)
            .map_err(ErrorKind::HandleMessage)?;
        for batch in &step.output {
            self.queue.remove_multiple(batch.iter());
        }
        Ok(step.join(self.propose()?))
    }

    /// Returns a reference to the internal managed `DynamicHoneyBadger` instance.
    pub fn dyn_hb(&self) -> &DynamicHoneyBadger<Vec<T>, N> {
        &self.dyn_hb
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
    fn propose(&mut self) -> Result<Step<T, N>> {
        let mut step = Step::default();
        while self.can_propose() {
            let amount = cmp::max(1, self.batch_size / self.dyn_hb.netinfo().num_nodes());
            let proposal = self.queue.choose(&mut self.rng, amount, self.batch_size);
            step.extend(
                self.dyn_hb
                    .handle_input(Input::User(proposal))
                    .map_err(ErrorKind::Propose)?,
            );
        }
        Ok(step)
    }
}

pub type Batch<T, N> = DhbBatch<Vec<T>, N>;
