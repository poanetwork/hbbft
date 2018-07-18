//! # Queueing Honey Badger
//!
//! This works exactly like Dynamic Honey Badger, but it has a transaction queue built in. Whenever
//! an epoch is output, it will automatically select a list of pending transactions and propose it
//! for the next one. The user can continuously add more pending transactions to the queue.
//!
//! **Note**: `QueueingHoneyBadger` currently requires at least two validators.
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

use std::cmp;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

use rand::Rand;
use serde::{Deserialize, Serialize};

use dynamic_honey_badger::{self, Batch as DhbBatch, DynamicHoneyBadger, Message};
use fault_log::FaultLog;
use messaging::{DistAlgorithm, NetworkInfo, Step, TargetedMessage};
use transaction_queue::TransactionQueue;

pub use dynamic_honey_badger::{Change, ChangeState, Input};

error_chain!{
    links {
        DynamicHoneyBadger(dynamic_honey_badger::Error, dynamic_honey_badger::ErrorKind);
    }
}

/// A Queueing Honey Badger builder, to configure the parameters and create new instances of
/// `QueueingHoneyBadger`.
pub struct QueueingHoneyBadgerBuilder<Tx, NodeUid> {
    /// Shared network data.
    netinfo: NetworkInfo<NodeUid>,
    /// The target number of transactions to be included in each batch.
    batch_size: usize,
    /// The epoch at which to join the network.
    start_epoch: u64,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    _phantom: PhantomData<Tx>,
}

impl<Tx, NodeUid> QueueingHoneyBadgerBuilder<Tx, NodeUid>
where
    Tx: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash + Clone,
    NodeUid: Eq + Ord + Clone + Debug + Serialize + for<'r> Deserialize<'r> + Hash + Rand,
{
    /// Returns a new `QueueingHoneyBadgerBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    pub fn new(netinfo: NetworkInfo<NodeUid>) -> Self {
        // TODO: Use the defaults from `HoneyBadgerBuilder`.
        QueueingHoneyBadgerBuilder {
            netinfo,
            batch_size: 100,
            start_epoch: 0,
            max_future_epochs: 3,
            _phantom: PhantomData,
        }
    }

    /// Sets the target number of transactions per batch.
    pub fn batch_size(&mut self, batch_size: usize) -> &mut Self {
        self.batch_size = batch_size;
        self
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: usize) -> &mut Self {
        self.max_future_epochs = max_future_epochs;
        self
    }

    /// Sets the epoch at which to join the network as an observer. This requires the node to
    /// receive all broadcast messages for `start_epoch` and later.
    pub fn start_epoch(&mut self, start_epoch: u64) -> &mut Self {
        self.start_epoch = start_epoch;
        self
    }

    /// Creates a new Queueing Honey Badger instance with an empty buffer.
    pub fn build(&self) -> QueueingHoneyBadger<Tx, NodeUid>
    where
        Tx: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq,
    {
        self.build_with_transactions(None)
            .expect("building without transactions cannot fail")
    }

    /// Returns a new Queueing Honey Badger instance that starts with the given transactions in its
    /// buffer.
    pub fn build_with_transactions<TI>(&self, txs: TI) -> Result<QueueingHoneyBadger<Tx, NodeUid>>
    where
        TI: IntoIterator<Item = Tx>,
        Tx: Serialize + for<'r> Deserialize<'r> + Debug + Hash + Eq,
    {
        let dyn_hb = DynamicHoneyBadger::builder(self.netinfo.clone())
            .max_future_epochs(self.max_future_epochs)
            .build()?;
        let queue = TransactionQueue(txs.into_iter().collect());
        let mut qhb = QueueingHoneyBadger {
            dyn_hb,
            queue,
            batch_size: self.batch_size,
            output: VecDeque::new(),
        };
        let _ = qhb.propose()?; // Fault log is empty: no contact with other nodes yet.
        Ok(qhb)
    }
}

/// A Honey Badger instance that can handle adding and removing nodes and manages a transaction
/// queue.
pub struct QueueingHoneyBadger<Tx, NodeUid>
where
    Tx: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Ord + Clone + Serialize + for<'r> Deserialize<'r> + Debug + Rand,
{
    /// The target number of transactions to be included in each batch.
    batch_size: usize,
    /// The internal `DynamicHoneyBadger` instance.
    dyn_hb: DynamicHoneyBadger<Vec<Tx>, NodeUid>,
    /// The queue of pending transactions that haven't been output in a batch yet.
    queue: TransactionQueue<Tx>,
    /// The outputs from completed epochs.
    output: VecDeque<Batch<Tx, NodeUid>>,
}

pub type QueueingHoneyBadgerStep<Tx, NodeUid> = Step<NodeUid, Batch<Tx, NodeUid>>;

impl<Tx, NodeUid> DistAlgorithm for QueueingHoneyBadger<Tx, NodeUid>
where
    Tx: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash + Clone,
    NodeUid: Eq + Ord + Clone + Serialize + for<'r> Deserialize<'r> + Debug + Hash + Rand,
{
    type NodeUid = NodeUid;
    type Input = Input<Tx, NodeUid>;
    type Output = Batch<Tx, NodeUid>;
    type Message = Message<NodeUid>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<QueueingHoneyBadgerStep<Tx, NodeUid>> {
        // User transactions are forwarded to `HoneyBadger` right away. Internal messages are
        // in addition signed and broadcast.
        let fault_log = match input {
            Input::User(tx) => {
                self.queue.0.push_back(tx);
                FaultLog::new()
            }
            Input::Change(change) => {
                let step = self.dyn_hb.input(Input::Change(change))?;
                // FIXME: Use the output since `dyn_hb` can output immediately on input.
                step.fault_log
            }
        };
        self.step(fault_log)
    }

    fn handle_message(
        &mut self,
        sender_id: &NodeUid,
        message: Self::Message,
    ) -> Result<QueueingHoneyBadgerStep<Tx, NodeUid>> {
        let Step {
            output,
            mut fault_log,
        } = self.dyn_hb.handle_message(sender_id, message)?;
        for batch in output {
            self.queue.remove_all(batch.iter());
            self.output.push_back(batch);
        }
        fault_log.extend(self.propose()?);
        self.step(fault_log)
    }

    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, NodeUid>> {
        self.dyn_hb.next_message()
    }

    fn terminated(&self) -> bool {
        false
    }

    fn our_id(&self) -> &NodeUid {
        self.dyn_hb.our_id()
    }
}

impl<Tx, NodeUid> QueueingHoneyBadger<Tx, NodeUid>
where
    Tx: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash + Clone,
    NodeUid: Eq + Ord + Clone + Debug + Serialize + for<'r> Deserialize<'r> + Hash + Rand,
{
    /// Returns a new `QueueingHoneyBadgerBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    pub fn builder(netinfo: NetworkInfo<NodeUid>) -> QueueingHoneyBadgerBuilder<Tx, NodeUid> {
        QueueingHoneyBadgerBuilder::new(netinfo)
    }

    fn step(
        &mut self,
        fault_log: FaultLog<NodeUid>,
    ) -> Result<QueueingHoneyBadgerStep<Tx, NodeUid>> {
        Ok(Step::new(self.output.drain(..).collect(), fault_log))
    }

    /// Returns a reference to the internal `DynamicHoneyBadger` instance.
    pub fn dyn_hb(&self) -> &DynamicHoneyBadger<Vec<Tx>, NodeUid> {
        &self.dyn_hb
    }

    /// Initiates the next epoch by proposing a batch from the queue.
    fn propose(&mut self) -> Result<FaultLog<NodeUid>> {
        let amount = cmp::max(1, self.batch_size / self.dyn_hb.netinfo().num_nodes());
        // TODO: This will loop forever if we are the only validator.
        let mut fault_log = FaultLog::new();
        while !self.dyn_hb.has_input() {
            let proposal = self.queue.choose(amount, self.batch_size);
            let step = self.dyn_hb.input(Input::User(proposal))?;
            fault_log.extend(step.fault_log);
            for batch in step.output {
                self.queue.remove_all(batch.iter());
                self.output.push_back(batch);
            }
        }
        Ok(fault_log)
    }
}

pub type Batch<Tx, NodeUid> = DhbBatch<Vec<Tx>, NodeUid>;
