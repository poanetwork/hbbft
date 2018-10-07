use std::collections::{HashSet, VecDeque};
use std::{cmp, fmt};

use rand::{self, Isaac64Rng, Rng};

use Contribution;
use util::SubRng;

/// An interface to the transaction queue. A transaction queue is a structural part of
/// `QueueingHoneyBadger` that manages enqueueing of transactions for a future batch and dequeueing
/// of transactions to become part of a current batch.
pub trait TransactionQueue<T> {
    fn is_empty(&self) -> bool;
    fn push_back(&mut self, t: T);
    fn choose(&mut self, amount: usize, batch_size: usize) -> Vec<T>;
    fn remove_all<'a, I>(&mut self, txs: I)
    where
        I: IntoIterator<Item = &'a T>,
        T: 'a + Contribution;
}

/// A wrapper providing a few convenience methods for a queue of pending transactions.
pub struct VecDequeTransactionQueue<T> {
    /// Random number generator passed on from the algorithm instance.
    rng: Box<dyn Rng + Send + Sync>,
    pub transactions: VecDeque<T>,
}

impl<T> TransactionQueue<T> for VecDequeTransactionQueue<T>
where
    T: Clone,
{
    fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    fn push_back(&mut self, t: T) {
        self.transactions.push_back(t);
    }

    /// Removes the given transactions from the queue.
    fn remove_all<'a, I>(&mut self, txs: I)
    where
        I: IntoIterator<Item = &'a T>,
        T: 'a + Contribution,
    {
        let tx_set: HashSet<_> = txs.into_iter().collect();
        self.transactions.retain(|tx| !tx_set.contains(tx));
    }

    /// Returns a new set of `amount` transactions, randomly chosen from the first `batch_size`.
    /// No transactions are removed from the queue.
    // TODO: Return references, once the `HoneyBadger` API accepts them. Remove `Clone` bound.
    fn choose(&mut self, amount: usize, batch_size: usize) -> Vec<T> {
        let limit = cmp::min(batch_size, self.transactions.len());
        let sample = match rand::seq::sample_iter(
            &mut self.rng,
            self.transactions.iter().take(limit),
            amount,
        ) {
            Ok(choice) => choice,
            Err(choice) => choice, // Fewer than `amount` were available, which is fine.
        };
        sample.into_iter().cloned().collect()
    }
}

impl<T> Default for VecDequeTransactionQueue<T>
where
    T: Clone,
{
    /// Creates an empty transaction queue with a default random number generator.
    fn default() -> Self {
        let mut rng = rand::thread_rng().gen::<Isaac64Rng>();
        VecDequeTransactionQueue::new(&mut rng, VecDeque::new())
    }
}

impl<T> fmt::Debug for VecDequeTransactionQueue<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VecDequeTransactionQueue")
            .field("transactions", &self.transactions)
            .field("rng", &"<RNG>")
            .finish()
    }
}

impl<T> Extend<T> for VecDequeTransactionQueue<T> {
    /// Extends the transaction queue with the contents of a given iterator.
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for tx in iter {
            self.transactions.push_back(tx);
        }
    }
}
impl<T: Clone> VecDequeTransactionQueue<T> {
    /// Returns a new `VecDequeTransactionQueue` object.
    pub fn new<R: Rng + Send + Sync>(rng: &mut R, transactions: VecDeque<T>) -> Self {
        VecDequeTransactionQueue {
            rng: rng.sub_rng(),
            transactions,
        }
    }
}
