use std::collections::{HashSet, VecDeque};
use std::{cmp, fmt};

use rand::{self, Rng};

use Contribution;
use util::SubRng;

/// A wrapper providing a few convenience methods for a queue of pending transactions.
pub struct TransactionQueue<T> {
    /// Random number generator passed on from the algorithm instance.
    rng: Box<dyn Rng + Send + Sync>,
    pub transactions: VecDeque<T>,
}

impl<T> fmt::Debug for TransactionQueue<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TransactionQueue")
            .field("transactions", &self.transactions)
            .field("rng", &"<RNG>")
            .finish()
    }
}

impl<T: Clone> TransactionQueue<T> {
    /// Returns a new `TransactionQueue` object.
    pub fn new<R: Rng + Send + Sync>(rng: &mut R, transactions: VecDeque<T>) -> Self {
        TransactionQueue {
            rng: rng.sub_rng(),
            transactions,
        }
    }

    /// Removes the given transactions from the queue.
    pub fn remove_all<'a, I>(&mut self, txs: I)
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
    pub fn choose(&mut self, amount: usize, batch_size: usize) -> Vec<T> {
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
