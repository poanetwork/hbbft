use std::cmp;
use std::collections::{HashSet, VecDeque};

use rand;

use Contribution;

/// A wrapper providing a few convenience methods for a queue of pending transactions.
#[derive(Debug)]
pub struct TransactionQueue<T>(pub VecDeque<T>);

impl<T: Clone> TransactionQueue<T> {
    /// Removes the given transactions from the queue.
    pub fn remove_all<'a, I>(&mut self, txs: I)
    where
        I: IntoIterator<Item = &'a T>,
        T: 'a + Contribution,
    {
        let tx_set: HashSet<_> = txs.into_iter().collect();
        self.0.retain(|tx| !tx_set.contains(tx));
    }

    /// Returns a new set of `amount` transactions, randomly chosen from the first `batch_size`.
    /// No transactions are removed from the queue.
    // TODO: Return references, once the `HoneyBadger` API accepts them. Remove `Clone` bound.
    pub fn choose(&self, amount: usize, batch_size: usize) -> Vec<T> {
        let mut rng = rand::thread_rng();
        let limit = cmp::min(batch_size, self.0.len());
        let sample = match rand::seq::sample_iter(&mut rng, self.0.iter().take(limit), amount) {
            Ok(choice) => choice,
            Err(choice) => choice, // Fewer than `amount` were available, which is fine.
        };
        sample.into_iter().cloned().collect()
    }
}
