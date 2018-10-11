use std::collections::HashSet;
use std::{cmp, fmt};

use rand::{self, Rng};

use Contribution;

/// An interface to the transaction queue. A transaction queue is a structural part of
/// `QueueingHoneyBadger` that manages enqueueing of transactions for a future batch and dequeueing
/// of transactions to become part of a current batch.
pub trait TransactionQueue<T>: fmt::Debug + Default + Extend<T> + Sync + Send {
    /// Checks whether the queue is empty.
    fn is_empty(&self) -> bool;
    /// Returns a new set of `amount` transactions, randomly chosen from the first `batch_size`.
    /// No transactions are removed from the queue.
    // TODO: Return references, once the `HoneyBadger` API accepts them.
    fn choose<R: Rng>(&mut self, rng: &mut R, amount: usize, batch_size: usize) -> Vec<T>;
    /// Removes the given transactions from the queue.
    fn remove_multiple<'a, I>(&mut self, txs: I)
    where
        I: IntoIterator<Item = &'a T>,
        T: 'a + Contribution;
}

impl<T> TransactionQueue<T> for Vec<T>
where
    T: Clone + fmt::Debug + Sync + Send,
{
    #[inline]
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    #[inline]
    fn remove_multiple<'a, I>(&mut self, txs: I)
    where
        I: IntoIterator<Item = &'a T>,
        T: 'a + Contribution,
    {
        let tx_set: HashSet<_> = txs.into_iter().collect();
        self.retain(|tx| !tx_set.contains(tx));
    }

    // TODO: Return references, once the `HoneyBadger` API accepts them. Remove `Clone` bound.
    #[inline]
    fn choose<R: Rng>(&mut self, rng: &mut R, amount: usize, batch_size: usize) -> Vec<T> {
        let limit = cmp::min(batch_size, self.len());
        let sample = match rand::seq::sample_iter(rng, self.iter().take(limit), amount) {
            Ok(choice) => choice,
            Err(choice) => choice, // Fewer than `amount` were available, which is fine.
        };
        sample.into_iter().cloned().collect()
    }
}
