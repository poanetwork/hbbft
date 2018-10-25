use std::collections::BTreeMap;

use {Epoched, NodeIdT};

/// A batch of contributions the algorithm has output.
#[derive(Clone, Debug)]
pub struct Batch<C, N> {
    pub epoch: u64,
    pub contributions: BTreeMap<N, C>,
}

impl<C, N: NodeIdT> Epoched for Batch<C, N> {
    type Epoch = u64;

    /// Returns the **next** `HoneyBadger` epoch after the sequential epoch of the batch.
    fn epoch(&self) -> u64 {
        self.epoch + 1
    }
}

impl<C, N: NodeIdT> Batch<C, N> {
    /// Returns an iterator over references to all transactions included in the batch.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = <&'a C as IntoIterator>::Item>
    where
        &'a C: IntoIterator,
    {
        self.contributions.values().flat_map(|item| item)
    }

    /// Returns an iterator over all transactions included in the batch. Consumes the batch.
    pub fn into_tx_iter(self) -> impl Iterator<Item = <C as IntoIterator>::Item>
    where
        C: IntoIterator,
    {
        self.contributions.into_iter().flat_map(|(_, vec)| vec)
    }

    /// Returns the number of transactions in the batch (without detecting duplicates).
    pub fn len<T>(&self) -> usize
    where
        C: AsRef<[T]>,
    {
        self.contributions
            .values()
            .map(C::as_ref)
            .map(<[T]>::len)
            .sum()
    }

    /// Returns `true` if the batch contains no transactions.
    pub fn is_empty<T>(&self) -> bool
    where
        C: AsRef<[T]>,
    {
        self.contributions
            .values()
            .map(C::as_ref)
            .all(<[T]>::is_empty)
    }
}
