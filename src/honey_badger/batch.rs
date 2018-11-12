use crypto::Signature;
use std::collections::BTreeMap;

use NodeIdT;

/// A batch of contributions the algorithm has output.
#[derive(Clone, Debug)]
pub struct Batch<C, N> {
    /// This batch's epoch number. Each epoch produces exactly one batch.
    pub epoch: u64,
    /// The set of agreed contributions, by the contributor's node ID.
    pub contributions: BTreeMap<N, C>,
    /// The signature that can be used as a pseudorandom value: None of the validators knew
    /// its value before the other of the batch were decided.
    ///
    /// If the `random_value` option is `false` (default), this is `None`.
    pub random_value: Option<Signature>,
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
