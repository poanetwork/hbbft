use std::collections::BTreeMap;

/// A batch of contributions the algorithm has output.
#[derive(Clone, Debug)]
pub struct Batch<C, NodeUid> {
    pub epoch: u64,
    pub contributions: BTreeMap<NodeUid, C>,
}

impl<C, NodeUid: Ord> Batch<C, NodeUid> {
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
    pub fn len<Tx>(&self) -> usize
    where
        C: AsRef<[Tx]>,
    {
        self.contributions
            .values()
            .map(C::as_ref)
            .map(<[Tx]>::len)
            .sum()
    }

    /// Returns `true` if the batch contains no transactions.
    pub fn is_empty<Tx>(&self) -> bool
    where
        C: AsRef<[Tx]>,
    {
        self.contributions
            .values()
            .map(C::as_ref)
            .all(<[Tx]>::is_empty)
    }
}
