use super::ChangeState;
use std::collections::BTreeMap;

/// A batch of transactions the algorithm has output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Batch<C, NodeUid> {
    /// The sequence number: there is exactly one batch in each epoch.
    pub epoch: u64,
    /// The user contributions committed in this epoch.
    pub contributions: BTreeMap<NodeUid, C>,
    /// The current state of adding or removing a node: whether any is in progress, or completed
    /// this epoch.
    pub change: ChangeState<NodeUid>,
}

impl<C, NodeUid: Ord> Batch<C, NodeUid> {
    /// Returns a new, empty batch with the given epoch.
    pub fn new(epoch: u64) -> Self {
        Batch {
            epoch,
            contributions: BTreeMap::new(),
            change: ChangeState::None,
        }
    }

    /// Returns whether any change to the set of participating nodes is in progress or was
    /// completed in this epoch.
    pub fn change(&self) -> &ChangeState<NodeUid> {
        &self.change
    }

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
