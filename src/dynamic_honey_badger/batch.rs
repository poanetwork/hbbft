use std::collections::BTreeMap;
use std::fmt::Debug;

use rand::Rand;
use serde::{Deserialize, Serialize};

use super::{ChangeState, JoinPlan};
use messaging::{NetworkInfo, ValidatorMap};

/// A batch of transactions the algorithm has output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Batch<C, NodeUid> {
    /// The sequence number: there is exactly one batch in each epoch.
    pub(super) epoch: u64,
    /// The user contributions committed in this epoch.
    pub(super) contributions: BTreeMap<NodeUid, C>,
    /// The current state of adding or removing a node: whether any is in progress, or completed
    /// this epoch.
    change: ChangeState<NodeUid>,
    /// The public network info, if `change` is not `None`.
    validator_map: Option<ValidatorMap<NodeUid>>,
}

impl<C, NodeUid: Ord + Rand + Clone + Debug> Batch<C, NodeUid> {
    /// Returns a new, empty batch with the given epoch.
    pub fn new(epoch: u64) -> Self {
        Batch {
            epoch,
            contributions: BTreeMap::new(),
            change: ChangeState::None,
            validator_map: None,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
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

    /// Returns the `JoinPlan` to be sent to new observer nodes, if it is possible to join in the
    /// next epoch.
    pub fn join_plan(&self) -> Option<JoinPlan<NodeUid>>
    where
        NodeUid: Serialize + for<'r> Deserialize<'r>,
    {
        self.validator_map.as_ref().map(|validator_map| JoinPlan {
            epoch: self.epoch + 1,
            change: self.change.clone(),
            validator_map: validator_map.clone(),
        })
    }

    /// Sets the current change state, and if it is not `None`, inserts the network information so
    /// that a `JoinPlan` can be generated for the next epoch.
    pub(super) fn set_change(
        &mut self,
        change: ChangeState<NodeUid>,
        netinfo: &NetworkInfo<NodeUid>,
    ) {
        self.change = change;
        if self.change != ChangeState::None {
            self.validator_map = Some(netinfo.validator_map().clone());
        }
    }
}
