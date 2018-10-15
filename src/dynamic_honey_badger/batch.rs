use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{ChangeState, JoinPlan};
use {NetworkInfo, NodeIdT};

/// A batch of transactions the algorithm has output.
#[derive(Clone, Debug)]
pub struct Batch<C, N> {
    /// The sequence number: there is exactly one batch in each epoch.
    pub(super) epoch: u64,
    /// The user contributions committed in this epoch.
    pub(super) contributions: BTreeMap<N, C>,
    /// The current state of adding or removing a node: whether any is in progress, or completed
    /// this epoch.
    pub(super) change: ChangeState<N>,
    /// The network info that applies to the _next_ epoch.
    pub(super) netinfo: Arc<NetworkInfo<N>>,
}

impl<C, N: NodeIdT> Batch<C, N> {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns whether any change to the set of participating nodes is in progress or was
    /// completed in this epoch.
    pub fn change(&self) -> &ChangeState<N> {
        &self.change
    }

    /// Returns the `NetworkInfo` containing the information about the validators that will produce
    /// the _next_ epoch after this one.
    pub fn network_info(&self) -> &Arc<NetworkInfo<N>> {
        &self.netinfo
    }

    /// Returns the contributions and their proposers.
    pub fn contributions(&self) -> impl Iterator<Item = (&N, &C)> {
        self.contributions.iter()
    }

    /// Returns an iterator over references to all transactions included in the batch.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = <&'a C as IntoIterator>::Item>
    where
        &'a C: IntoIterator,
    {
        self.contributions.values().flatten()
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

    /// Returns the `JoinPlan` to be sent to new observer nodes, if it is possible to join in the
    /// next epoch.
    pub fn join_plan(&self) -> Option<JoinPlan<N>>
    where
        N: Serialize + for<'r> Deserialize<'r>,
    {
        if self.change == ChangeState::None {
            return None;
        }
        Some(JoinPlan {
            epoch: self.epoch + 1,
            change: self.change.clone(),
            pub_key_set: self.netinfo.public_key_set().clone(),
            pub_keys: self.netinfo.public_key_map().clone(),
        })
    }

    /// Returns `true` if all public parts of the batch are equal to `other`. Secret keys and our
    /// own node ID are ignored.
    pub fn public_eq(&self, other: &Self) -> bool
    where
        C: PartialEq,
    {
        self.epoch == other.epoch
            && self.contributions == other.contributions
            && self.change == other.change
            && self.netinfo.public_key_set() == other.netinfo.public_key_set()
            && self.netinfo.public_key_map() == other.netinfo.public_key_map()
    }
}
