use std::collections::BTreeMap;

use rand::Rand;
use serde::{Deserialize, Serialize};

use super::{ChangeState, JoinPlan};
use crypto::{PublicKey, PublicKeySet};
use messaging::NetworkInfo;
use traits::NodeUidT;

/// A batch of transactions the algorithm has output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Batch<C, N> {
    /// The sequence number: there is exactly one batch in each epoch.
    pub(super) epoch: u64,
    /// The user contributions committed in this epoch.
    pub(super) contributions: BTreeMap<N, C>,
    /// The current state of adding or removing a node: whether any is in progress, or completed
    /// this epoch.
    change: ChangeState<N>,
    /// The public network info, if `change` is not `None`.
    pub_netinfo: Option<(PublicKeySet, BTreeMap<N, PublicKey>)>,
}

impl<C, N: NodeUidT + Rand> Batch<C, N> {
    /// Returns a new, empty batch with the given epoch.
    pub fn new(epoch: u64) -> Self {
        Batch {
            epoch,
            contributions: BTreeMap::new(),
            change: ChangeState::None,
            pub_netinfo: None,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns whether any change to the set of participating nodes is in progress or was
    /// completed in this epoch.
    pub fn change(&self) -> &ChangeState<N> {
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
        self.pub_netinfo
            .as_ref()
            .map(|&(ref pub_key_set, ref pub_keys)| JoinPlan {
                epoch: self.epoch + 1,
                change: self.change.clone(),
                pub_key_set: pub_key_set.clone(),
                pub_keys: pub_keys.clone(),
            })
    }

    /// Sets the current change state, and if it is not `None`, inserts the network information so
    /// that a `JoinPlan` can be generated for the next epoch.
    pub(super) fn set_change(&mut self, change: ChangeState<N>, netinfo: &NetworkInfo<N>) {
        self.change = change;
        if self.change != ChangeState::None {
            self.pub_netinfo = Some((
                netinfo.public_key_set().clone(),
                netinfo.public_key_map().clone(),
            ));
        }
    }
}
