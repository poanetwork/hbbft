use std::collections::BTreeMap;

use crate::crypto::PublicKey;
use serde_derive::{Deserialize, Serialize};

use super::EncryptionSchedule;

/// A node change action: adding or removing a node.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum Change<N: Ord> {
    /// Change the set of validators to the one in the provided map. There are no restrictions on
    /// the new set of validators. In particular, it can be disjoint with the current set of
    /// validators.
    NodeChange(BTreeMap<N, PublicKey>),
    /// Change the threshold encryption schedule.
    /// Increase frequency to prevent censorship or decrease frequency for increased throughput.
    EncryptionSchedule(EncryptionSchedule),
}

/// A change status: whether a change to the network is currently in progress or completed.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum ChangeState<N: Ord> {
    /// No change is currently being considered.
    None,
    /// A change is currently in progress. If it is a node addition, all broadcast messages must be
    /// sent to the new node, too.
    InProgress(Change<N>),
    /// A change has been completed in this epoch. From the next epoch on, the new composition of
    /// the network will perform the consensus process.
    Complete(Change<N>),
}
