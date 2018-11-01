use crypto::PublicKey;
use serde_derive::{Deserialize, Serialize};
use threshold_decryption::EncryptionSchedule;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum NodeChange<N> {
    /// Add a node. The public key is used only temporarily, for key generation.
    Add(N, PublicKey),
    /// Remove a node.
    Remove(N),
}

impl<N> NodeChange<N> {
    /// Returns the ID of the current candidate for being added, if any.
    pub fn candidate(&self) -> Option<&N> {
        match *self {
            NodeChange::Add(ref id, _) => Some(id),
            NodeChange::Remove(_) => None,
        }
    }
}

/// A node change action: adding or removing a node.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum Change<N> {
    // Add or Remove a node from the set of validators
    NodeChange(NodeChange<N>),
    /// Change the threshold encryption schedule.
    /// Increase frequency to prevent censorship or decrease frequency for increased throughput.
    EncryptionSchedule(EncryptionSchedule),
}

impl<N> Change<N> {
    /// Returns the ID of the current candidate for being added, if any.
    pub fn candidate(&self) -> Option<&N> {
        match self {
            Change::NodeChange(node_change) => node_change.candidate(),
            _ => None,
        }
    }
}

/// A change status: whether a change to the network is currently in progress or completed.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum ChangeState<N> {
    /// No change is currently being considered.
    None,
    /// A change is currently in progress. If it is a node addition, all broadcast messages must be
    /// sent to the new node, too.
    InProgress(Change<N>),
    /// A change has been completed in this epoch. From the next epoch on, the new composition of
    /// the network will perform the consensus process.
    Complete(Change<N>),
}
