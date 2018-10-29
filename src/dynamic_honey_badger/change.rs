use crypto::PublicKey;
use serde_derive::{Deserialize, Serialize};

/// A node change action: adding or removing a node.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum Change<N> {
    /// Add a node. The public key is used only temporarily, for key generation.
    Add(N, PublicKey),
    /// Remove a node.
    Remove(N),
}

impl<N> Change<N> {
    /// Returns the ID of the current candidate for being added, if any.
    pub fn candidate(&self) -> Option<&N> {
        match *self {
            Change::Add(ref id, _) => Some(id),
            Change::Remove(_) => None,
        }
    }
}

/// A change status: whether a node addition or removal is currently in progress or completed.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum ChangeState<N> {
    /// No node is currently being considered for addition or removal.
    None,
    /// A change is currently in progress. If it is an addition, all broadcast messages must be
    /// sent to the new node, too.
    InProgress(Change<N>),
    /// A change has been completed in this epoch. From the next epoch on, the new composition of
    /// the network will perform the consensus process.
    Complete(Change<N>),
}
