use crypto::DecryptionShare;
use rand::Rand;

use common_subset;

/// The content of a `HoneyBadger` message. It should be further annotated with an epoch.
#[derive(Clone, Debug, Deserialize, Rand, Serialize)]
pub enum MessageContent<NodeUid: Rand> {
    /// A message belonging to the common subset algorithm in the given epoch.
    CommonSubset(common_subset::Message<NodeUid>),
    /// A decrypted share of the output of `proposer_id`.
    DecryptionShare {
        proposer_id: NodeUid,
        share: DecryptionShare,
    },
}

impl<NodeUid: Rand> MessageContent<NodeUid> {
    pub fn with_epoch(self, epoch: u64) -> Message<NodeUid> {
        Message {
            epoch,
            content: self,
        }
    }
}

/// A message sent to or received from another node's Honey Badger instance.
#[derive(Clone, Debug, Deserialize, Rand, Serialize)]
pub struct Message<NodeUid: Rand> {
    pub(super) epoch: u64,
    pub(super) content: MessageContent<NodeUid>,
}

impl<NodeUid: Rand> Message<NodeUid> {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
