use crypto::DecryptionShare;
use rand::Rand;

use common_subset;

/// The content of a `HoneyBadger` message. It should be further annotated with an epoch.
#[derive(Clone, Debug, Deserialize, Rand, Serialize)]
pub enum MessageContent<N: Rand> {
    /// A message belonging to the common subset algorithm in the given epoch.
    CommonSubset(common_subset::Message<N>),
    /// A decrypted share of the output of `proposer_id`.
    DecryptionShare {
        proposer_id: N,
        share: DecryptionShare,
    },
}

impl<N: Rand> MessageContent<N> {
    pub fn with_epoch(self, epoch: u64) -> Message<N> {
        Message {
            epoch,
            content: self,
        }
    }
}

/// A message sent to or received from another node's Honey Badger instance.
#[derive(Clone, Debug, Deserialize, Rand, Serialize)]
pub struct Message<N: Rand> {
    pub(super) epoch: u64,
    pub(super) content: MessageContent<N>,
}

impl<N: Rand> Message<N> {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
