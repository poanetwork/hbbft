use rand::Rand;
use rand_derive::Rand;
use serde_derive::{Deserialize, Serialize};

use subset;
use threshold_decrypt;

/// The content of a `HoneyBadger` message. It should be further annotated with an epoch.
#[derive(Clone, Debug, Deserialize, Rand, Serialize)]
// `threshold_sign::Message` triggers this Clippy lint, but `Box<T>` doesn't implement `Rand`.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum MessageContent<N: Rand> {
    /// A message belonging to the subset algorithm in the given epoch.
    Subset(subset::Message<N>),
    /// A decrypted share of the output of `proposer_id`.
    DecryptionShare {
        proposer_id: N,
        share: threshold_decrypt::Message,
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
    /// Returns this message's Honey Badger epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
