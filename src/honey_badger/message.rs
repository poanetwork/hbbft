use rand::Rand;

use subset;
use threshold_decryption;

/// The content of a `HoneyBadger` message. It should be further annotated with an epoch.
#[derive(Clone, Debug, Deserialize, PartialEq, Rand, Serialize)]
pub enum MessageContent<N: Rand> {
    /// A message belonging to the subset algorithm in the given epoch.
    Subset(subset::Message<N>),
    /// A decrypted share of the output of `proposer_id`.
    DecryptionShare {
        proposer_id: N,
        share: threshold_decryption::Message,
    },
}

impl<N: Rand> MessageContent<N> {
    pub fn with_epoch(self, epoch: u64) -> Message<N> {
        Message::HoneyBadger {
            epoch,
            content: self,
        }
    }
}

/// A message sent to or received from another node's Honey Badger instance.
#[derive(Clone, Debug, Deserialize, Rand, Serialize)]
pub enum Message<N: Rand> {
    /// A Honey Badger algorithm message annotated with the epoch number.
    HoneyBadger {
        epoch: u64,
        content: MessageContent<N>,
    },
    /// A Honey Badger participant uses this message to announce its transition to the given
    /// epoch. This message informs the recipients that this participant now accepts messages for
    /// `max_future_epochs + 1` epochs counting from the given one, and drops any incoming messages
    /// from earlier epochs.
    EpochStarted(u64),
}

impl<N: Rand> Message<N> {
    /// Returns the epoch from which the message originated.
    pub fn epoch(&self) -> u64 {
        match *self {
            Message::HoneyBadger { epoch, .. } => epoch,
            Message::EpochStarted(epoch) => epoch,
        }
    }
}
