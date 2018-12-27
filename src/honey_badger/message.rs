// `threshold_sign::Message` triggers this Clippy lint, but `Box<T>` doesn't implement `Rand`.
#![allow(clippy::large_enum_variant)]

use rand::distributions::{Distribution, Standard};
use rand::{seq::SliceRandom, Rng};
use serde_derive::{Deserialize, Serialize};

use crate::subset;
use crate::threshold_decrypt;

/// The content of a `HoneyBadger` message. It should be further annotated with an epoch.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum MessageContent<N> {
    /// A message belonging to the subset algorithm in the given epoch.
    Subset(subset::Message<N>),
    /// A decryption share of the output of `proposer_id`.
    DecryptionShare {
        /// The ID of the node that proposed the contribution that is being decrypted.
        proposer_id: N,
        /// The decryption share: _f + 1_ of these are required to decrypt the contribution.
        share: threshold_decrypt::Message,
    },
}

impl<N> Distribution<MessageContent<N>> for Standard
where
    Standard: Distribution<N>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MessageContent<N> {
        let message_type = *["subset", "dec_share"].choose(rng).unwrap();

        match message_type {
            "subset" => MessageContent::Subset(rng.gen::<subset::Message<N>>()),
            "dec_share" => MessageContent::DecryptionShare {
                proposer_id: rng.gen::<N>(),
                share: rng.gen::<threshold_decrypt::Message>(),
            },
            _ => unreachable!(),
        }
    }
}

impl<N> MessageContent<N> {
    /// Wraps this content in a `Message` with the given epoch.
    pub fn with_epoch(self, epoch: u64) -> Message<N> {
        Message {
            epoch,
            content: self,
        }
    }
}

/// A message sent to or received from another node's Honey Badger instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message<N> {
    pub(super) epoch: u64,
    pub(super) content: MessageContent<N>,
}

impl<N> Distribution<Message<N>> for Standard
where
    Standard: Distribution<N>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Message<N> {
        Message {
            epoch: rng.gen::<u64>(),
            content: rng.gen::<MessageContent<N>>(),
        }
    }
}

impl<N> Message<N> {
    /// Returns this message's Honey Badger epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
