use rand::distributions::{Distribution, Standard};
use rand::{seq::SliceRandom, Rng};
use serde_derive::{Deserialize, Serialize};

use super::SenderQueueableMessage;

/// A `SenderQueue` message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Message<M: SenderQueueableMessage> {
    /// The announcement that this node has reached the given epoch.
    EpochStarted(M::Epoch),
    /// A message of the wrapped algorithm.
    Algo(M),
}

impl<M: SenderQueueableMessage> Distribution<Message<M>> for Standard
where
    Standard: Distribution<M> + Distribution<M::Epoch>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Message<M> {
        let message_type = *["epoch", "algo"].choose(rng).unwrap();

        match message_type {
            "epoch" => Message::EpochStarted(rng.gen()),
            "algo" => Message::Algo(rng.gen()),
            _ => unreachable!(),
        }
    }
}

impl<M: SenderQueueableMessage> From<M> for Message<M> {
    fn from(message: M) -> Self {
        Message::Algo(message)
    }
}
