use rand::{Rand, Rng};
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

impl<M> Rand for Message<M>
where
    M: SenderQueueableMessage + Rand,
    M::Epoch: Rand,
{
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let message_type = *rng.choose(&["epoch", "algo"]).unwrap();

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
