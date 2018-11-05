use rand::{Rand, Rng};
use serde_derive::{Deserialize, Serialize};

use Epoched;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Message<M: Epoched> {
    EpochStarted(<M as Epoched>::LinEpoch),
    Algo(M),
}

impl<M> Rand for Message<M>
where
    M: Epoched + Rand,
    <M as Epoched>::Epoch: Rand,
    <M as Epoched>::LinEpoch: Rand,
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

impl<M> Epoched for Message<M>
where
    M: Epoched,
    <M as Epoched>::Epoch: From<<M as Epoched>::LinEpoch>,
{
    type Epoch = <M as Epoched>::Epoch;
    type LinEpoch = <M as Epoched>::LinEpoch;

    fn epoch(&self) -> Self::Epoch {
        match self {
            Message::EpochStarted(epoch) => <M as Epoched>::Epoch::from(*epoch),
            Message::Algo(message) => message.epoch(),
        }
    }

    fn linearizable_epoch(&self) -> Option<Self::LinEpoch> {
        match self {
            Message::EpochStarted(epoch) => Some(*epoch),
            Message::Algo(message) => message.linearizable_epoch(),
        }
    }
}

impl<M: Epoched> From<M> for Message<M> {
    fn from(message: M) -> Self {
        Message::Algo(message)
    }
}
