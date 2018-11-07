use rand::{Rand, Rng};
use serde_derive::{Deserialize, Serialize};

use Epoched;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Message<M: Epoched> {
    EpochStarted(<M as Epoched>::Epoch),
    Algo(M),
}

impl<M> Rand for Message<M>
where
    M: Epoched + Rand,
    <M as Epoched>::Epoch: Rand,
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

impl<M: Epoched> From<M> for Message<M> {
    fn from(message: M) -> Self {
        Message::Algo(message)
    }
}
