use rand::distributions::{Distribution, Standard};
use rand::Rng;
use rand_derive::Rand;
use serde_derive::{Deserialize, Serialize};

use crate::binary_agreement;
use crate::broadcast;

/// Message from Subset to remote nodes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message<N> {
    /// The proposer whose contribution this message is about.
    pub proposer_id: N,
    /// The wrapped broadcast or agreement message.
    pub content: MessageContent,
}

impl<N> Distribution<Message<N>> for Standard
where
    Standard: Distribution<N>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Message<N> {
        Message {
            proposer_id: rng.gen::<N>(),
            content: rng.gen::<MessageContent>(),
        }
    }
}

/// A message about a particular proposer's contribution.
#[derive(Serialize, Deserialize, Clone, Debug, Rand)]
pub enum MessageContent {
    /// A wrapped message for the broadcast instance, to deliver the proposed value.
    Broadcast(broadcast::Message),
    /// A wrapped message for the agreement instance, to decide on whether to accept the value.
    Agreement(binary_agreement::Message),
}

impl MessageContent {
    /// Returns a `Message` with this content and the specified proposer ID.
    pub(super) fn with<N>(self, proposer_id: N) -> Message<N> {
        Message {
            proposer_id,
            content: self,
        }
    }
}
