use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use rand::Rand;
use serde::{Deserialize, Serialize};

use super::{HoneyBadger, Message, Step};
use messaging::{NetworkInfo, Target};
use traits::{Contribution, NodeIdT};

/// A Honey Badger builder, to configure the parameters and create new instances of `HoneyBadger`.
pub struct HoneyBadgerBuilder<C, N>
where
    N: Rand,
{
    /// Shared network data.
    netinfo: Arc<NetworkInfo<N>>,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    _phantom: PhantomData<C>,
}

impl<C, N> HoneyBadgerBuilder<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeIdT + Rand,
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn new(netinfo: Arc<NetworkInfo<N>>) -> Self {
        HoneyBadgerBuilder {
            netinfo,
            max_future_epochs: 3,
            _phantom: PhantomData,
        }
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: usize) -> &mut Self {
        self.max_future_epochs = max_future_epochs;
        self
    }

    /// Creates a new Honey Badger instance in epoch 0 and makes the initial `Step` on that
    /// instance.
    pub fn build(&self) -> (HoneyBadger<C, N>, Step<C, N>) {
        let epoch = 0;
        let hb = HoneyBadger {
            netinfo: self.netinfo.clone(),
            epoch,
            has_input: false,
            epochs: BTreeMap::new(),
            max_future_epochs: self.max_future_epochs as u64,
            outgoing_queue: BTreeMap::new(),
            remote_epochs: BTreeMap::new(),
        };
        // The first message in an epoch announces the epoch transition.
        (hb, Target::All.message(Message::EpochStarted(epoch)).into())
    }
}
