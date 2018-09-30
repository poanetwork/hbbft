use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use rand::{self, Rand, Rng};
use serde::{Deserialize, Serialize};

use super::{HoneyBadger, Message, Step};
use honey_badger::SubsetHandlingStrategy;
use messaging::{NetworkInfo, Target};
use traits::{Contribution, NodeIdT};
use util::SubRng;

/// A Honey Badger builder, to configure the parameters and create new instances of `HoneyBadger`.
pub struct HoneyBadgerBuilder<C, N>
where
    N: Rand,
{
    /// Shared network data.
    netinfo: Arc<NetworkInfo<N>>,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    /// Random number generator passed on to algorithm instance for signing and encrypting.
    rng: Box<dyn Rng>,
    subset_handling_strategy: SubsetHandlingStrategy,
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
            rng: Box::new(rand::thread_rng()),
            subset_handling_strategy: SubsetHandlingStrategy::Incremental,
            _phantom: PhantomData,
        }
    }

    /// Sets the random number generator for the public key cryptography.
    pub fn rng<R: Rng + 'static>(&mut self, rng: R) -> &mut Self {
        self.rng = Box::new(rng);
        self
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: usize) -> &mut Self {
        self.max_future_epochs = max_future_epochs;
        self
    }

    pub fn subset_handling_strategy(
        &mut self,
        subset_handling_strategy: SubsetHandlingStrategy,
    ) -> &mut Self {
        self.subset_handling_strategy = subset_handling_strategy;
        self
    }

    /// Creates a new Honey Badger instance in epoch 0 and makes the initial `Step` on that
    /// instance.
    pub fn build(&mut self) -> (HoneyBadger<C, N>, Step<C, N>) {
        let hb = HoneyBadger {
            netinfo: self.netinfo.clone(),
            epoch: 0,
            has_input: false,
            epochs: BTreeMap::new(),
            max_future_epochs: self.max_future_epochs as u64,
            incoming_queue: BTreeMap::new(),
            remote_epochs: BTreeMap::new(),
            rng: Box::new(self.rng.sub_rng()),
            subset_handling_strategy: self.subset_handling_strategy.clone(),
        };
        let step = if self.netinfo.is_validator() {
            // The first message in an epoch announces the epoch transition.
            Target::All.message(Message::EpochStarted(0)).into()
        } else {
            Step::default()
        };
        (hb, step)
    }
}
