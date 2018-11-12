use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use rand::{self, Rand, Rng};
use serde::{de::DeserializeOwned, Serialize};

use super::{EncryptionSchedule, HoneyBadger};
use honey_badger::SubsetHandlingStrategy;
use util::SubRng;
use {Contribution, NetworkInfo, NodeIdT};

/// A Honey Badger builder, to configure the parameters and create new instances of `HoneyBadger`.
pub struct HoneyBadgerBuilder<C, N> {
    /// Shared network data.
    netinfo: Arc<NetworkInfo<N>>,
    /// A session identifier. Different session IDs foil replay attacks in two instances with the
    /// same epoch numbers and the same validators.
    session_id: u64,
    /// Start in this epoch.
    epoch: u64,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: u64,
    /// Random number generator passed on to algorithm instance for signing and encrypting.
    rng: Box<dyn Rng>,
    /// Strategy used to handle the output of the `Subset` algorithm.
    subset_handling_strategy: SubsetHandlingStrategy,
    /// Whether to generate a pseudorandom value in each epoch.
    random_value: bool,
    /// Schedule for adding threshold encryption to some percentage of rounds
    encryption_schedule: EncryptionSchedule,
    _phantom: PhantomData<C>,
}

impl<C, N> HoneyBadgerBuilder<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Rand,
{
    /// Returns a new `HoneyBadgerBuilder` configured to use the node IDs and cryptographic keys
    /// specified by `netinfo`.
    pub fn new(netinfo: Arc<NetworkInfo<N>>) -> Self {
        HoneyBadgerBuilder {
            netinfo,
            session_id: 0,
            epoch: 0,
            max_future_epochs: 3,
            rng: Box::new(rand::thread_rng()),
            subset_handling_strategy: SubsetHandlingStrategy::Incremental,
            random_value: false,
            encryption_schedule: EncryptionSchedule::Always,
            _phantom: PhantomData,
        }
    }

    /// Sets the random number generator for the public key cryptography.
    pub fn rng<R: Rng + 'static>(&mut self, rng: R) -> &mut Self {
        self.rng = Box::new(rng);
        self
    }

    /// Sets the session identifier.
    ///
    /// Different session IDs foil replay attacks in two instances with the same epoch numbers and
    /// the same validators.
    pub fn session_id(&mut self, session_id: u64) -> &mut Self {
        self.session_id = session_id;
        self
    }

    /// Sets the starting epoch to the given value.
    pub fn epoch(&mut self, epoch: u64) -> &mut Self {
        self.epoch = epoch;
        self
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: u64) -> &mut Self {
        self.max_future_epochs = max_future_epochs;
        self
    }

    /// Sets the strategy to use when handling `Subset` output.
    pub fn subset_handling_strategy(
        &mut self,
        subset_handling_strategy: SubsetHandlingStrategy,
    ) -> &mut Self {
        self.subset_handling_strategy = subset_handling_strategy;
        self
    }

    /// Whether to generate a pseudorandom value in each epoch.
    pub fn random_value(&mut self, random_value: bool) -> &mut Self {
        self.random_value = random_value;
        self
    }

    /// Sets the schedule to use for threshold encryption.
    pub fn encryption_schedule(&mut self, encryption_schedule: EncryptionSchedule) -> &mut Self {
        self.encryption_schedule = encryption_schedule;
        self
    }

    /// Creates a new Honey Badger instance.
    pub fn build(&mut self) -> HoneyBadger<C, N> {
        HoneyBadger {
            netinfo: self.netinfo.clone(),
            session_id: self.session_id,
            epoch: self.epoch,
            has_input: false,
            epochs: BTreeMap::new(),
            max_future_epochs: self.max_future_epochs as u64,
            rng: Box::new(self.rng.sub_rng()),
            subset_handling_strategy: self.subset_handling_strategy.clone(),
            encryption_schedule: self.encryption_schedule,
            random_value: self.random_value,
        }
    }
}
