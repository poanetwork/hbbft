use std::default::Default;
use std::iter::once;
use std::marker::PhantomData;
use std::sync::Arc;

use crate::crypto::{SecretKey, SecretKeySet};
use serde::{de::DeserializeOwned, Serialize};

use super::{DynamicHoneyBadger, EncryptionSchedule, JoinPlan, Result, Step};
use crate::honey_badger::{Params, SubsetHandlingStrategy};
use crate::{to_pub_keys, Contribution, NetworkInfo, NodeIdT, PubKeyMap};

/// A Dynamic Honey Badger builder, to configure the parameters and create new instances of
/// `DynamicHoneyBadger`.
pub struct DynamicHoneyBadgerBuilder<C, N> {
    /// Start in this era.
    era: u64,
    /// Start in this epoch.
    epoch: u64,
    /// Parameters controlling Honey Badger's behavior and performance.
    params: Params,
    _phantom: PhantomData<(C, N)>,
}

impl<C, N: Ord> Default for DynamicHoneyBadgerBuilder<C, N> {
    fn default() -> Self {
        DynamicHoneyBadgerBuilder {
            era: 0,
            epoch: 0,
            params: Params::default(),
            _phantom: PhantomData,
        }
    }
}

impl<C, N> DynamicHoneyBadgerBuilder<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned,
{
    /// Returns a new `DynamicHoneyBadgerBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the starting era to the given value.
    pub fn era(&mut self, era: u64) -> &mut Self {
        self.era = era;
        self
    }

    /// Sets the starting era to the given value.
    pub fn epoch(&mut self, epoch: u64) -> &mut Self {
        self.epoch = epoch;
        self
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: u64) -> &mut Self {
        self.params.max_future_epochs = max_future_epochs;
        self
    }

    /// Sets the strategy to use when handling `Subset` output.
    pub fn subset_handling_strategy(
        &mut self,
        subset_handling_strategy: SubsetHandlingStrategy,
    ) -> &mut Self {
        self.params.subset_handling_strategy = subset_handling_strategy;
        self
    }

    /// Sets the schedule to use for threshold encryption.
    pub fn encryption_schedule(&mut self, encryption_schedule: EncryptionSchedule) -> &mut Self {
        self.params.encryption_schedule = encryption_schedule;
        self
    }

    /// Sets the parameters controlling Honey Badger's behavior and performance.
    pub fn params(&mut self, params: Params) -> &mut Self {
        self.params = params;
        self
    }

    /// Creates a new Dynamic Honey Badger instance with an empty buffer.
    pub fn build(
        &mut self,
        netinfo: NetworkInfo<N>,
        secret_key: SecretKey,
        pub_keys: PubKeyMap<N>,
    ) -> DynamicHoneyBadger<C, N> {
        DynamicHoneyBadger::new(
            secret_key,
            pub_keys,
            Arc::new(netinfo),
            self.params.clone(),
            self.era,
            self.epoch,
        )
    }

    /// Creates a new `DynamicHoneyBadger` configured to start a new network as a single validator.
    pub fn build_first_node<R: rand::Rng>(
        &mut self,
        our_id: N,
        rng: &mut R,
    ) -> Result<DynamicHoneyBadger<C, N>> {
        let sk_set = SecretKeySet::random(0, rng);
        let pk_set = sk_set.public_keys();
        let sks = sk_set.secret_key_share(0);
        let sk = rng.gen::<SecretKey>();
        let pub_keys = to_pub_keys(once((&our_id, &sk)));
        let netinfo = NetworkInfo::new(our_id.clone(), sks, pk_set, once(our_id));
        Ok(self.build(netinfo, sk, pub_keys))
    }

    /// Creates a new `DynamicHoneyBadger` configured to join the network at the epoch specified in
    /// the `JoinPlan`. This ignores the builder's configuration settings.
    ///
    /// **Deprecated**: Please use `DynamicHoneyBadger::new_joining` instead.
    #[deprecated]
    pub fn build_joining<R: rand::Rng>(
        &mut self,
        our_id: N,
        secret_key: SecretKey,
        join_plan: JoinPlan<N>,
        rng: &mut R,
    ) -> Result<(DynamicHoneyBadger<C, N>, Step<C, N>)> {
        DynamicHoneyBadger::new_joining(our_id, secret_key, join_plan, rng)
    }
}
