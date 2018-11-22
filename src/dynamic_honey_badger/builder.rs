use std::default::Default;
use std::iter::once;
use std::marker::PhantomData;
use std::sync::Arc;

use crypto::{SecretKey, SecretKeySet};
use rand::{self, Rand, Rng};
use serde::{de::DeserializeOwned, Serialize};

use super::{DynamicHoneyBadger, EncryptionSchedule, JoinPlan, Result, Step, VoteCounter};
use honey_badger::{HoneyBadger, Params, SubsetHandlingStrategy};
use util::SubRng;
use {Contribution, NetworkInfo, NodeIdT};

/// A Dynamic Honey Badger builder, to configure the parameters and create new instances of
/// `DynamicHoneyBadger`.
pub struct DynamicHoneyBadgerBuilder<C, N> {
    /// Start in this era.
    era: u64,
    /// Random number generator passed on to algorithm instance for key generation. Also used to
    /// instantiate `HoneyBadger`.
    rng: Box<dyn rand::Rng>,
    /// Parameters controlling Honey Badger's behavior and performance.
    params: Params,
    _phantom: PhantomData<(C, N)>,
}

impl<C, N> Default for DynamicHoneyBadgerBuilder<C, N>
where
    N: Ord,
{
    fn default() -> Self {
        DynamicHoneyBadgerBuilder {
            era: 0,
            rng: Box::new(rand::thread_rng()),
            params: Params::default(),
            _phantom: PhantomData,
        }
    }
}

impl<C, N> DynamicHoneyBadgerBuilder<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned + Rand,
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

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: u64) -> &mut Self {
        self.params.max_future_epochs = max_future_epochs;
        self
    }

    /// Sets the random number generator to be used to instantiate cryptographic structures.
    pub fn rng<R: rand::Rng + 'static>(&mut self, rng: R) -> &mut Self {
        self.rng = Box::new(rng);
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
    pub fn build(&mut self, netinfo: NetworkInfo<N>) -> DynamicHoneyBadger<C, N> {
        let DynamicHoneyBadgerBuilder {
            era,
            rng,
            params,
            _phantom,
        } = self;
        let arc_netinfo = Arc::new(netinfo.clone());
        let honey_badger = HoneyBadger::builder(arc_netinfo.clone())
            .session_id(*era)
            .params(params.clone())
            .rng(rng.sub_rng())
            .build();
        DynamicHoneyBadger {
            netinfo,
            max_future_epochs: params.max_future_epochs,
            era: *era,
            vote_counter: VoteCounter::new(arc_netinfo, 0),
            key_gen_msg_buffer: Vec::new(),
            honey_badger,
            key_gen_state: None,
            rng: Box::new(rng.sub_rng()),
        }
    }

    /// Creates a new `DynamicHoneyBadger` configured to start a new network as a single validator.
    pub fn build_first_node(&mut self, our_id: N) -> Result<DynamicHoneyBadger<C, N>> {
        let sk_set = SecretKeySet::random(0, &mut self.rng);
        let pk_set = sk_set.public_keys();
        let sks = sk_set.secret_key_share(0);
        let sk: SecretKey = self.rng.gen();
        let pub_keys = once((our_id.clone(), sk.public_key())).collect();
        let netinfo = NetworkInfo::new(our_id, sks, pk_set, sk, pub_keys);
        Ok(self.build(netinfo))
    }

    /// Creates a new `DynamicHoneyBadger` configured to join the network at the epoch specified in
    /// the `JoinPlan`. This ignores the builder's configuration settings.
    ///
    /// **Deprecated**: Please use `DynamicHoneyBadger::new_joining` instead.
    #[deprecated]
    pub fn build_joining(
        &mut self,
        our_id: N,
        secret_key: SecretKey,
        join_plan: JoinPlan<N>,
    ) -> Result<(DynamicHoneyBadger<C, N>, Step<C, N>)> {
        DynamicHoneyBadger::new_joining(our_id, secret_key, join_plan, self.rng.sub_rng())
    }
}
