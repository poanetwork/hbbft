use std::collections::{BTreeMap, BTreeSet};
use std::default::Default;
use std::iter::once;
use std::marker::PhantomData;
use std::sync::Arc;

use crypto::{SecretKey, SecretKeySet, SecretKeyShare};
use rand::{self, Rand, Rng};
use serde::{Deserialize, Serialize};

use super::{ChangeState, DynamicHoneyBadger, JoinPlan, Result, Step, VoteCounter};
use honey_badger::HoneyBadger;
use messaging::NetworkInfo;
use traits::{Contribution, NodeIdT};

/// A Dynamic Honey Badger builder, to configure the parameters and create new instances of
/// `DynamicHoneyBadger`.
pub struct DynamicHoneyBadgerBuilder<C, N> {
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    _phantom: PhantomData<(C, N)>,
}

impl<C, N> Default for DynamicHoneyBadgerBuilder<C, N> {
    fn default() -> Self {
        // TODO: Use the defaults from `HoneyBadgerBuilder`.
        DynamicHoneyBadgerBuilder {
            max_future_epochs: 3,
            _phantom: PhantomData,
        }
    }
}

impl<C, N> DynamicHoneyBadgerBuilder<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeIdT + Serialize + for<'r> Deserialize<'r> + Rand,
{
    /// Returns a new `DynamicHoneyBadgerBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: usize) -> &mut Self {
        self.max_future_epochs = max_future_epochs;
        self
    }

    /// Creates a new Dynamic Honey Badger instance with an empty buffer.
    pub fn build(&self, netinfo: NetworkInfo<N>) -> Result<(DynamicHoneyBadger<C, N>, Step<C, N>)> {
        let arc_netinfo = Arc::new(netinfo.clone());
        let (honey_badger, hb_step) = HoneyBadger::builder(arc_netinfo.clone())
            .max_future_epochs(self.max_future_epochs)
            .build();
        let mut dhb = DynamicHoneyBadger {
            netinfo,
            max_future_epochs: self.max_future_epochs,
            start_epoch: 0,
            vote_counter: VoteCounter::new(arc_netinfo, 0),
            key_gen_msg_buffer: Vec::new(),
            honey_badger,
            key_gen_state: None,
            outgoing_queue_hb: BTreeMap::new(),
            outgoing_queue_dhb: BTreeMap::new(),
            remote_epochs: BTreeMap::new(),
            nodes_being_added: BTreeSet::new(),
        };
        let step = dhb.process_output(hb_step)?;
        Ok((dhb, step))
    }

    /// Creates a new `DynamicHoneyBadger` configured to start a new network as a single validator.
    pub fn build_first_node(&self, our_id: N) -> Result<(DynamicHoneyBadger<C, N>, Step<C, N>)> {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(0, &mut rng)?;
        let pk_set = sk_set.public_keys();
        let sks = sk_set.secret_key_share(0)?;
        let sk: SecretKey = rng.gen();
        let pub_keys = once((our_id.clone(), sk.public_key())).collect();
        let netinfo = NetworkInfo::new(our_id, sks, pk_set, sk, pub_keys);
        self.build(netinfo)
    }

    /// Creates a new `DynamicHoneyBadger` configured to join the network at the epoch specified in
    /// the `JoinPlan`.
    pub fn build_joining(
        &self,
        our_id: N,
        secret_key: SecretKey,
        join_plan: JoinPlan<N>,
    ) -> Result<(DynamicHoneyBadger<C, N>, Step<C, N>)> {
        let netinfo = NetworkInfo::new(
            our_id,
            SecretKeyShare::default(), // TODO: Should be an option?
            join_plan.pub_key_set,
            secret_key,
            join_plan.pub_keys,
        );
        let arc_netinfo = Arc::new(netinfo.clone());
        let (honey_badger, hb_step) = HoneyBadger::builder(arc_netinfo.clone())
            .max_future_epochs(self.max_future_epochs)
            .build();
        let start_epoch = join_plan.epoch;
        let mut dhb = DynamicHoneyBadger {
            netinfo,
            max_future_epochs: self.max_future_epochs,
            start_epoch,
            vote_counter: VoteCounter::new(arc_netinfo, start_epoch),
            key_gen_msg_buffer: Vec::new(),
            honey_badger,
            key_gen_state: None,
            outgoing_queue_hb: BTreeMap::new(),
            outgoing_queue_dhb: BTreeMap::new(),
            remote_epochs: BTreeMap::new(),
            nodes_being_added: BTreeSet::new(),
        };
        let mut step = dhb.process_output(hb_step)?;
        match join_plan.change {
            ChangeState::InProgress(ref change) => {
                step.extend(dhb.update_key_gen(start_epoch, change)?)
            }
            ChangeState::None | ChangeState::Complete(..) => (),
        };
        Ok((dhb, step))
    }
}
