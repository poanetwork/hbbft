use std::default::Default;
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::once;
use std::marker::PhantomData;
use std::sync::Arc;

use rand::{self, Rand, Rng};
use serde::{Deserialize, Serialize};

use super::{ChangeState, DynamicHoneyBadger, JoinPlan, Result, Step, VoteCounter};
use crypto::{SecretKey, SecretKeySet, SecretKeyShare};
use honey_badger::HoneyBadger;
use messaging::NetworkInfo;

/// A Dynamic Honey Badger builder, to configure the parameters and create new instances of
/// `DynamicHoneyBadger`.
pub struct DynamicHoneyBadgerBuilder<C, NodeUid> {
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    _phantom: PhantomData<(C, NodeUid)>,
}

impl<C, NodeUid> Default for DynamicHoneyBadgerBuilder<C, NodeUid> {
    fn default() -> Self {
        // TODO: Use the defaults from `HoneyBadgerBuilder`.
        DynamicHoneyBadgerBuilder {
            max_future_epochs: 3,
            _phantom: PhantomData,
        }
    }
}

impl<C, NodeUid> DynamicHoneyBadgerBuilder<C, NodeUid>
where
    C: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Eq + Ord + Clone + Debug + Serialize + for<'r> Deserialize<'r> + Hash + Rand,
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
    pub fn build(&self, netinfo: NetworkInfo<NodeUid>) -> DynamicHoneyBadger<C, NodeUid> {
        let arc_netinfo = Arc::new(netinfo.clone());
        let honey_badger = HoneyBadger::builder(arc_netinfo.clone())
            .max_future_epochs(self.max_future_epochs)
            .build();
        DynamicHoneyBadger {
            netinfo,
            max_future_epochs: self.max_future_epochs,
            start_epoch: 0,
            vote_counter: VoteCounter::new(arc_netinfo, 0),
            key_gen_msg_buffer: Vec::new(),
            honey_badger,
            key_gen: None,
            incoming_queue: Vec::new(),
        }
    }

    /// Creates a new `DynamicHoneyBadger` configured to start a new network as a single validator.
    pub fn build_first_node(&self, our_uid: NodeUid) -> Result<DynamicHoneyBadger<C, NodeUid>> {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(0, &mut rng)?;
        let pk_set = sk_set.public_keys();
        let sks = sk_set.secret_key_share(0)?;
        let sk: SecretKey = rng.gen();
        let pub_keys = once((our_uid.clone(), sk.public_key())).collect();
        let netinfo = NetworkInfo::new(our_uid, sks, pk_set, sk, pub_keys);
        Ok(self.build(netinfo))
    }

    /// Creates a new `DynamicHoneyBadger` configured to join the network at the epoch specified in
    /// the `JoinPlan`.
    pub fn build_joining(
        &self,
        our_uid: NodeUid,
        secret_key: SecretKey,
        join_plan: JoinPlan<NodeUid>,
    ) -> Result<(DynamicHoneyBadger<C, NodeUid>, Step<C, NodeUid>)> {
        let netinfo = NetworkInfo::new(
            our_uid,
            SecretKeyShare::default(), // TODO: Should be an option?
            join_plan.pub_key_set,
            secret_key,
            join_plan.pub_keys,
        );
        let arc_netinfo = Arc::new(netinfo.clone());
        let honey_badger = HoneyBadger::builder(arc_netinfo.clone())
            .max_future_epochs(self.max_future_epochs)
            .build();
        let mut dhb = DynamicHoneyBadger {
            netinfo,
            max_future_epochs: self.max_future_epochs,
            start_epoch: join_plan.epoch,
            vote_counter: VoteCounter::new(arc_netinfo, join_plan.epoch),
            key_gen_msg_buffer: Vec::new(),
            honey_badger,
            key_gen: None,
            incoming_queue: Vec::new(),
        };
        let step = match join_plan.change {
            ChangeState::InProgress(ref change) => dhb.update_key_gen(join_plan.epoch, change)?,
            ChangeState::None | ChangeState::Complete(..) => Step::default(),
        };
        Ok((dhb, step))
    }
}
