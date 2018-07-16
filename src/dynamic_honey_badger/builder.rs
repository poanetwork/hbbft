use std::collections::VecDeque;
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::once;
use std::marker::PhantomData;
use std::sync::Arc;

use rand::{self, Rand};
use serde::{Deserialize, Serialize};

use super::{ChangeState, DynamicHoneyBadger, JoinPlan, MessageQueue, Result, VoteCounter};
use crypto::{SecretKey, SecretKeySet};
use honey_badger::HoneyBadger;
use messaging::NetworkInfo;

/// A Dynamic Honey Badger builder, to configure the parameters and create new instances of
/// `DynamicHoneyBadger`.
pub struct DynamicHoneyBadgerBuilder<C, NodeUid> {
    /// Shared network data.
    netinfo: NetworkInfo<NodeUid>,
    /// The epoch at which to join the network.
    start_epoch: u64,
    /// The current change, for which key generation is beginning at `start_epoch`.
    change: ChangeState<NodeUid>,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    _phantom: PhantomData<C>,
}

impl<C, NodeUid> DynamicHoneyBadgerBuilder<C, NodeUid>
where
    C: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Eq + Ord + Clone + Debug + Serialize + for<'r> Deserialize<'r> + Hash + Rand,
{
    /// Returns a new `DynamicHoneyBadgerBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    pub fn new(netinfo: NetworkInfo<NodeUid>) -> Self {
        // TODO: Use the defaults from `HoneyBadgerBuilder`.
        DynamicHoneyBadgerBuilder {
            netinfo,
            start_epoch: 0,
            change: ChangeState::None,
            max_future_epochs: 3,
            _phantom: PhantomData,
        }
    }

    /// Returns a new `DynamicHoneyBadgerBuilder` configured to start a new network as a single
    /// validator.
    pub fn new_first_node(our_uid: NodeUid) -> Self {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(0, &mut rng);
        let pk_set = sk_set.public_keys();
        let sk = sk_set.secret_key_share(0);
        let netinfo = NetworkInfo::new(our_uid.clone(), once(our_uid).collect(), sk, pk_set);
        DynamicHoneyBadgerBuilder::new(netinfo)
    }

    /// Returns a new `DynamicHoneyBadgerBuilder` configured to join the network at the epoch
    /// specified in the `JoinPlan`.
    pub fn new_joining(
        our_uid: NodeUid,
        secret_key: SecretKey,
        join_plan: JoinPlan<NodeUid>,
    ) -> Self {
        let netinfo = NetworkInfo::new(
            our_uid,
            join_plan.all_uids,
            secret_key,
            join_plan.pub_key_set,
        );
        DynamicHoneyBadgerBuilder {
            netinfo,
            start_epoch: join_plan.epoch,
            change: join_plan.change,
            max_future_epochs: 3,
            _phantom: PhantomData,
        }
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: usize) -> &mut Self {
        self.max_future_epochs = max_future_epochs;
        self
    }

    /// Creates a new Dynamic Honey Badger instance with an empty buffer.
    pub fn build(&self) -> Result<DynamicHoneyBadger<C, NodeUid>> {
        let netinfo = Arc::new(self.netinfo.clone());
        let honey_badger = HoneyBadger::builder(netinfo.clone())
            .max_future_epochs(self.max_future_epochs)
            .build();
        let mut dhb = DynamicHoneyBadger {
            netinfo: self.netinfo.clone(),
            max_future_epochs: self.max_future_epochs,
            start_epoch: self.start_epoch,
            vote_counter: VoteCounter::new(netinfo, self.start_epoch),
            key_gen_msg_buffer: Vec::new(),
            honey_badger,
            key_gen: None,
            incoming_queue: Vec::new(),
            messages: MessageQueue(VecDeque::new()),
            output: VecDeque::new(),
        };
        if let ChangeState::InProgress(ref change) = self.change {
            dhb.update_key_gen(self.start_epoch, change.clone())?;
        }
        Ok(dhb)
    }
}
