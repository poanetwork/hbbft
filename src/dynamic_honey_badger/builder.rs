use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{DynamicHoneyBadger, MessageQueue};
use honey_badger::HoneyBadger;
use messaging::NetworkInfo;

/// A Dynamic Honey Badger builder, to configure the parameters and create new instances of
/// `DynamicHoneyBadger`.
pub struct DynamicHoneyBadgerBuilder<C, NodeUid> {
    /// Shared network data.
    netinfo: NetworkInfo<NodeUid>,
    /// The epoch at which to join the network.
    start_epoch: u64,
    /// The maximum number of future epochs for which we handle messages simultaneously.
    max_future_epochs: usize,
    _phantom: PhantomData<C>,
}

impl<C, NodeUid> DynamicHoneyBadgerBuilder<C, NodeUid>
where
    C: Eq + Serialize + for<'r> Deserialize<'r> + Debug + Hash,
    NodeUid: Eq + Ord + Clone + Debug + Serialize + for<'r> Deserialize<'r> + Hash,
{
    /// Returns a new `DynamicHoneyBadgerBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    pub fn new(netinfo: NetworkInfo<NodeUid>) -> Self {
        // TODO: Use the defaults from `HoneyBadgerBuilder`.
        DynamicHoneyBadgerBuilder {
            netinfo,
            start_epoch: 0,
            max_future_epochs: 3,
            _phantom: PhantomData,
        }
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: usize) -> &mut Self {
        self.max_future_epochs = max_future_epochs;
        self
    }

    /// Sets the epoch at which to join the network as an observer. This requires the node to
    /// receive all broadcast messages for `start_epoch` and later.
    pub fn start_epoch(&mut self, start_epoch: u64) -> &mut Self {
        self.start_epoch = start_epoch;
        self
    }

    /// Creates a new Dynamic Honey Badger instance with an empty buffer.
    pub fn build(&self) -> DynamicHoneyBadger<C, NodeUid> {
        let honey_badger = HoneyBadger::builder(Arc::new(self.netinfo.clone()))
            .max_future_epochs(self.max_future_epochs)
            .build();
        DynamicHoneyBadger {
            netinfo: self.netinfo.clone(),
            max_future_epochs: self.max_future_epochs,
            start_epoch: self.start_epoch,
            votes: BTreeMap::new(),
            node_tx_buffer: Vec::new(),
            honey_badger,
            key_gen: None,
            incoming_queue: Vec::new(),
            messages: MessageQueue(VecDeque::new()),
            output: VecDeque::new(),
        }
    }
}
