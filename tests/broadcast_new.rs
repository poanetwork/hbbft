pub mod net;

use std::iter::once;
use std::sync::Arc;

use log::info;
use rand::rngs::ThreadRng;
use rand::Rng;

use hbbft::{broadcast::Broadcast, util, ConsensusProtocol};

use crate::net::adversary::{
    sort_ascending, swap_random, Adversary, NetMutHandle, NodeOrderAdversary, ReorderingAdversary,
};
use crate::net::{NetBuilder, NewNodeInfo, VirtualNet};

type NodeId = u16;

/// A strategy for picking the next good node to handle a message.
pub enum MessageSorting {
    /// Swaps the first message with a random message in the queue
    RandomSwap,
    /// Sorts the message queue by receiving node id
    SortAscending,
}

/// For each adversarial node does the following, but only once:
///
/// * creates a **new** instance of the Broadcast ConsensusProtocol,
///   with the adversarial node ID as proposer
/// * Let it handle a "Fake News" input
/// * Take the returned step's messages
/// * Converts the messages to be enqueued
pub struct ProposeAdversary {
    message_strategy: MessageSorting,
    has_sent: bool,
}

impl ProposeAdversary {
    /// Create a new `ProposeAdversary`.
    #[inline]
    pub fn new(message_strategy: MessageSorting) -> Self {
        ProposeAdversary {
            message_strategy,
            has_sent: false,
        }
    }
}

impl<D> Adversary<D> for ProposeAdversary
where
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
{
    #[inline]
    fn pre_crank<R: Rng>(&mut self, mut net: NetMutHandle<'_, D, Self>, rng: &mut R) {
        if !self.has_sent {
            self.has_sent = true;

            // Get adversarial nodes
            let _faulty_nodes = net.faulty_nodes_mut();

            // Need to get netinfo from somewhere
            // the binary_agreeement_mitm test has an approach, albeit not a pretty one
        }

        match self.message_strategy {
            MessageSorting::RandomSwap => swap_random(net, rng),
            MessageSorting::SortAscending => sort_ascending(net),
        }
    }
}

/// Broadcasts a value from node 0 and expects all good nodes to receive it.
fn test_broadcast<A: Adversary<Broadcast<NodeId>>>(
    mut net: VirtualNet<Broadcast<NodeId>, A>,
    proposed_value: &[u8],
    rng: &mut ThreadRng,
) {
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    // Make node 0 propose the value.
    let _step = net
        .send_input(0, proposed_value.to_vec(), rng)
        .expect("Setting input failed");

    // Handle messages until all good nodes have terminated.
    while !net.nodes().all(|node| node.algorithm().terminated()) {
        let _ = net.crank_expect(rng);
    }

    // Verify that all instances output the proposed value.
    assert!(net
        .nodes()
        .all(|node| once(&proposed_value.to_vec()).eq(node.outputs())));
}

fn test_broadcast_different_sizes<A, F>(new_adversary: F, proposed_value: &[u8])
where
    A: Adversary<Broadcast<NodeId>>,
    F: Fn() -> A,
{
    let mut rng = rand::thread_rng();
    let sizes = (1..6)
        .chain(once(rng.gen_range(6, 20)))
        .chain(once(rng.gen_range(30, 50)));
    for size in sizes {
        let num_faulty_nodes = util::max_faulty(size);
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            size - num_faulty_nodes,
            num_faulty_nodes
        );

        let (net, _) = NetBuilder::new(0..size as u16)
            .num_faulty(num_faulty_nodes as usize)
            .message_limit(10_000 * size as usize)
            .no_time_limit()
            .adversary(new_adversary())
            .using(move |node_info: NewNodeInfo<_>| {
                Broadcast::new(Arc::new(node_info.netinfo), 0)
                    .expect("Failed to create a ThresholdSign instance.")
            })
            .build(&mut rng)
            .expect("Could not construct test network.");

        test_broadcast(net, proposed_value, &mut rng);
    }
}

#[test]
fn test_8_broadcast_equal_leaves_silent_new() {
    let new_adversary = || ReorderingAdversary::new();
    let mut rng = rand::thread_rng();
    let size = 8;
    let (net, _) = NetBuilder::new(0..size as u16)
        .num_faulty(0 as usize)
        .message_limit(10_000 * size as usize)
        .no_time_limit()
        .adversary(new_adversary())
        .using(move |node_info: NewNodeInfo<_>| {
            Broadcast::new(Arc::new(node_info.netinfo), 0)
                .expect("Failed to create a ThresholdSign instance.")
        })
        .build(&mut rng)
        .expect("Could not construct test network.");

    // Space is ASCII character 32. So 32 spaces will create shards that are all equal, even if the
    // length of the value is inserted.
    test_broadcast(net, &[b' '; 32], &mut rng);
}

#[test]
fn test_broadcast_random_delivery_silent_new() {
    let new_adversary = || ReorderingAdversary::new();
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_first_delivery_silent_new() {
    let new_adversary = || NodeOrderAdversary::new();
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_random_delivery_adv_propose_new() {
    let new_adversary = || ProposeAdversary::new(MessageSorting::RandomSwap);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}

#[test]
fn test_broadcast_first_delivery_adv_propose_new() {
    let new_adversary = || ProposeAdversary::new(MessageSorting::SortAscending);
    test_broadcast_different_sizes(new_adversary, b"Foo");
}
