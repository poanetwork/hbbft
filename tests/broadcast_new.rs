pub mod net;

use std::collections::BTreeMap;
use std::iter::once;
use std::sync::{Arc, Mutex};

use log::info;
use rand::rngs::ThreadRng;
use rand::Rng;

use hbbft::{broadcast::Broadcast, util, ConsensusProtocol, NetworkInfo, Target, TargetedMessage};

use crate::net::adversary::{
    sort_ascending, swap_random, Adversary, NetMutHandle, NodeOrderAdversary, QueuePosition,
    ReorderingAdversary,
};
use crate::net::{NetBuilder, NetworkMessage, NewNodeInfo, VirtualNet};

type NodeId = u16;
type NetworkInfoMap = BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>;

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
/// * Record the returned step's messages
/// * Inject the messages to the queue
pub struct ProposeAdversary {
    message_strategy: MessageSorting,
    has_sent: bool,
    // TODO this is really hacky but there's no better way to get this value
    // Solution taken from binary_agreement_mitm test - ideally the new network simulator
    // should be altered to store the netinfo structure alongside nodes similar to
    // the way the old network simulator did it.
    netinfo_mutex: Arc<Mutex<NetworkInfoMap>>,
}

impl ProposeAdversary {
    /// Create a new `ProposeAdversary`.
    #[inline]
    pub fn new(
        message_strategy: MessageSorting,
        netinfo_mutex: Arc<Mutex<NetworkInfoMap>>,
    ) -> Self {
        ProposeAdversary {
            message_strategy,
            has_sent: false,
            netinfo_mutex,
        }
    }
}

impl Adversary<Broadcast<NodeId>> for ProposeAdversary {
    #[inline]
    fn pre_crank<R: Rng>(
        &mut self,
        mut net: NetMutHandle<'_, Broadcast<NodeId>, Self>,
        mut rng: &mut R,
    ) {
        if !self.has_sent {
            self.has_sent = true;

            // Get adversarial nodes
            let faulty_nodes = net.faulty_nodes_mut();

            // Collect adversarial proposer messages
            // Using a tupple since we need the sender's NodeId to inject messages
            let msgs: Vec<(NodeId, TargetedMessage<_, _>)> = faulty_nodes
                .flat_map(|node| {
                    let netinfo = self
                        .netinfo_mutex
                        .lock()
                        .unwrap()
                        .get(node.id())
                        .cloned()
                        .expect("Adversary netinfo mutex not populated");

                    Broadcast::new(netinfo, *node.id())
                        .expect("broadcast instance")
                        .handle_input(b"Fake news".to_vec(), &mut rng)
                        .expect("propose")
                        .messages
                        .into_iter()
                        .map(move |msg| (*node.id(), msg))
                })
                .collect();

            // Inject recorded messages
            let all_node_ids: Vec<NodeId> = net.nodes_mut().map(|node| node.id()).collect();
            for m in &msgs {
                match m.1.target {
                    Target::Node(idx) => net.inject_message(
                        QueuePosition::Back,
                        NetworkMessage::new(m.0, m.1.message.clone(), idx),
                    ),
                    Target::All => {
                        for id in &all_node_ids {
                            if *id != m.0 {
                                net.inject_message(
                                    QueuePosition::Front,
                                    NetworkMessage::new(m.0, m.1.message.clone(), *id),
                                )
                            }
                        }
                    }
                }
            }
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

fn test_broadcast_different_sizes<A, F>(
    new_adversary: F,
    proposed_value: &[u8],
    adversary_netinfo: Arc<Mutex<NetworkInfoMap>>,
) where
    A: Adversary<Broadcast<NodeId>>,
    F: Fn() -> A,
{
    let mut rng = rand::thread_rng();
    let sizes = (1..6)
        .chain(once(rng.gen_range(6, 20)))
        .chain(once(rng.gen_range(30, 50)));
    for size in sizes {
        // cloning since it gets moved into a closure
        let cloned_netinfo = adversary_netinfo.clone();
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
            .using(move |info| {
                let netinfo = Arc::new(info.netinfo);
                cloned_netinfo
                    .lock()
                    .unwrap()
                    .insert(info.id, netinfo.clone());
                Broadcast::new(netinfo, 0).expect("Failed to create a ThresholdSign instance.")
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
    test_broadcast_different_sizes(new_adversary, b"Foo", Default::default());
}

#[test]
fn test_broadcast_first_delivery_silent_new() {
    let new_adversary = || NodeOrderAdversary::new();
    test_broadcast_different_sizes(new_adversary, b"Foo", Default::default());
}

#[test]
fn test_broadcast_first_delivery_adv_propose_new() {
    let adversary_netinfo: Arc<Mutex<NetworkInfoMap>> = Default::default();
    let new_adversary =
        || ProposeAdversary::new(MessageSorting::SortAscending, adversary_netinfo.clone());
    test_broadcast_different_sizes(new_adversary, b"Foo", adversary_netinfo.clone());
}
