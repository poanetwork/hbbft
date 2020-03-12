use std::iter::once;

use hbbft::{broadcast::Broadcast, util, ConsensusProtocol, CpStep};
use hbbft_testing::adversary::{
    sort_ascending, swap_random, Adversary, NetMutHandle, NodeOrderAdversary, RandomAdversary,
    ReorderingAdversary,
};
use hbbft_testing::proptest::{gen_seed, TestRng, TestRngSeed};
use hbbft_testing::{CrankError, NetBuilder, NetMessage, NewNodeInfo, VirtualNet};
use log::info;
use proptest::{prelude::ProptestConfig, proptest};
use rand::{Rng, SeedableRng};

type NodeId = u16;

/// A strategy for picking the next node to handle a message.
/// The sorting algorithm used is stable - preserves message
/// order relative to the node id.
pub enum MessageSorting {
    /// Picks a random node and swaps its messages to the front of the queue
    RandomPick,
    /// Sorts the message queue by receiving node id
    SortAscending,
}

/// For each adversarial node does the following, but only once:
///
/// * Creates a *new* instance of the Broadcast ConsensusProtocol,
///   with the adversarial node ID as proposer
/// * Lets it handle a "Fake News" input
/// * Records the returned step's messages
/// * Injects the messages to the queue
pub struct ProposeAdversary {
    message_strategy: MessageSorting,
    has_sent: bool,
    drop_messages: bool,
}

impl ProposeAdversary {
    /// Creates a new `ProposeAdversary`.
    #[inline]
    pub fn new(message_strategy: MessageSorting, drop_messages: bool) -> Self {
        ProposeAdversary {
            message_strategy,
            has_sent: false,
            drop_messages,
        }
    }
}

impl Adversary<Broadcast<NodeId>> for ProposeAdversary {
    #[inline]
    fn pre_crank<R: Rng>(
        &mut self,
        mut net: NetMutHandle<'_, Broadcast<NodeId>, Self>,
        rng: &mut R,
    ) {
        match self.message_strategy {
            MessageSorting::RandomPick => swap_random(&mut net, rng),
            MessageSorting::SortAscending => sort_ascending(&mut net),
        }
    }

    #[inline]
    fn tamper<R: Rng>(
        &mut self,
        mut net: NetMutHandle<'_, Broadcast<NodeId>, Self>,
        msg: NetMessage<Broadcast<NodeId>>,
        mut rng: &mut R,
    ) -> Result<CpStep<Broadcast<NodeId>>, CrankError<Broadcast<NodeId>>> {
        let mut step = net.dispatch_message(msg, rng)?;

        // optionally drop all messages other than the fake broadcasts
        if self.drop_messages {
            step.messages.clear();
        }

        if !self.has_sent {
            self.has_sent = true;

            // Get adversarial nodes
            let faulty_nodes = net.faulty_nodes_mut();

            // Instantiate a temporary broadcast consensus protocol for each faulty node
            // and add the generated messages to the current step.
            for faulty_node in faulty_nodes {
                let validators = faulty_node.algorithm().validator_set().clone();
                let fake_step = Broadcast::new(*faulty_node.id(), validators, *faulty_node.id())
                    .expect("broadcast instance")
                    .handle_input(b"Fake news".to_vec(), &mut rng)
                    .expect("propose");

                step.messages.extend(fake_step.messages);
            }
        }
        Ok(step)
    }
}

/// Broadcasts a value from node 0 and expects all good nodes to receive it.
fn test_broadcast<A: Adversary<Broadcast<NodeId>>>(
    mut net: VirtualNet<Broadcast<NodeId>, A>,
    proposed_value: &[u8],
    rng: &mut TestRng,
    proposer_id: NodeId,
) {
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let proposer_is_faulty = net.get(proposer_id).unwrap().is_faulty();

    // Make node 0 propose the value.
    let _step = net
        .send_input(proposer_id, proposed_value.to_vec(), rng)
        .expect("Setting input failed");

    // Handle messages until all good nodes have terminated.
    // If the proposer is faulty it is legal for the queue to starve
    while !net.nodes().all(|node| node.algorithm().terminated()) {
        if proposer_is_faulty && net.messages_len() == 0 {
            info!("Expected starvation of messages with a faulty proposer");
            // The output of all correct nodes needs to be empty in this case.
            // We check for the output of the first node to be empty and
            // rely on the identity checks at the end of this function to
            // verify that all other correct nodes have empty output as well.
            let first = net
                .correct_nodes()
                .next()
                .expect("At least one correct node needs to exist");
            assert!(first.outputs().is_empty());
            break;
        }

        let _ = net.crank_expect(rng);
    }

    if proposer_is_faulty {
        // If the proposer was faulty it is sufficient for all correct nodes having the same value.
        let first = net.correct_nodes().next().unwrap().outputs();
        assert!(net.nodes().all(|node| node.outputs() == first));
    } else {
        // In the case where the proposer was valid it must be the value it proposed.
        assert!(net
            .nodes()
            .all(|node| once(&proposed_value.to_vec()).eq(node.outputs())));
    }
}

fn test_broadcast_different_sizes<A, F>(new_adversary: F, proposed_value: &[u8], seed: TestRngSeed)
where
    A: Adversary<Broadcast<NodeId>>,
    F: Fn() -> A,
{
    let mut rng: TestRng = TestRng::from_seed(seed);
    let sizes = (1..6)
        .chain(once(rng.gen_range(6, 20)))
        .chain(once(rng.gen_range(30, 50)));
    for size in sizes {
        // cloning since it gets moved into a closure
        let num_faulty_nodes = util::max_faulty(size);
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            size - num_faulty_nodes,
            num_faulty_nodes
        );

        let proposer_id = rng.gen_range(0, size) as NodeId;

        let (net, _) = NetBuilder::new(0..size as u16)
            .num_faulty(num_faulty_nodes as usize)
            .message_limit(10_000 * size as usize)
            .no_time_limit()
            .adversary(new_adversary())
            .using(move |info| {
                let validators = info.netinfo.validator_set().clone();
                let id = *info.netinfo.our_id();
                Broadcast::new(id, validators, proposer_id)
                    .expect("Failed to create a Broadcast instance.")
            })
            .build(&mut rng)
            .expect("Could not construct test network.");

        test_broadcast(net, proposed_value, &mut rng, proposer_id);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1, .. ProptestConfig::default()
    })]

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_8_broadcast_equal_leaves_silent(seed in gen_seed()) {
        do_test_8_broadcast_equal_leaves_silent(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_broadcast_random_delivery_silent(seed in gen_seed()) {
        do_test_broadcast_random_delivery_silent(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_broadcast_first_delivery_silent(seed in gen_seed()) {
        do_test_broadcast_first_delivery_silent(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_broadcast_first_delivery_adv_propose(seed in gen_seed()) {
        do_test_broadcast_first_delivery_adv_propose(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_broadcast_random_delivery_adv_propose(seed in gen_seed()) {
        do_test_broadcast_random_delivery_adv_propose(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_broadcast_random_delivery_adv_propose_and_drop(seed in gen_seed()) {
        do_test_broadcast_random_delivery_adv_propose_and_drop(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_broadcast_random_adversary(seed in gen_seed()) {
        do_test_broadcast_random_adversary(seed)
    }
}

fn do_test_8_broadcast_equal_leaves_silent(seed: TestRngSeed) {
    let mut rng: TestRng = TestRng::from_seed(seed);
    let size = 8;

    let num_faulty = 0;
    let proposer_id = rng.gen_range(0, size);
    let (net, _) = NetBuilder::new(0..size as u16)
        .num_faulty(num_faulty as usize)
        .message_limit(10_000 * size as usize)
        .no_time_limit()
        .adversary(ReorderingAdversary::new())
        .using(move |node_info: NewNodeInfo<_>| {
            let id = *node_info.netinfo.our_id();
            let validators = node_info.netinfo.validator_set().clone();
            Broadcast::new(id, validators, proposer_id)
                .expect("Failed to create a Broadcast instance.")
        })
        .build(&mut rng)
        .expect("Could not construct test network.");

    // Space is ASCII character 32. So 32 spaces will create shards that are all equal, even if the
    // length of the value is inserted.
    test_broadcast(net, &[b' '; 32], &mut rng, proposer_id);
}

fn do_test_broadcast_random_delivery_silent(seed: TestRngSeed) {
    test_broadcast_different_sizes(ReorderingAdversary::new, b"Foo", seed);
}

fn do_test_broadcast_first_delivery_silent(seed: TestRngSeed) {
    test_broadcast_different_sizes(NodeOrderAdversary::new, b"Foo", seed);
}

fn do_test_broadcast_first_delivery_adv_propose(seed: TestRngSeed) {
    let new_adversary = || ProposeAdversary::new(MessageSorting::SortAscending, false);
    test_broadcast_different_sizes(new_adversary, b"Foo", seed);
}

fn do_test_broadcast_random_delivery_adv_propose(seed: TestRngSeed) {
    let new_adversary = || ProposeAdversary::new(MessageSorting::RandomPick, false);
    test_broadcast_different_sizes(new_adversary, b"Foo", seed);
}

fn do_test_broadcast_random_delivery_adv_propose_and_drop(seed: TestRngSeed) {
    let new_adversary = || ProposeAdversary::new(MessageSorting::RandomPick, true);
    test_broadcast_different_sizes(new_adversary, b"Foo", seed);
}

fn do_test_broadcast_random_adversary(seed: TestRngSeed) {
    let new_adversary = || RandomAdversary::new(0.2, 0.2);
    test_broadcast_different_sizes(new_adversary, b"RandomFoo", seed);
}
