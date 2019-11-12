use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time;

use hbbft::dynamic_honey_badger::{
    Batch, Change, ChangeState, DynamicHoneyBadger, Input, JoinPlan,
};
use hbbft::sender_queue::{SenderQueue, Step};
use hbbft::{util, Epoched, PubKeyMap};
use hbbft_testing::adversary::{Adversary, ReorderingAdversary};
use hbbft_testing::proptest::{gen_seed, NetworkDimension, TestRng, TestRngSeed};
use hbbft_testing::{NetBuilder, NewNodeInfo, Node, VirtualNet};
use proptest::{prelude::ProptestConfig, prop_compose, proptest};
use rand::{seq::SliceRandom, SeedableRng};

type DHB = SenderQueue<DynamicHoneyBadger<Vec<usize>, usize>>;

/// Chooses a node's contribution for an epoch.
///
/// Selects randomly out of a slice, according to chosen batch and contribution sizes. The function
/// will not fail to do so, even if the queue is empty, returning a smaller or empty slice
/// `Vec` accordingly.
///
/// # Panics
///
/// The function asserts that `batch_size >= contribution_size`.
fn choose_contribution<R, T>(
    rng: &mut R,
    queue: &[T],
    batch_size: usize,
    contribution_size: usize,
) -> Vec<T>
where
    R: rand::Rng,
    T: Clone,
{
    assert!(batch_size >= contribution_size);

    let n = queue.len().min(batch_size);
    let k = queue.len().min(contribution_size);

    queue[0..n].choose_multiple(rng, k).cloned().collect()
}

/// Test configuration for dynamic honey badger tests.
#[derive(Debug)]
struct TestConfig {
    /// The desired network dimension.
    dimension: NetworkDimension,
    /// Total number of transactions to execute before finishing.
    total_txs: usize,
    /// Epoch batch size.
    batch_size: usize,
    /// Individual nodes contribution size.
    contribution_size: usize,
    /// Random number generator to be passed to subsystems.
    seed: TestRngSeed,
}

prop_compose! {
    /// Strategy to generate a test configuration.
    fn arb_config()
                 (dimension in NetworkDimension::range(3, 15),
                  total_txs in 20..60usize,
                  batch_size in 10..20usize,
                  contribution_size in 1..10usize,
                  seed in gen_seed())
                 -> TestConfig {
        TestConfig {
            dimension, total_txs, batch_size, contribution_size, seed
        }
    }
}

// Proptest wrapper for `do_drop_and_re_add`.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1))]
    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn drop_and_re_add(cfg in arb_config()) {
        do_drop_and_re_add(cfg)
    }
}

/// Dynamic honey badger: Drop a validator node, demoting it to observer, then re-add it, all while
/// running a regular honey badger network.
// TODO: Add an observer node to the test network.
#[allow(clippy::needless_pass_by_value, clippy::cognitive_complexity)]
fn do_drop_and_re_add(cfg: TestConfig) {
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng: TestRng = TestRng::from_seed(cfg.seed);

    // First, we create a new test network with Honey Badger instances.
    let num_faulty = cfg.dimension.faulty();
    let (net, _) = NetBuilder::new(0..cfg.dimension.size())
        .num_faulty(num_faulty)
        // Limited to 20k messages per node.
        .message_limit(20_000 * cfg.dimension.size() as usize)
        // 30 secs per node.
        .time_limit(time::Duration::from_secs(30 * cfg.dimension.size() as u64))
        .adversary(ReorderingAdversary::new())
        .using_step(move |node: NewNodeInfo<SenderQueue<_>>| {
            let id = node.id;
            println!(
                "Constructing new {} dynamic honey badger node #{}",
                if id < num_faulty { "faulty" } else { "correct" },
                id
            );
            let netinfo = node.netinfo.clone();
            let dhb = DynamicHoneyBadger::builder().build(netinfo, node.secret_key, node.pub_keys);
            SenderQueue::builder(dhb, node.netinfo.other_ids().cloned()).build(node.id)
        })
        .build(&mut rng)
        .expect("could not construct test network");

    let mut state = TestState::new(net);

    let nodes_for_remove = state.subset_for_remove(&mut rng);
    println!("Will remove and re-add nodes {:?}", nodes_for_remove);

    // We generate a list of total_txs transactions we want to propose, for each node.
    let mut queues: BTreeMap<_, Vec<usize>> = state
        .net
        .nodes()
        .map(|node| (*node.id(), (0..cfg.total_txs).collect()))
        .collect();

    // For each node, select transactions randomly from the queue and propose them.
    for (id, queue) in &mut queues {
        let proposal = choose_contribution(&mut rng, queue, cfg.batch_size, cfg.contribution_size);
        println!("Node {:?} will propose: {:?}", id, proposal);

        // The step will have its messages added to the queue automatically, we ignore the output.
        let _ = state
            .net
            .send_input(*id, Input::User(proposal), &mut rng)
            .expect("could not send initial transaction");
    }

    // Afterwards, remove specific nodes from the dynamic honey badger network.
    let old_pub_keys = state.get_pub_keys();
    let not_removed = |(id, _): &(usize, _)| !nodes_for_remove.contains(id);
    let old_pub_keys_iter = (*old_pub_keys).clone().into_iter();
    let new_pub_keys: PubKeyMap<usize> = Arc::new(old_pub_keys_iter.filter(not_removed).collect());
    let change = Input::Change(Change::NodeChange(new_pub_keys.clone()));
    state
        .net
        .broadcast_input(&change, &mut rng)
        .expect("broadcasting failed");

    // We are tracking (correct) nodes' state through the process by ticking them off individually.
    let correct_nodes: BTreeSet<_> = state.net.correct_nodes().map(|n| *n.id()).collect();
    let non_rm_nodes = &correct_nodes - &nodes_for_remove;

    let mut awaiting_apply_new_subset: BTreeSet<_> = correct_nodes.clone();
    let mut awaiting_apply_old_subset: BTreeSet<_> = correct_nodes.clone();
    let mut awaiting_apply_old_subset_input: BTreeSet<_> = non_rm_nodes.clone();
    let mut awaiting_apply_old_subset_in_progress: BTreeSet<_> = non_rm_nodes;
    let mut expected_outputs: BTreeMap<_, BTreeSet<_>> = correct_nodes
        .iter()
        .map(|id| (id, (0..cfg.total_txs).collect()))
        .collect();
    let mut received_batches: BTreeMap<u64, _> = BTreeMap::new();

    // Run the network:
    loop {
        let (node_id, step) = state.net.crank_expect(&mut rng);
        if !state.net[node_id].is_faulty() {
            for batch in &step.output {
                // Check that correct nodes don't output different batches for the same epoch.
                if let Some(b) = received_batches.insert(batch.epoch(), batch.clone()) {
                    assert!(
                        batch.public_eq(&b),
                        "A batch of node {} doesn't match a previous batch for the same epoch {}",
                        node_id,
                        batch.epoch()
                    );
                }
                let expected_participants: Vec<_> = if awaiting_apply_new_subset.contains(&node_id)
                {
                    // The node hasn't applied a new subset of nodes yet.
                    old_pub_keys.keys()
                } else if awaiting_apply_old_subset.contains(&node_id) {
                    // The node has applied a new subset of nodes.
                    new_pub_keys.keys()
                } else {
                    // The node has applied the old (previous) subset of nodes back.
                    old_pub_keys.keys()
                }
                .collect();
                assert!(
                    batch.contributions().count() * 3 > expected_participants.len() * 2,
                    "The batch contains less than N - f contributions: {:?}",
                    batch
                );
                // Verify that only contributions from expected participants are present in the
                // batch.
                let batch_participants: Vec<_> = batch.contributions().map(|(id, _)| id).collect();
                assert!(
                    batch_participants
                        .iter()
                        .all(|id| expected_participants.contains(id)),
                    "The batch at node {} contains an unexpected participant: {:?} (expected {:?})",
                    node_id,
                    batch_participants,
                    expected_participants,
                );
            }
        }
        for change in step.output.iter().map(Batch::change) {
            match change {
                ChangeState::Complete(Change::NodeChange(ref pub_keys))
                    if *pub_keys == new_pub_keys =>
                {
                    println!("Node {} done applying a new subset.", node_id);
                    // Applying a new subset complete, tally:
                    awaiting_apply_new_subset.remove(&node_id);
                }

                ChangeState::InProgress(Change::NodeChange(ref pub_keys))
                    if *pub_keys == old_pub_keys =>
                {
                    println!(
                        "Node {} is progressing for applying the old subset.",
                        node_id
                    );
                    awaiting_apply_old_subset_in_progress.remove(&node_id);
                }

                ChangeState::Complete(Change::NodeChange(ref pub_keys))
                    if *pub_keys == old_pub_keys =>
                {
                    println!("Node {} done applying the old subset back.", node_id);
                    // Node has applied the old subset, ensure it has applied the new subset previously.
                    assert!(
                        !awaiting_apply_new_subset.contains(&node_id),
                        "Node {} reported a success applying the old subset before applying the new subset.",
                        node_id,
                    );
                    awaiting_apply_old_subset.remove(&node_id);
                }
                ChangeState::None => (),
                _ => {
                    println!("Unhandled change: {:?}", change);
                }
            }
        }

        let (era, hb_epoch) = state.net[node_id].algorithm().algo().epoch();
        if !nodes_for_remove.contains(&node_id)
            && awaiting_apply_old_subset_input.contains(&node_id)
            && state.re_add_epoch.is_some()
            && era + hb_epoch >= state.re_add_epoch.unwrap()
        {
            // Now we apply old subset of node back. Public keys will be reused.
            let step = state
                .net
                .send_input(
                    node_id,
                    Input::Change(Change::NodeChange(old_pub_keys.clone())),
                    &mut rng,
                )
                .expect("failed to send `apply old subset` input");
            assert!(step.output.is_empty());
            awaiting_apply_old_subset_input.remove(&node_id);
            println!("Node {} started to apply old subset.", node_id);
        }

        // Record whether or not we received some output.
        let has_output = !step.output.is_empty();

        // Find the node's input queue.
        let queue: &mut Vec<_> = queues
            .get_mut(&node_id)
            .expect("queue for node disappeared");

        // Examine potential algorithm output.
        for batch in step.output {
            println!(
                "Received epoch {} batch on node {:?}.",
                batch.epoch(),
                node_id,
            );

            // If this is a batch applying the new subset of nodes, record the epoch
            // in which 'nodes_for_remove' will shut down.
            if let ChangeState::Complete(Change::NodeChange(ref pub_keys)) = batch.change() {
                if *pub_keys == new_pub_keys {
                    state.re_add_epoch = Some(batch.epoch() + 1);
                }
            }

            for tx in batch.iter() {
                // Remove the confirmed contribution from the input queue.
                let index = queue.iter().position(|v| v == tx);
                if let Some(idx) = index {
                    assert_eq!(queue.remove(idx), *tx);
                }

                // Add it to the set of received outputs.
                if !state.net[node_id].is_faulty() {
                    expected_outputs
                        .get_mut(&node_id)
                        .expect("output set disappeared")
                        .remove(tx);
                    // Also, delete expected output from the 'nodes_for_remove' if those nodes are
                    // currently removed. They do not output any values in epochs in which they
                    // are not a participant.
                    if !nodes_for_remove.contains(&node_id)
                        && awaiting_apply_new_subset.is_empty()
                        && !state.old_subset_applied
                    {
                        nodes_for_remove.iter().for_each(|id| {
                            expected_outputs
                                .get_mut(&id)
                                .map(|output| output.remove(tx));
                        });
                    }
                }
            }
            // If this is the first batch from a correct node with a vote to apply the old subset
            // back, take the join plan of the batch and use it to restart removed nodes.
            if !state.old_subset_applied
                && !state.net[node_id].is_faulty()
                && state.join_plan.is_none()
            {
                if let ChangeState::InProgress(Change::NodeChange(pub_keys)) = batch.change() {
                    if *pub_keys == old_pub_keys {
                        state.join_plan = Some(
                            batch
                                .join_plan()
                                .expect("failed to get the join plan of the batch"),
                        );
                    }
                }
            }
            // Restart removed nodes having checked that they can be correctly restarted.
            if !state.old_subset_applied && awaiting_apply_old_subset_in_progress.is_empty() {
                if let Some(join_plan) = state.join_plan.take() {
                    let saved_nodes: Vec<_> = state.saved_nodes.drain(..).collect();

                    assert!(!saved_nodes.is_empty(), "removed nodes wasn't saved");

                    saved_nodes.into_iter().for_each(|node| {
                        let node_id = *node.id();
                        let step =
                            restart_node_for_add(&mut state.net, node, join_plan.clone(), &mut rng);
                        state
                            .net
                            .process_step(node_id, &step)
                            .expect("processing a step failed");
                    });
                    state.old_subset_applied = true;
                }
            }
        }

        let all_removed = |nodes: &BTreeSet<usize>| {
            nodes
                .iter()
                .all(|id| state.net[*id].algorithm().is_removed())
        };
        // Decide - from the point of view of removed nodes - whether they are ready to go offline.
        if !state.old_subset_applied
            && state.saved_nodes.is_empty()
            && all_removed(&nodes_for_remove)
        {
            println!(
                "Removing nodes {:?} from the test network.",
                nodes_for_remove
            );
            state.saved_nodes = state.net.remove_nodes(&nodes_for_remove);
            if nodes_for_remove.contains(&node_id) {
                // Further operations on the cranked node are not possible. Continue with
                // processing other nodes.
                continue;
            }
        }

        // Check if we are done.
        if expected_outputs.values().all(BTreeSet::is_empty)
            && awaiting_apply_old_subset.is_empty()
            && awaiting_apply_new_subset.is_empty()
        {
            // All outputs are empty, the old subset was applied back after that
            // new subset was applied.
            break;
        }

        // If not done, check if we still want to propose something.
        if has_output {
            // Out of the remaining transactions, select a suitable amount.
            let proposal =
                choose_contribution(&mut rng, queue, cfg.batch_size, cfg.contribution_size);

            let _ = state
                .net
                .send_input(node_id, Input::User(proposal), &mut rng)
                .expect("could not send follow-up transaction");
        }
    }

    // As a final step, we verify that all nodes have arrived at the same conclusion.
    // Removed nodes can miss some batches while they were removed.
    let result: Vec<_> = state
        .net
        .correct_nodes()
        .filter(|node| !nodes_for_remove.contains(node.id()))
        .map(|node| {
            state.net.verify_batches(&node);
            node.outputs()
        })
        .collect();

    assert!(!result.is_empty(), "Could not find a full node");

    println!("End result: {:?}", result);
}

/// Restarts specified node on the test network for adding it back as a validator.
fn restart_node_for_add<R, A>(
    net: &mut VirtualNet<DHB, A>,
    mut node: Node<DHB>,
    join_plan: JoinPlan<usize>,
    rng: &mut R,
) -> Step<DynamicHoneyBadger<Vec<usize>, usize>>
where
    R: rand::Rng,
    A: Adversary<DHB>,
{
    println!("Restarting node {} with {:?}", node.id(), join_plan);
    // TODO: When an observer node is added to the network, it should also be added to peer_ids.
    let peer_ids: Vec<_> = net
        .nodes()
        .map(Node::id)
        .filter(|id| *id != node.id())
        .cloned()
        .collect();
    let step = node
        .algorithm_mut()
        .restart(join_plan, peer_ids.into_iter(), rng)
        .expect("failed to restart the node");
    net.insert_node(node);
    step
}

/// Internal state of the test.
struct TestState<A>
where
    A: Adversary<DHB>,
{
    /// The test network.
    net: VirtualNet<DHB, A>,
    /// The join plan for adding nodes.
    join_plan: Option<JoinPlan<usize>>,
    /// The epoch in which the removed nodes should go offline.
    re_add_epoch: Option<u64>,
    /// The removed nodes which are to be restarted as soon as all remaining
    /// validators agree to add them back.
    saved_nodes: Vec<Node<DHB>>,
    /// Whether the old subset of validators was applied back to the network.
    old_subset_applied: bool,
}

impl<A> TestState<A>
where
    A: Adversary<DHB>,
{
    /// Constructs a new `VirtualNetState`.
    fn new(net: VirtualNet<DHB, A>) -> Self {
        TestState {
            net,
            join_plan: None,
            re_add_epoch: None,
            saved_nodes: Vec::new(),
            old_subset_applied: false,
        }
    }

    /// Selects random subset of validators which can be safely removed from the network.
    ///
    /// The cluster always remain correct after removing this subset from the cluster.
    /// This method may select correct nodes as well as malicious ones.
    fn subset_for_remove<R>(&self, rng: &mut R) -> BTreeSet<usize>
    where
        R: rand::Rng,
    {
        let net = &self.net;
        let (faulty, correct): (Vec<_>, Vec<_>) = net.nodes().partition(|n| n.is_faulty());

        let f = faulty.len();
        let n = correct.len() + f;

        assert!(n > 2, "cannot remove any more nodes");
        assert!(
            n > f * 3,
            "the network is already captured by the faulty nodes"
        );

        let new_n = rng.gen_range(2, n); // new_n is between 2 and n-1
        let min_new_f = f.saturating_sub(n - new_n);
        let new_f = rng.gen_range(min_new_f, f.min(util::max_faulty(new_n)) + 1);

        let remove_from_faulty = f - new_f;
        let remove_from_correct = n - new_n - remove_from_faulty;

        let result: BTreeSet<usize> = correct
            .choose_multiple(rng, remove_from_correct)
            .map(|n| *n.id())
            .chain(
                faulty
                    .choose_multiple(rng, remove_from_faulty)
                    .map(|n| *n.id()),
            )
            .collect();

        assert!(
            !result.is_empty(),
            "subset for remove should have at least one node"
        );
        println!("{} nodes were chosen for removing", result.len());

        result
    }

    /// Returns clone of all public keys for this network.
    fn get_pub_keys(&self) -> PubKeyMap<usize> {
        self.net
            .get(0)
            .expect("network should have at least one node")
            .algorithm()
            .algo()
            .public_keys()
            .clone()
    }
}
