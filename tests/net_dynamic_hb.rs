pub mod net;

use std::collections::{BTreeMap, BTreeSet};
use std::time;

use hbbft::dynamic_honey_badger::{Change, ChangeState, DynamicHoneyBadger, Input, JoinPlan};
use hbbft::sender_queue::{SenderQueue, Step};
use hbbft::Epoched;
use proptest::{prelude::ProptestConfig, prop_compose, proptest, proptest_helper};
use rand::{seq::SliceRandom, SeedableRng};

use crate::net::adversary::{Adversary, ReorderingAdversary};
use crate::net::proptest::{gen_seed, NetworkDimension, TestRng, TestRngSeed};
use crate::net::{NetBuilder, NewNodeInfo, Node, VirtualNet};

type DHB = SenderQueue<DynamicHoneyBadger<Vec<usize>, usize>>;

/// Choose a node's contribution for an epoch.
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

/// Proptest wrapper for `do_drop_and_readd`.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1, .. ProptestConfig::default()
    })]
    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn drop_and_readd(cfg in arb_config()) {
        do_drop_and_readd(cfg)
    }
}

/// Dynamic honey badger: Drop a validator node, demoting it to observer, then re-add it, all while
/// running a regular honey badger network.
// TODO: Add an observer node to the test network.
#[allow(clippy::needless_pass_by_value, clippy::cyclomatic_complexity)]
fn do_drop_and_readd(cfg: TestConfig) {
    let mut rng: TestRng = TestRng::from_seed(cfg.seed);

    // First, we create a new test network with Honey Badger instances.
    let num_faulty = cfg.dimension.faulty();
    let (net, _) = NetBuilder::new(0..cfg.dimension.size())
        .num_faulty(num_faulty)
        // Limited to 15k messages per node.
        .message_limit(15_000 * cfg.dimension.size() as usize)
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
            let dhb = DynamicHoneyBadger::builder().build(node.netinfo.clone());
            SenderQueue::builder(
                dhb,
                node.netinfo.all_ids().filter(|&&them| them != id).cloned(),
            )
            .build(node.id)
        })
        .build(&mut rng)
        .expect("could not construct test network");

    let mut state = TestState::new(net);

    // We will use the first correct node as the node we will remove from and re-add to the network.
    // Note: This should be randomized using proptest.
    let pivot_node_id: usize = *(state
        .net
        .correct_nodes()
        .nth(0)
        .expect("expected at least one correct node")
        .id());
    println!("Will remove and readd node #{}", pivot_node_id);

    // We generate a list of transaction we want to propose, for each node. All nodes will propose
    // a number between 0..total_txs, chosen randomly.
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

    // Afterwards, remove a specific node from the dynamic honey badger network.
    let netinfo = state
        .net
        .get(pivot_node_id)
        .expect("pivot node missing")
        .algorithm()
        .algo()
        .netinfo()
        .clone();
    let pub_keys_add = netinfo.public_key_map().clone();
    let mut pub_keys_rm = pub_keys_add.clone();
    pub_keys_rm.remove(&pivot_node_id);
    state
        .net
        .broadcast_input(
            &Input::Change(Change::NodeChange(pub_keys_rm.clone())),
            &mut rng,
        )
        .expect("broadcasting failed");

    // We are tracking (correct) nodes' state through the process by ticking them off individually.
    let non_pivot_nodes: BTreeSet<_> = state
        .net
        .correct_nodes()
        .map(|n| *n.id())
        .filter(|id| *id != pivot_node_id)
        .collect();
    let mut awaiting_removal: BTreeSet<_> = state.net.correct_nodes().map(|n| *n.id()).collect();
    let mut awaiting_addition_input: BTreeSet<_> = non_pivot_nodes.clone();
    let mut awaiting_addition_in_progress: BTreeSet<_> = non_pivot_nodes.clone();
    let mut awaiting_addition: BTreeSet<_> = awaiting_removal.clone();
    let mut expected_outputs: BTreeMap<_, BTreeSet<_>> = state
        .net
        .correct_nodes()
        .map(|n| (*n.id(), (0..10).collect()))
        .collect();
    let mut received_batches: BTreeMap<u64, _> = BTreeMap::new();
    // Whether node 0 was rejoined as a validator.
    let mut rejoined_pivot_node = false;
    // The removed pivot node which is to be restarted as soon as all remaining validators agree to
    // add it back.
    let mut saved_node: Option<Node<DHB>> = None;

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
                let expected_participants: Vec<_> = if awaiting_removal.contains(&node_id) {
                    // The node hasn't removed the pivot node yet.
                    pub_keys_add.keys()
                } else if awaiting_addition.contains(&node_id) {
                    // The node has removed the pivot node but hasn't added it back yet.
                    pub_keys_rm.keys()
                } else {
                    // The node has added the pivot node back.
                    pub_keys_add.keys()
                }
                .collect();
                assert!(
                    batch.contributions().count() * 3 > expected_participants.len() * 2,
                    "The batch contains less than N - f contributions: {:?}",
                    batch
                );
                // Verify that only contributions from expected participants can be present in the
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
        for change in step.output.iter().map(|output| output.change()) {
            match change {
                ChangeState::Complete(Change::NodeChange(ref pub_keys))
                    if *pub_keys == pub_keys_rm =>
                {
                    println!("Node {} done removing.", node_id);
                    // Removal complete, tally:
                    awaiting_removal.remove(&node_id);
                }

                ChangeState::InProgress(Change::NodeChange(ref pub_keys))
                    if *pub_keys == pub_keys_add =>
                {
                    println!("Node {} is progressing with readding.", node_id);
                    awaiting_addition_in_progress.remove(&node_id);
                }

                ChangeState::Complete(Change::NodeChange(ref pub_keys))
                    if *pub_keys == pub_keys_add =>
                {
                    println!("Node {} done adding.", node_id);
                    // Node added, ensure it has been removed first.
                    if awaiting_removal.contains(&node_id) {
                        panic!(
                            "Node {} reported a success `Add({}, _)` before `Remove({})`",
                            node_id, pivot_node_id, pivot_node_id
                        );
                    }
                    awaiting_addition.remove(&node_id);
                }
                _ => {
                    println!("Unhandled change: {:?}", change);
                }
            }
        }

        let (era, hb_epoch) = state.net[node_id].algorithm().algo().epoch();
        if node_id != pivot_node_id
            && awaiting_addition_input.contains(&node_id)
            && state.shutdown_epoch.is_some()
            && era + hb_epoch == state.shutdown_epoch.unwrap()
        {
            // Now we can add the node again. Public keys will be reused.
            let _ = state
                .net
                .send_input(
                    node_id,
                    Input::Change(Change::NodeChange(pub_keys_add.clone())),
                    &mut rng,
                )
                .expect("failed to send `Add` input");
            awaiting_addition_input.remove(&node_id);
            println!("Node {} started readding.", node_id);
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

            // If this is a batch removing the pivot node, record the epoch in which the pivot node
            // will shut down.
            if let ChangeState::Complete(Change::NodeChange(ref pub_keys)) = batch.change() {
                if *pub_keys == pub_keys_rm {
                    state.shutdown_epoch = Some(batch.epoch() + 1);
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
                    // Also delete expected output from the pivot node if that node is currently
                    // removed. It does not output any values in epochs in which it is not a
                    // participant.
                    if node_id != pivot_node_id
                        && awaiting_removal.is_empty()
                        && !rejoined_pivot_node
                    {
                        expected_outputs
                            .get_mut(&pivot_node_id)
                            .expect("pivot node output set disappeared")
                            .remove(tx);
                    }
                }
            }
            // If this is the first batch from a correct node with a vote to add node 0 back, take
            // the join plan of the batch and use it to restart node 0.
            if !rejoined_pivot_node && !state.net[node_id].is_faulty() && state.join_plan.is_none()
            {
                if let ChangeState::InProgress(Change::NodeChange(pub_keys)) = batch.change() {
                    if *pub_keys == pub_keys_add {
                        state.join_plan = Some(
                            batch
                                .join_plan()
                                .expect("failed to get the join plan of the batch"),
                        );
                    }
                }
            }
            // Restart the pivot node having checked that it can be correctly restarted.
            if !rejoined_pivot_node && awaiting_addition_in_progress.is_empty() {
                if let Some(join_plan) = state.join_plan.take() {
                    let node = saved_node.take().expect("the pivot node wasn't saved");
                    let step = restart_node_for_add(&mut state.net, node, join_plan, &mut rng);
                    state
                        .net
                        .process_step(pivot_node_id, &step)
                        .expect("processing a step failed");
                    rejoined_pivot_node = true;
                }
            }
        }

        // Decide - from the point of view of the pivot node - whether it is ready to go offline.
        if !rejoined_pivot_node
            && saved_node.is_none()
            && state.net[pivot_node_id].algorithm().is_removed()
        {
            println!(
                "Removing the pivot node {} from the test network.",
                pivot_node_id
            );
            saved_node = state.net.remove_node(&pivot_node_id);
            if node_id == pivot_node_id {
                // Further operations on the cranked node are not possible. Continue with
                // processing other nodes.
                continue;
            }
        }

        // Check if we are done.
        if expected_outputs.values().all(|s| s.is_empty())
            && awaiting_addition.is_empty()
            && awaiting_removal.is_empty()
        {
            // All outputs are empty and all nodes have removed and added the single pivot node.
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

    // As a final step, we verify that all nodes have arrived at the same conclusion. The pivot node
    // can miss some batches while it was removed.
    let full_node = state
        .net
        .correct_nodes()
        .find(|node| *node.id() != pivot_node_id)
        .expect("Could not find a full node");
    state.net.verify_batches(&full_node);
    println!("End result: {:?}", full_node.outputs());
}

/// Restarts node 0 on the test network for adding it back as a validator.
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
        .map(|node| node.id())
        .filter(|id| *id != node.id())
        .cloned()
        .collect();
    let step = node
        .algorithm_mut()
        .restart(join_plan, peer_ids.into_iter(), rng)
        .expect("failed to restart pivot node");
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
    /// The join plan for readding the pivot node.
    join_plan: Option<JoinPlan<usize>>,
    /// The epoch in which the pivot node should go offline.
    shutdown_epoch: Option<u64>,
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
            shutdown_epoch: None,
        }
    }
}
