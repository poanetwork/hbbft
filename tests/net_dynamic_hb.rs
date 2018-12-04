extern crate failure;
extern crate hbbft;
extern crate integer_sqrt;
extern crate proptest;
extern crate rand;
extern crate threshold_crypto;

pub mod net;

use std::{collections, time};

use hbbft::dynamic_honey_badger::{Change, ChangeState, DynamicHoneyBadger, Input};
use hbbft::sender_queue::SenderQueue;
use net::adversary::ReorderingAdversary;
use net::proptest::{gen_seed, NetworkDimension, TestRng, TestRngSeed};
use net::{NetBuilder, NewNodeInfo};
use proptest::{prelude::ProptestConfig, prop_compose, proptest, proptest_helper};
use rand::{Rng, SeedableRng};

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

    rand::seq::sample_slice(rng, &queue[0..n], k)
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
        TestConfig{
            dimension, total_txs, batch_size, contribution_size, seed
        }
    }
}

/// Proptest wrapper for `do_drop_and_readd`.
proptest!{
    #![proptest_config(ProptestConfig {
        cases: 1, .. ProptestConfig::default()
    })]
    #[test]
    #[cfg_attr(feature = "cargo-clippy", allow(unnecessary_operation))]
    fn drop_and_readd(cfg in arb_config()) {
        do_drop_and_readd(cfg)
    }
}

/// Dynamic honey badger: Drop a validator node, demoting it to observer, then re-add it, all while
/// running a regular honey badger network.
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn do_drop_and_readd(cfg: TestConfig) {
    let mut rng: TestRng = TestRng::from_seed(cfg.seed);

    // First, we create a new test network with Honey Badger instances.
    let mut net = NetBuilder::new(0..cfg.dimension.size())
        .num_faulty(cfg.dimension.faulty())
        // Limited to 15k messages per node.
        .message_limit(15_000 * cfg.dimension.size() as usize)
        // 30 secs per node.
        .time_limit(time::Duration::from_secs(30 * cfg.dimension.size() as u64))
        // Ensure runs are reproducible.
        .rng(rng.gen::<TestRng>())
        .adversary(ReorderingAdversary::new(rng.gen::<TestRng>()))
        .using_step(move |node: NewNodeInfo<SenderQueue<_>>| {
            let id = node.id;
            println!("Constructing new dynamic honey badger node #{}", id);
            let dhb = DynamicHoneyBadger::builder()
                .rng(node.rng)
                .build(node.netinfo.clone());
            SenderQueue::builder(
                dhb,
                node.netinfo.all_ids().filter(|&&them| them != id).cloned(),
            ).build(node.id)
        }).build()
        .expect("could not construct test network");

    // We will use the first correct node as the node we will remove from and re-add to the network.
    // Note: This should be randomized using proptest.
    let pivot_node_id: usize = *(net
        .correct_nodes()
        .nth(0)
        .expect("expected at least one correct node")
        .id());
    println!("Will remove and readd node #{}", pivot_node_id);

    // We generate a list of transaction we want to propose, for each node. All nodes will propose
    // a number between 0..total_txs, chosen randomly.
    let mut queues: collections::BTreeMap<_, Vec<usize>> = net
        .nodes()
        .map(|node| (*node.id(), (0..cfg.total_txs).collect()))
        .collect();

    // For each node, select transactions randomly from the queue and propose them.
    for (id, queue) in &mut queues {
        let proposal = choose_contribution(&mut rng, queue, cfg.batch_size, cfg.contribution_size);
        println!("Node {:?} will propose: {:?}", id, proposal);

        // The step will have its messages added to the queue automatically, we ignore the output.
        let _ = net
            .send_input(*id, Input::User(proposal))
            .expect("could not send initial transaction");
    }

    // Afterwards, remove a specific node from the dynamic honey badger network.
    let netinfo = net
        .get(pivot_node_id)
        .expect("pivot node missing")
        .algorithm()
        .algo()
        .netinfo()
        .clone();
    let pub_keys_add = netinfo.public_key_map().clone();
    let mut pub_keys_rm = pub_keys_add.clone();
    pub_keys_rm.remove(&pivot_node_id);
    net.broadcast_input(&Input::Change(Change::NodeChange(pub_keys_rm.clone())))
        .expect("broadcasting failed");

    // We are tracking (correct) nodes' state through the process by ticking them off individually.
    let mut awaiting_removal: collections::BTreeSet<_> =
        net.correct_nodes().map(|n| *n.id()).collect();
    let mut awaiting_addition: collections::BTreeSet<_> =
        net.correct_nodes().map(|n| *n.id()).collect();
    let mut expected_outputs: collections::BTreeMap<_, collections::BTreeSet<_>> = net
        .correct_nodes()
        .map(|n| (*n.id(), (0..10).collect()))
        .collect();

    // Run the network:
    loop {
        let (node_id, step) = net.crank_expect();
        if !net[node_id].is_faulty() {
            // Verify that only contributions from expected participants can be present in the batch.
            for batch in &step.output {
                let expected_participants: Vec<_> = if awaiting_removal.contains(&node_id) {
                    // The node hasn't removed the pivot node yet.
                    pub_keys_add.keys()
                } else if awaiting_addition.contains(&node_id) {
                    // The node has removed the pivot node but hasn't added it back yet.
                    pub_keys_rm.keys()
                } else {
                    // The node has added the pivot node back.
                    pub_keys_add.keys()
                }.collect();
                let batch_participants: Vec<_> = batch.contributions().map(|(id, _)| id).collect();
                assert!(
                    batch_participants
                        .iter()
                        .all(|id| expected_participants.contains(id)),
                    "The batch at node {} contains a contribution from an unexpected participant: {:?}",
                    node_id,
                    batch
                );
            }
        }
        for change in step.output.iter().map(|output| output.change()) {
            match change {
                ChangeState::Complete(Change::NodeChange(ref pub_keys))
                    if *pub_keys == pub_keys_rm =>
                {
                    println!("Node {:?} done removing.", node_id);
                    // Removal complete, tally:
                    awaiting_removal.remove(&node_id);

                    // Now we can add the node again. Public keys will be reused.
                    let _ = net
                        .send_input(
                            node_id,
                            Input::Change(Change::NodeChange(pub_keys_add.clone())),
                        ).expect("failed to send `Add` input");
                }

                ChangeState::Complete(Change::NodeChange(ref pub_keys))
                    if *pub_keys == pub_keys_add =>
                {
                    println!("Node {:?} done adding.", node_id);
                    // Node added, ensure it has been removed first.
                    if awaiting_removal.contains(&node_id) {
                        panic!(
                            "Node {:?} reported a success `Add({}, _)` before `Remove({})`",
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

            for tx in batch.iter() {
                // Remove the confirmed contribution from the input queue.
                let index = queue.iter().position(|v| v == tx);
                if let Some(idx) = index {
                    assert_eq!(queue.remove(idx), *tx);
                }

                // Add it to the set of received outputs.
                if !net[node_id].is_faulty() {
                    expected_outputs
                        .get_mut(&node_id)
                        .expect("output set disappeared")
                        .remove(tx);
                }
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

            let _ = net
                .send_input(node_id, Input::User(proposal))
                .expect("could not send follow-up transaction");
        }
    }

    // As a final step, we verify that all nodes have arrived at the same conclusion.
    let out = net.verify_batches();

    println!("End result: {:?}", out);
}
