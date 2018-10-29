extern crate failure;
extern crate hbbft;
#[macro_use]
extern crate proptest;
extern crate env_logger;
extern crate integer_sqrt;
#[macro_use]
extern crate log;
extern crate rand;
extern crate serde;
extern crate threshold_crypto;

pub mod net;

use std::{collections, time};

use proptest::strategy::Strategy;
use serde::{de::DeserializeOwned, Serialize};

use hbbft::dynamic_honey_badger::{Change, ChangeState, DynamicHoneyBadger, Input};
use hbbft::{NodeIdT, Step};
use net::adversary::{Adversary, NullAdversary};
use net::proptest::{gen_adversary, gen_seed, NetworkDimension, TestRng, TestRngSeed};
use net::{util, NetBuilder, Steps, VirtualNet};
use rand::{Rand, Rng, SeedableRng};

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
    /// Random general adversary
    adversary: Box<dyn Adversary<DynamicHoneyBadger<Vec<usize>, usize>>>,
}

prop_compose! {
    /// Strategy to generate a test configuration.
    fn arb_config()
                 (dimension in NetworkDimension::range(3, 15)
                     .prop_filter("Must have at least two nodes to remove one.".to_owned(),
                                  |dim| dim.size() > 1),
                  total_txs in 20..60usize,
                  batch_size in 10..20usize,
                  contribution_size in 1..10usize,
                  seed in gen_seed(),
                  adversary in gen_adversary())
                 -> TestConfig {
        TestConfig{
            dimension, total_txs, batch_size, contribution_size, seed, adversary
        }
    }
}

proptest!{
    /// Proptest wrapper for `do_drop_and_readd`.
    #[test]
    #[cfg_attr(feature = "cargo-clippy", allow(unnecessary_operation))]
    fn drop_and_readd(cfg in arb_config()) {
        do_drop_and_readd(cfg)
    }
}

proptest!{
    /// Small instance `drop_and_readd`.
    ///
    /// This is a regression tests that ensures a minimally sized test network works succesfully.
    #[test]
    fn small_instance_drop_and_readd(seed in gen_seed()) {
        do_drop_and_readd(TestConfig {
            dimension: NetworkDimension::new(2, 0),
            total_txs: 20,
            batch_size: 10,
            contribution_size: 1,
            seed,
            adversary: NullAdversary::new().boxed(),
        })
    }
}

#[derive(Debug)]
struct DropAndReAddProgress<V, N> {
    awaiting_removal: collections::BTreeSet<N>,
    awaiting_addition: collections::BTreeSet<N>,
    expected_outputs: collections::BTreeMap<N, collections::BTreeSet<V>>,
    queues: collections::BTreeMap<N, Vec<usize>>,
    batch_size: usize,
    contribution_size: usize,
}

// FIXME: Do not pin to `usize`.
impl<N> DropAndReAddProgress<usize, N>
where
    N: NodeIdT + Serialize + DeserializeOwned + Rand,
{
    fn new(
        net: &VirtualNet<DynamicHoneyBadger<Vec<usize>, N>>,
        batch_size: usize,
        contribution_size: usize,
    ) -> Self {
        let total_txs = 200;

        let expected_outputs: collections::BTreeMap<_, collections::BTreeSet<_>> = net
            .correct_nodes()
            .map(|node| (node.id().clone(), (0..total_txs).collect()))
            .collect();

        let queues: collections::BTreeMap<_, Vec<_>> = expected_outputs
            .iter()
            .map(|(id, txs)| (id.clone(), txs.iter().cloned().collect()))
            .collect();

        DropAndReAddProgress {
            awaiting_removal: net.correct_nodes().map(|n| n.id().clone()).collect(),
            awaiting_addition: net.correct_nodes().map(|n| n.id().clone()).collect(),
            expected_outputs,
            queues,
            batch_size,
            contribution_size,
        }
    }

    fn process_step<R: Rng>(
        &mut self,
        rng: &mut R,
        node_id: N,
        step: &Step<DynamicHoneyBadger<Vec<usize>, N>>,
        net: &mut VirtualNet<DynamicHoneyBadger<Vec<usize>, N>>,
    ) {
        for change in step.output.iter().map(|output| output.change()) {
            match change {
                ChangeState::Complete(Change::Remove(pivot_node_id)) => {
                    info!("Node {:?} done removing.", node_id);
                    // Removal complete, tally:
                    // FIXME: Check if correct ID is removed?
                    self.awaiting_removal.remove(&node_id);

                    // Now we can add the node again. Public keys will be reused.
                    let pk = net[pivot_node_id.clone()]
                        .algorithm()
                        .netinfo()
                        .secret_key()
                        .public_key();

                    let step = net
                        .send_input(
                            node_id.clone(),
                            Input::Change(Change::Add(pivot_node_id.clone(), pk)),
                        ).expect("failed to send `Add` input");
                    self.process_step(rng, node_id.clone(), &step, net);
                }

                ChangeState::Complete(Change::Add(pivot_node_id, _)) => {
                    info!("Node {:?} done adding.", node_id);
                    // Node added, ensure it has been removed first.
                    if self.awaiting_removal.contains(&node_id) {
                        panic!(
                            "Node {:?} reported a success `Add({:?}, _)` before `Remove({:?})`",
                            node_id, pivot_node_id, pivot_node_id
                        );
                    }
                    self.awaiting_addition.remove(&node_id);
                }
                ChangeState::None => {
                    // Nothing has changed yet.
                }
                _ => {
                    warn!("Unhandled change: {:?}", change);
                }
            }
        }

        let step = {
            // Find the node's input queue.
            let queue: &mut Vec<_> = self
                .queues
                .get_mut(&node_id)
                .expect("queue for node disappeared");

            // Examine potential algorithm output.
            // FIXME: Use owned step.
            for batch in &step.output {
                info!(
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
                    if !net[node_id.clone()].is_faulty() {
                        self.expected_outputs
                            .get_mut(&node_id)
                            .expect("output set disappeared")
                            .remove(tx);
                    }
                }
            }

            // If not done, check if we still want to propose something.
            if !step.output.is_empty() {
                // Out of the remaining transactions, select a suitable amount.
                let proposal =
                    choose_contribution(rng, queue, self.batch_size, self.contribution_size);

                Some(
                    net.send_input(node_id.clone(), Input::User(proposal))
                        .expect("could not send follow-up transaction"),
                )
            } else {
                None
            }
        };

        step.map(|step| self.process_step(rng, node_id.clone(), &step, net));
    }

    // fn process_steps(
    //     &mut self,
    //     steps: Steps<DynamicHoneyBadger<Vec<usize>, N>>,
    //     net: &mut VirtualNet<DynamicHoneyBadger<Vec<usize>, N>>,
    // ) {
    //     for (node_id, step) in steps.0 {
    //         self.process_step(node_id, &step, net)
    //     }
    // }

    // Checks if the test has finished successfully.
    //
    // The following conditions must be satisfied:
    //
    // 1. All nodes must have removed the pivot node once.
    // 2. All nodes must have re-add the pivot node once.
    // 3. All nodes must have output all queued transactions.
    fn finished(&self) -> bool {
        let incomplete = self
            .expected_outputs
            .values()
            .filter(|s| !s.is_empty())
            .count();
        // FIXME: Check order of outputs.
        // FIXME: Ensure addition/removal only happens once and in-order.
        debug!(
            "Checking for completion. Nodes with incomplete output: {}. \
             Awaiting addition: {:?}; awaiting removal: {:?}",
            incomplete, self.awaiting_addition, self.awaiting_removal
        );
        incomplete == 0 && self.awaiting_addition.is_empty() && self.awaiting_removal.is_empty()
    }
}

/// Dynamic honey badger: Drop a validator node, demoting it to observer, then re-add it, all while
/// running a regular honey badger network.
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn do_drop_and_readd(cfg: TestConfig) {
    util::init_logging();

    let mut rng: TestRng = TestRng::from_seed(cfg.seed);

    // Copy total transactions, as it is used multiple times throughout.
    let total_txs = cfg.total_txs;

    // First, we create a new test network with Honey Badger instances.
    let mut net = NetBuilder::new(0..cfg.dimension.size())
        .num_faulty(cfg.dimension.faulty())
        // Limited to 15k messages per node.
        .message_limit(15_000 * cfg.dimension.size() as usize)
        // 30 secs per node.
        .time_limit(time::Duration::from_secs(30 * cfg.dimension.size() as u64))
        // Ensure runs are reproducible.
        .rng(rng.gen::<TestRng>())
        .adversary(cfg.adversary)
        .using(move |node| {
            info!("Constructing new dynamic honey badger node #{}", node.id);
            DynamicHoneyBadger::builder()
                .rng(node.rng)
                .build(node.netinfo)
        }).build()
        .expect("could not construct test network");

    // We will use the first correct node as the node we will remove from and re-add to the network.
    // FIXME: This should be randomized using proptest.
    let pivot_node_id: usize = *(net
        .correct_nodes()
        .nth(0)
        .expect("expected at least one correct node")
        .id());
    info!("Will remove and readd node #{}", pivot_node_id);

    // We generate a list of transaction we want to propose, for each node. All nodes will propose
    // a number between 0..total_txs, chosen randomly.
    let mut queues: collections::BTreeMap<_, Vec<usize>> = net
        .nodes()
        .map(|node| (*node.id(), (0..total_txs).collect()))
        .collect();

    // We are tracking (correct) nodes' state through the process by ticking them off individually.
    let mut progress = DropAndReAddProgress::new(&net, cfg.batch_size, cfg.contribution_size);

    // For each node, select transactions randomly from the queue and propose them.
    for (&id, queue) in &mut queues {
        let proposal = choose_contribution(&mut rng, queue, cfg.batch_size, cfg.contribution_size);
        info!("Node {:?} will propose: {:?}", id, proposal);

        let step = net
            .send_input(id, Input::User(proposal))
            .expect("could not send initial transaction");

        progress.process_step(&mut rng, id, &step, &mut net);
    }

    // Afterwards, remove a specific node from the dynamic honey badger network.
    let steps = net
        .broadcast_input(&Input::Change(Change::Remove(pivot_node_id)))
        .expect("broadcasting failed");
    for (node_id, step) in steps.0 {
        progress.process_step(&mut rng, node_id, &step, &mut net);
    }

    while !progress.finished() {
        // First, crank the network, recording the output.
        let (node_id, step) = net.crank_expect();
        progress.process_step(&mut rng, node_id, &step, &mut net);

        // // Record whether or not we received some output.
        // let has_output = !step.output.is_empty();

        // // If not done, check if we still want to propose something.
        // if has_output {
        //     // Out of the remaining transactions, select a suitable amount.
        //     let proposal =
        //         choose_contribution(&mut rng, queue, cfg.batch_size, cfg.contribution_size);

        //     let step = net
        //         .send_input(node_id, Input::User(proposal))
        //         .expect("could not send follow-up transaction");
        //     progress.process_step(node_id, &step, &mut net);
        // }
    }

    // As a final step, we verify that all nodes have arrived at the same conclusion.
    let out = net.verify_batches();

    info!("End result: {:?}", out);
}
