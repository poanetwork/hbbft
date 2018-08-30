extern crate failure;
extern crate hbbft;
extern crate rand;
extern crate threshold_crypto;

pub mod net;

use std::collections;

use hbbft::dynamic_honey_badger::{Change, ChangeState, DynamicHoneyBadger, Input};
use hbbft::messaging::DistAlgorithm;

use net::NetBuilder;

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

// Note: Still pending: Better batch sizes (configurable).
#[test]
fn drop_and_readd() {
    // Currently fixed settings; to be replace by proptest later on. This wrapper function is
    // already in place, to avoid with rustfmt not formatting the inside of macros.
    do_drop_and_readd(3, 10, 20, 10, 3)
}

/// Dynamic honey badger: Drop a validator node, demoting it to observer, then re-add it.
///
/// * `num_faulty`: The number of faulty nodes.
/// * `total`: Total number of nodes. Must be >= `3 * num_faulty + 1`.
/// * `total_txs`: The total number of transactions each node will propose. All nodes will propose
///                the same transactions, albeit in random order.
/// * `batch_size`: The number of transaction per epoch, total.
/// * `contribution_size`: A single nodes contribution to the batch.
fn do_drop_and_readd(
    num_faulty: usize,
    total: usize,
    total_txs: usize,
    batch_size: usize,
    contribution_size: usize,
) {
    let mut rng = rand::thread_rng();

    // First, we create a new test network with Honey Badger instances.
    let mut net = NetBuilder::new(0..total)
        .num_faulty(num_faulty)
        .message_limit(200_000)  // Limited to 200k messages for now.
        .using_step(move |node| {
            println!("Constructing new dynamic honey badger node #{}", node.id);
            DynamicHoneyBadger::builder().build(node.netinfo).expect("cannot build instance")
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
        .map(|node| (*node.id(), (0..total_txs).collect()))
        .collect();

    // For each node, select transactions randomly from the queue and propose them.
    for (id, queue) in &mut queues {
        let proposal = choose_contribution(&mut rng, queue, batch_size, contribution_size);
        println!("Node {:?} will propose: {:?}", id, proposal);

        // The step will have its messages added to the queue automatically, we ignore the output.
        let _ = net
            .send_input(*id, Input::User(proposal))
            .expect("could not send initial transaction");
    }

    // Afterwards, remove a specific node from the dynamic honey badger network.
    net.broadcast_input(&Input::Change(Change::Remove(pivot_node_id)))
        .expect("broadcasting failed");

    // We are tracking (correct) nodes' state through the process by ticking them off individually.
    let mut awaiting_removal: collections::BTreeSet<_> =
        net.correct_nodes().map(|n| *n.id()).collect();
    let mut awaiting_addition: collections::BTreeSet<_> =
        net.correct_nodes().map(|n| *n.id()).collect();
    let mut expected_outputs: collections::BTreeMap<_, collections::BTreeSet<_>> = net
        .correct_nodes()
        .map(|n| (*n.id(), (0..10).into_iter().collect()))
        .collect();

    // Run the network:
    loop {
        let (node_id, step) = net.crank_expect();

        for change in step.output.iter().map(|output| output.change()) {
            match change {
                ChangeState::Complete(Change::Remove(pivot_node_id)) => {
                    println!("Node {:?} done removing.", node_id);
                    // Removal complete, tally:
                    awaiting_removal.remove(&node_id);

                    // Now we can add the node again. Public keys will be reused.
                    let pk = net[*pivot_node_id]
                        .algorithm()
                        .netinfo()
                        .secret_key()
                        .public_key();
                    let _ = net[node_id]
                        .algorithm_mut()
                        .handle_input(Input::Change(Change::Add(*pivot_node_id, pk)))
                        .expect("failed to send `Add` input");
                }

                ChangeState::Complete(Change::Add(pivot_node_id, _)) => {
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
            let proposal = choose_contribution(&mut rng, queue, batch_size, contribution_size);

            let _ = net
                .send_input(node_id, Input::User(proposal))
                .expect("could not send follow-up transaction");
        }
    }

    // As a final step, we verify that all nodes have arrived at the same conclusion.
    let first = net.correct_nodes().nth(0).unwrap().outputs();
    assert!(net.nodes().all(|node| node.outputs() == first));

    println!("End result: {:?}", first);
}
