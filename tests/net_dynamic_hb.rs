extern crate failure;
extern crate hbbft;
extern crate rand;
extern crate threshold_crypto;

pub mod net;

use std::{collections, ops};

use hbbft::dynamic_honey_badger::{Change, ChangeState, DynamicHoneyBadger, Input};
use hbbft::messaging::DistAlgorithm;

use net::adversary::NullAdversary;
use net::VirtualNet;

trait SubSlice
where
    Self: ops::Index<ops::Range<usize>>,
{
    #[inline]
    fn subslice(
        &self,
        range: ops::Range<usize>,
    ) -> &<Self as ops::Index<ops::Range<usize>>>::Output;
}

impl<T> SubSlice for [T] {
    #[inline]
    fn subslice(
        &self,
        mut range: ops::Range<usize>,
    ) -> &<Self as ops::Index<ops::Range<usize>>>::Output {
        if range.end > self.len() {
            range.end = self.len();
        }

        &self[range]
    }
}

fn choose_approx<R: ?Sized + rand::Rng, T: Clone>(
    rng: &mut R,
    mut slice: &[T],
    mut n: usize,
    out_of_first: usize,
) {
    slice = &slice[..(out_of_first.min(slice.len()))];
}

// FIXME: User better batch size, etc.

#[test]
fn drop_and_readd() {
    // Currently fixed settings; to be replace by proptest later on.
    do_drop_and_readd(3, 10, 10, 3)
}

/// Dynamic honey badger: Drop a validator node, demoting it to observer, then re-add it.
///
/// * `num_faulty`: The number of faulty nodes.
/// * `total`: Total number of nodes. Must be >= `3 * num_faulty + 1`.
/// * `total_txs`: The total number of transactions each node will propose. All nodes will propose
///                the same transactions, albeit in random order.
/// * `proposals_per_epoch`: The number of transaction to propose, per epoch.
fn do_drop_and_readd(
    num_faulty: usize,
    total: usize,
    total_txs: usize,
    proposals_per_epoch: usize,
) {
    let mut rng = rand::thread_rng();

    const NEW_OBSERVER_NODE_ID: usize = 0;

    // First, we create a new test network with Honey Badger instances.
    // Dynamic honey badger does not output an initial step, so we use a regular construction
    // function:
    let mut net: VirtualNet<DynamicHoneyBadger<Vec<usize>, _>> =
        VirtualNet::new(0..total, num_faulty, |id, netinfo| {
            println!("Constructing new dynamic honey badger node #{}", id);

            DynamicHoneyBadger::builder().build(netinfo)
        }).expect("could not construct test network");

    // Our test network includes faulty nodes, so we need an adversary.
    net.set_adversary(Box::new(NullAdversary::new()));

    // We generate a list of transaction we want to propose, for each node. All nodes will propose
    // a number between 0..total_txs, chosen randomly.
    let mut queues: collections::BTreeMap<_, Vec<usize>> = net
        .nodes()
        .map(|node| (node.id().clone(), (0..total_txs).collect()))
        .collect();

    // For each node, select transactions randomly from the queue and propose them.
    for (id, queue) in queues.iter_mut() {
        let proposal =
            rand::seq::sample_slice(&mut rng, queue.as_slice(), proposals_per_epoch).to_vec();
        println!("Node {:?} will propose: {:?}", id, proposal);

        // The step will have its messages added to the queue automatically, we ignore the output.
        let _ = net
            .send_input(*id, Input::User(proposal))
            .expect("could not send initial transaction");
    }

    // Afterwards, remove a specific node from the dynamic honey badger network.
    net.broadcast_input(&Input::Change(Change::Remove(NEW_OBSERVER_NODE_ID)))
        .expect("broadcasting failed");

    // We are tracking (correct) nodes' state through the process by ticking them off individually.
    let mut awaiting_removal: collections::BTreeSet<_> =
        net.correct_nodes().map(|n| n.id().clone()).collect();
    let mut awaiting_addition: collections::BTreeSet<_> =
        net.correct_nodes().map(|n| n.id().clone()).collect();
    let mut expected_outputs: collections::BTreeMap<_, collections::BTreeSet<_>> = net
        .correct_nodes()
        .map(|n| (n.id().clone(), (0..10).into_iter().collect()))
        .collect();

    // Run the network:
    loop {
        let (node_id, step) = net
            .crank()
            .expect("network queue emptied unexpectedly")
            .expect("node failed to process step");

        for change in step.output.iter().map(|output| output.change()) {
            if let ChangeState::Complete(Change::Remove(NEW_OBSERVER_NODE_ID)) = change {
                println!("Node {:?} done removing.", node_id);
                // Removal complete, tally:
                awaiting_removal.remove(&node_id);

                // Now we can add the node again. Public keys will be reused.
                let pk = net[NEW_OBSERVER_NODE_ID]
                    .algorithm()
                    .netinfo()
                    .secret_key()
                    .public_key();
                let _ = net[node_id]
                    .algorithm_mut()
                    .input(Input::Change(Change::Add(NEW_OBSERVER_NODE_ID, pk)))
                    .expect("failed to send `Add` input");
            }

            if let ChangeState::Complete(Change::Add(NEW_OBSERVER_NODE_ID, _)) = change {
                println!("Node {:?} done adding.", node_id);
                // Node added, ensure it has been removed first.
                if awaiting_removal.contains(&node_id) {
                    panic!(
                        "Node {:?} reported a success `Add({}, _)` before `Remove({})`",
                        node_id, NEW_OBSERVER_NODE_ID, NEW_OBSERVER_NODE_ID
                    );
                }
                awaiting_addition.remove(&node_id);
            }

            println!("Unhandled change: {:?}", change);
        }

        // Record whether or not we received some output.
        let has_output = !step.output.is_empty();

        // Find the node's input queue.
        let queue: &mut Vec<_> = queues
            .get_mut(&node_id)
            .expect("queue for node disappeared");

        // Examine potential algorithm output.
        for batch in step.output.into_iter() {
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
                    // println!(
                    //     "Removed {} from output set of node {}, remaining: {:?}",
                    //     tx,
                    //     node_id,
                    //     expected_outputs.get(&node_id).unwrap()
                    // );
                }
            }
        }

        // Finally, check if we are done.
        if expected_outputs.values().all(|s| s.is_empty())
            && awaiting_addition.is_empty()
            && awaiting_removal.is_empty()
        {
            println!(
                "All outputs are empty all nodes have removed and added the single dynamic node."
            );
            break;
        }

        // Now check if we still want to propose something.
        if has_output {
            if !queue.is_empty() {
                // println!("More to propose: {:?}", queue);

                // Out of the remaining transaction, select a suitable amount.
                let proposal = rand::seq::sample_slice(
                    &mut rng,
                    // FIXME: Use better numbers.
                    queue.as_slice().subslice(0..10),
                    10.min(3.min(queue.len())),
                );
                // println!("Selected: {:?}", proposal);

                let _ = net
                    .send_input(node_id, Input::User(proposal))
                    .expect("could not send follow-up transaction");
            } else {
                net.send_input(node_id, Input::User(Vec::new()))
                    .expect("could not send follow-up transaction");
            }
        }
    }

    // FIXME: Ensure output order is the same.
}
