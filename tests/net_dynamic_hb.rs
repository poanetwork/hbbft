extern crate failure;
extern crate hbbft;
extern crate rand;

pub mod net;

use std::collections;

use hbbft::dynamic_honey_badger::{Change, ChangeState, DynamicHoneyBadger, Input};
use hbbft::messaging::DistAlgorithm;

use net::adversary::NullAdversary;
use net::VirtualNet;

// FIXME: No observers yet.

#[test]
fn dyn_hb_test() {
    let mut rng = rand::thread_rng();

    // Number of faulty nodes.
    let num_faulty = 3;

    // Total number of nodes.
    let total = 10;

    // Number of transactions to run in test.
    let total_txs = 10;

    // Initial number of transactions to send
    let txs_to_send = 3;

    const NEW_OBSERVER_NODE_ID: usize = 0;

    // First, we create a new test network with Honey Badger instances.
    // Dynamic honey badger does not output an initial step, so we use a regular construction
    // function:
    let mut net: VirtualNet<DynamicHoneyBadger<Vec<usize>, _>> =
        VirtualNet::new(0..total, num_faulty, |id, netinfo| {
            println!("Constructing new dynamic honey badger node #{}", id);

            DynamicHoneyBadger::builder().build(netinfo)
        });

    // Our test network includes faulty nodes, so we need an adversary.
    net.set_adversary(Box::new(NullAdversary::new()));

    // We generate a list of transaction we want to propose, for each node. All nodes will propose
    // a number between 0..total_txs, chosen randomly.
    let mut queues: collections::BTreeMap<_, Vec<usize>> = net.nodes()
        .map(|node| (node.id().clone(), (0..total_txs).collect()))
        .collect();

    // For each node, select 3 transactions randomly from the queue and propose them.
    for (id, queue) in queues {
        let proposal = rand::seq::sample_slice(&mut rng, queue.as_slice(), txs_to_send).to_vec();
        println!("Node {:?} will propose: {:?}", id, proposal);
        net.send_input(id, Input::User(proposal));
    }

    // Afterwards, remove a specific node from the dynamic honey badger network.
    println!(
        "BROADCAST: {:?}",
        net.broadcast_input(&Input::Change(Change::Remove(NEW_OBSERVER_NODE_ID)))
    );

    // [

    // fn has_remove(node: &TestNode<UsizeDhb>) -> bool {
    //     node.outputs()
    //         .iter()
    //         .any(|batch| *batch.change() == ChangeState::Complete(Change::Remove(NodeUid(0))))
    // }

    // fn has_add(node: &TestNode<UsizeDhb>) -> bool {
    //     node.outputs().iter().any(|batch| match *batch.change() {
    //         ChangeState::Complete(Change::Add(ref id, _)) => *id == NodeUid(0),
    //         _ => false,
    //     })
    // }

    // // Returns `true` if the node has not output all transactions yet.
    // let node_busy = |node: &TestNode<UsizeDhb>| {
    //     if !has_remove(node) || !has_add(node) {
    //         return true;
    //     }
    //     node.outputs().iter().flat_map(Batch::iter).unique().count() < num_txs
    // };

    // ]

    // ??
    // let mut input_add = false; // Whether the vote to add node 0 has already been input.

    // enum TestNodeState {
    //     WaitingForRemoval,
    //     // v
    //     // |
    //     // v   input Add
    //     // |
    //     // v
    //     WaitingForAdd,
    //     // v
    //     // |
    //     // v   EPSILON
    //     // |
    //     // v
    //     WaitingForTransactions,
    //     // v
    //     // |
    //     // v   "terminate"
    //     // |
    //     // v
    //     Done,
    // }

    // We are tracking (correct) nodes' state through the process by ticking them off individually.
    let mut awaiting_removal: collections::BTreeSet<_> =
        net.correct_nodes().map(|n| n.id().clone()).collect();
    let mut awaiting_addition: collections::BTreeSet<_> =
        net.correct_nodes().map(|n| n.id().clone()).collect();

    // Run the network:
    loop {
        //     // If a node is expecting input, take it from the queue. Otherwise handle a message.
        //     let input_ids: Vec<_> = network
        //         .nodes
        //         .iter()
        //         .filter(|(_, node)| {
        //             node_busy(*node)
        //                 && !node.instance().has_input()
        //                 && node.instance().netinfo().is_validator()
        //                 // If there's only one node, it will immediately output on input. Make sure we
        //                 // first process all incoming messages before providing input again.
        //                 && (network.nodes.len() > 2 || node.queue.is_empty())
        //         })
        //         .map(|(id, _)| *id)
        //         .collect();

        let (node_id, step) = net.crank()
            .expect("network queue emptied unexpectedly")
            .expect("node failed to process step");

        // Examine potential algorithm output.
        if !step.output.is_empty() {
            println!("Non-empty step: {:?}", step);
        }
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
                net[node_id]
                    .algorithm_mut()
                    .input(Input::Change(Change::Add(NEW_OBSERVER_NODE_ID, pk)));
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
        }
        // batch.change();

        // for (cid, contrib) in step.output.iter().flat_map(|output| output.contributions.iter()) {
        //     for contrib in output.contributions {

        //     }
        // }

        // if ! step.outputs.is_empty() {
        //     // A: contains Remove  -> remove from outstanding removes
        //     // B: contains Add     -> remove from outstanding add

        // }

        // provide new input iff
        //
        // * N not in AwaitingRemove
        // * N not in AwaitingAdd

        // note: hide output of faulty nodes?

        // on A empty -> ...
        // on B empty -> ...
    }

    // // Handle messages in random order until all nodes have output all transactions.
    // while network.nodes.values().any(node_busy) {
    //     if let Some(id) = rng.choose(&input_ids) {
    //         let queue = queues.get_mut(id).unwrap();
    //         queue.remove_all(network.nodes[id].outputs().iter().flat_map(Batch::iter));
    //         network.input(*id, Input::User(queue.choose(3, 10)));
    //     }
    //     network.step();
    //     // Once all nodes have processed the removal of node 0, add it again.
    //     if !input_add && network.nodes.values().all(has_remove) {
    //         let pk = network.nodes[&NodeUid(0)]
    //             .instance()
    //             .netinfo()
    //             .secret_key()
    //             .public_key();
    //         network.input_all(Input::Change(Change::Add(NodeUid(0), pk)));
    //         input_add = true;
    //     }
    // }
    // verify_output_sequence(&network);
}
