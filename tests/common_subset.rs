//! Integration tests of the Asynchronous Common Subset protocol.

extern crate env_logger;
extern crate hbbft;
#[macro_use]
extern crate log;
extern crate rand;

mod network;

use std::collections::{BTreeMap, BTreeSet};

use hbbft::common_subset::CommonSubset;
use hbbft::messaging::DistAlgorithm;

use network::{Adversary, MessageScheduler, NodeUid, SilentAdversary, TestNetwork};

type ProposedValue = Vec<u8>;

fn test_common_subset<A: Adversary<CommonSubset<NodeUid>>>(
    mut network: TestNetwork<A, CommonSubset<NodeUid>>,
    inputs: &BTreeMap<NodeUid, ProposedValue>,
) {
    let ids: Vec<NodeUid> = network.nodes.keys().cloned().collect();
    let mut decided_nodes: BTreeSet<NodeUid> = BTreeSet::new();

    for id in ids {
        if let Some(value) = inputs.get(&id) {
            network.input(id, value.to_owned());
        }
    }

    // Terminate when all good nodes do.
    while network
        .nodes
        .values()
        .any(|node| network.adv_nodes.contains(&node.algo.our_id()) || node.algo.terminated())
    {
        let id = network.step();
        if let Some(output) = network.nodes[&id].outputs().iter().next() {
            assert_eq!(inputs, output);
            debug!("Node {:?} decided: {:?}", id, output);

            // Test uniqueness of output of the good nodes.
            if !network.adv_nodes.contains(&id) {
                assert!(!decided_nodes.insert(id));
            }
        }
    }
}

fn new_network<A: Adversary<CommonSubset<NodeUid>>>(
    good_num: usize,
    bad_num: usize,
    adversary: A,
) -> TestNetwork<A, CommonSubset<NodeUid>> {
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let new_common_subset = |id, all_ids: BTreeSet<_>| {
        CommonSubset::new(id, &all_ids).expect("new Common Subset instance")
    };
    TestNetwork::new(good_num, bad_num, adversary, new_common_subset)
}

#[test]
fn test_common_subset_3_out_of_4_nodes_propose() {
    let proposed_value = Vec::from("Fake news");
    let proposing_ids: BTreeSet<NodeUid> = (0..3).map(NodeUid).collect();
    let proposals: BTreeMap<NodeUid, ProposedValue> = proposing_ids
        .iter()
        .map(|id| (*id, proposed_value.clone()))
        .collect();
    let adversary = SilentAdversary::new(MessageScheduler::First);
    let network = new_network(3, 1, adversary);
    test_common_subset(network, &proposals);
}

#[test]
fn test_common_subset_5_nodes_different_proposed_values() {
    let proposed_values = vec![
        Vec::from("Alpha"),
        Vec::from("Bravo"),
        Vec::from("Charlie"),
        Vec::from("Delta"),
        Vec::from("Echo"),
    ];
    let proposals: BTreeMap<NodeUid, ProposedValue> = (0..5)
        .into_iter()
        .map(NodeUid)
        .zip(proposed_values)
        .collect();
    let adversary = SilentAdversary::new(MessageScheduler::Random);
    let network = new_network(5, 0, adversary);
    test_common_subset(network, &proposals);
}
