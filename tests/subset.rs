#![deny(unused_must_use)]
//! Integration tests of the Subset protocol.

extern crate env_logger;
extern crate hbbft;
#[macro_use]
extern crate log;
extern crate pairing;
extern crate rand;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate rand_derive;
extern crate threshold_crypto as crypto;

mod network;

use std::collections::{BTreeMap, BTreeSet};
use std::iter::once;
use std::sync::Arc;

use hbbft::messaging::NetworkInfo;
use hbbft::subset::{Subset, SubsetOutput};

use network::{Adversary, MessageScheduler, NodeId, SilentAdversary, TestNetwork, TestNode};

type ProposedValue = Vec<u8>;

fn test_subset<A: Adversary<Subset<NodeId>>>(
    mut network: TestNetwork<A, Subset<NodeId>>,
    inputs: &BTreeMap<NodeId, ProposedValue>,
) {
    let ids: Vec<NodeId> = network.nodes.keys().cloned().collect();

    for id in ids {
        if let Some(value) = inputs.get(&id) {
            network.input(id, value.to_owned());
        }
    }

    // Terminate when all good nodes do.
    while !network.nodes.values().all(TestNode::terminated) {
        network.step();
    }

    // Verify that all instances output the same set.
    let observer: BTreeSet<_> = network.observer.outputs().iter().cloned().collect();
    for node in network.nodes.values() {
        let mut outputs = node.outputs();
        let mut actual = BTreeMap::default();

        let mut has_seen_done = false;
        for i in outputs {
            assert!(!has_seen_done);
            match i {
                SubsetOutput::Contribution(k, v) => {
                    assert!(actual.insert(k, v).is_none());
                }
                SubsetOutput::Done => has_seen_done = true,
            }
        }
        assert_eq!(outputs.len(), actual.len() + 1);

        // The Subset algorithm guarantees that more than two thirds of the proposed elements
        // are in the set.
        assert!(actual.len() * 3 > inputs.len() * 2);
        for (id, value) in actual {
            assert_eq!(&inputs[id], value);
        }

        assert_eq!(outputs.iter().cloned().collect::<BTreeSet<_>>(), observer);
    }
}

fn new_network<A, F>(
    good_num: usize,
    bad_num: usize,
    adversary: F,
) -> TestNetwork<A, Subset<NodeId>>
where
    A: Adversary<Subset<NodeId>>,
    F: Fn(BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>) -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let new_subset =
        |netinfo: Arc<NetworkInfo<NodeId>>| Subset::new(netinfo, 0).expect("new Subset instance");
    TestNetwork::new(good_num, bad_num, adversary, new_subset)
}

#[test]
fn test_subset_3_out_of_4_nodes_propose() {
    let proposed_value = Vec::from("Fake news");
    let proposing_ids: BTreeSet<NodeId> = (0..3).map(NodeId).collect();
    let proposals: BTreeMap<NodeId, ProposedValue> = proposing_ids
        .iter()
        .map(|id| (*id, proposed_value.clone()))
        .collect();
    let adversary = |_| SilentAdversary::new(MessageScheduler::First);
    let network = new_network(3, 1, adversary);
    test_subset(network, &proposals);
}

#[test]
fn test_subset_5_nodes_different_proposed_values() {
    let proposed_values = vec![
        Vec::from("Alpha"),
        Vec::from("Bravo"),
        Vec::from("Charlie"),
        Vec::from("Delta"),
        Vec::from("Echo"),
    ];
    let proposals: BTreeMap<NodeId, ProposedValue> = (0..5)
        .into_iter()
        .map(NodeId)
        .zip(proposed_values)
        .collect();
    let adversary = |_| SilentAdversary::new(MessageScheduler::Random);
    let network = new_network(5, 0, adversary);
    test_subset(network, &proposals);
}

#[test]
fn test_subset_1_node() {
    let proposals: BTreeMap<NodeId, ProposedValue> =
        once((NodeId(0), Vec::from("Node 0 is the greatest!"))).collect();
    let adversary = |_| SilentAdversary::new(MessageScheduler::Random);
    let network = new_network(1, 0, adversary);
    test_subset(network, &proposals);
}
