#![deny(unused_must_use)]
pub mod net;

use std::collections::{BTreeMap, BTreeSet};
use std::iter::once;
use std::sync::Arc;

use hbbft::subset::{Subset, SubsetOutput};
use hbbft::ConsensusProtocol;

use crate::net::adversary::{Adversary, NodeOrderAdversary, ReorderingAdversary};
use crate::net::{NetBuilder, NewNodeInfo, VirtualNet};

type NodeId = u16;
type ProposedValue = Vec<u8>;

fn test_subset<A>(
    mut net: VirtualNet<Subset<NodeId, u8>, A>,
    inputs: &BTreeMap<NodeId, ProposedValue>,
) where
    A: Adversary<Subset<NodeId, u8>>,
{
    let ids: Vec<NodeId> = net.nodes().map(|node| *node.id()).collect();

    let mut rng = rand::thread_rng();

    for id in ids {
        if let Some(value) = inputs.get(&id) {
            let _ = net.send_input(id, value.to_owned(), &mut rng);
        }
    }

    // Handle messages until all good nodes have terminated.
    while !net.nodes().all(|node| node.algorithm().terminated()) {
        let _ = net.crank_expect(&mut rng);
    }

    // Get reference value from the first correct node.
    // TODO: Revisit when observers are available in the new net simulator
    //       or drop this TODO if we decide to abandon that concept.
    let expected_value: BTreeSet<_> = net
        .correct_nodes()
        .nth(0)
        .unwrap()
        .outputs()
        .iter()
        .cloned()
        .collect();

    // Verify that all correct nodes output the same value.
    for node in net.correct_nodes() {
        let outputs = node.outputs();
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

        assert_eq!(outputs.iter().cloned().collect::<BTreeSet<_>>(), expected_value);
    }
}

fn new_network<A, F>(
    good_num: usize,
    bad_num: usize,
    adversary: F,
) -> VirtualNet<Subset<NodeId, u8>, A>
where
    A: Adversary<Subset<NodeId, u8>>,
    F: Fn() -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng = rand::thread_rng();

    let size = good_num + bad_num;

    let (net, _) = NetBuilder::new(0..size as u16)
        .num_faulty(bad_num as usize)
        .message_limit(10_000 * size as usize)
        .no_time_limit()
        .adversary(adversary())
        .using(move |node_info: NewNodeInfo<_>| {
            Subset::new(Arc::new(node_info.netinfo), 0).expect("new Subset instance")
        })
        .build(&mut rng)
        .expect("Could not construct test network.");
    net
}

#[test]
fn test_subset_3_out_of_4_nodes_propose() {
    let proposed_value = Vec::from("Fake news");
    let proposing_ids: BTreeSet<NodeId> = (0..3).collect();
    let proposals: BTreeMap<NodeId, ProposedValue> = proposing_ids
        .iter()
        .map(|id| (*id, proposed_value.clone()))
        .collect();
    let net = new_network(3, 1, NodeOrderAdversary::new);
    test_subset(net, &proposals);
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
    let proposals: BTreeMap<NodeId, ProposedValue> =
        (0..5).zip(proposed_values).collect();
    let net = new_network(5, 0, ReorderingAdversary::new);
    test_subset(net, &proposals);
}

#[test]
fn test_subset_1_node() {
    let proposals: BTreeMap<NodeId, ProposedValue> =
        once((0, Vec::from("Node 0 is the greatest!"))).collect();
    let net = new_network(1, 0, ReorderingAdversary::new);
    test_subset(net, &proposals);
}
