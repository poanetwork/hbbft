#![deny(unused_must_use)]
pub mod net;

use std::collections::{BTreeMap, BTreeSet};
use std::iter::once;
use std::sync::Arc;

use proptest::{prelude::ProptestConfig, proptest, proptest_helper};
use rand::SeedableRng;

use hbbft::subset::{Subset, SubsetOutput};
use hbbft::ConsensusProtocol;

use crate::net::adversary::{Adversary, NodeOrderAdversary, ReorderingAdversary};
use crate::net::proptest::{gen_seed, TestRng, TestRngSeed};
use crate::net::{NetBuilder, NewNodeInfo, VirtualNet};

type NodeId = u16;
type ProposedValue = Vec<u8>;

fn test_subset<A>(
    mut net: VirtualNet<Subset<NodeId, u8>, A>,
    inputs: &BTreeMap<NodeId, ProposedValue>,
    mut rng: &mut TestRng,
) where
    A: Adversary<Subset<NodeId, u8>>,
{
    let ids: Vec<NodeId> = net.nodes().map(|node| *node.id()).collect();

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

        assert_eq!(
            outputs.iter().cloned().collect::<BTreeSet<_>>(),
            expected_value
        );
    }
}

fn new_network<A, F>(
    good_num: usize,
    bad_num: usize,
    mut rng: &mut TestRng,
    adversary: F,
) -> VirtualNet<Subset<NodeId, u8>, A>
where
    A: Adversary<Subset<NodeId, u8>>,
    F: Fn() -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

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

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1, .. ProptestConfig::default()
    })]

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_subset_3_out_of_4_nodes_propose(seed in gen_seed()) {
        do_test_subset_3_out_of_4_nodes_propose(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_subset_5_nodes_different_proposed_values(seed in gen_seed()) {
        do_test_subset_5_nodes_different_proposed_values(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_subset_1_node(seed in gen_seed()) {
        do_test_subset_1_node(seed)
    }
}

fn do_test_subset_3_out_of_4_nodes_propose(seed: TestRngSeed) {
    let proposed_value = Vec::from("Fake news");
    let proposing_ids: BTreeSet<NodeId> = (0..3).collect();
    let proposals: BTreeMap<NodeId, ProposedValue> = proposing_ids
        .iter()
        .map(|id| (*id, proposed_value.clone()))
        .collect();
    let mut rng: TestRng = TestRng::from_seed(seed);
    let net = new_network(3, 1, &mut rng, NodeOrderAdversary::new);
    test_subset(net, &proposals, &mut rng);
}

fn do_test_subset_5_nodes_different_proposed_values(seed: TestRngSeed) {
    let proposed_values = vec![
        Vec::from("Alpha"),
        Vec::from("Bravo"),
        Vec::from("Charlie"),
        Vec::from("Delta"),
        Vec::from("Echo"),
    ];
    let proposals: BTreeMap<NodeId, ProposedValue> = (0..5).zip(proposed_values).collect();
    let mut rng: TestRng = TestRng::from_seed(seed);
    let net = new_network(5, 0, &mut rng, ReorderingAdversary::new);
    test_subset(net, &proposals, &mut rng);
}

fn do_test_subset_1_node(seed: TestRngSeed) {
    let proposals: BTreeMap<NodeId, ProposedValue> =
        once((0, Vec::from("Node 0 is the greatest!"))).collect();
    let mut rng: TestRng = TestRng::from_seed(seed);
    let net = new_network(1, 0, &mut rng, ReorderingAdversary::new);
    test_subset(net, &proposals, &mut rng);
}
