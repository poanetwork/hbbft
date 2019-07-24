#![deny(unused_must_use)]
//! Network tests for Honey Badger.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hbbft::honey_badger::{Batch, EncryptionSchedule, HoneyBadger, MessageContent};
use hbbft::sender_queue::{self, SenderQueue, Step};
use hbbft::transaction_queue::TransactionQueue;
use hbbft::{threshold_decrypt, util, CpStep, NetworkInfo, Target};
use hbbft_testing::adversary::{
    sort_by_random_node, Adversary, NetMutHandle, NodeOrderAdversary, RandomAdversary,
    ReorderingAdversary,
};
use hbbft_testing::proptest::{gen_seed, TestRng, TestRngSeed};
use hbbft_testing::{CrankError, NetBuilder, NetMessage, NewNodeInfo, Node, VirtualNet};
use itertools::Itertools;
use log::info;
use proptest::{prelude::ProptestConfig, proptest};
use rand::{seq::SliceRandom, Rng, SeedableRng};

type NodeId = u16;
type NetworkInfoMap = BTreeMap<NodeId, Arc<NetworkInfo<NodeId>>>;
type UsizeHoneyBadger = SenderQueue<HoneyBadger<Vec<usize>, NodeId>>;
type HoneyBadgerMessage = NetMessage<UsizeHoneyBadger>;

/// An adversary whose nodes only send messages with incorrect decryption shares.
#[derive(Clone, Debug, Default)]
pub struct FaultyShareAdversary {
    share_triggers: BTreeMap<u64, bool>,
    // TODO this is really hacky but there's no better way to get this value
    // Solution taken from binary_agreement_mitm test - ideally the new network simulator
    // should be altered to store the netinfo structure alongside nodes similar to
    // the way the old network simulator did it.
    netinfo_mutex: Arc<Mutex<NetworkInfoMap>>,
}

impl FaultyShareAdversary {
    /// Creates a new adversary with the necessary network info instances
    pub fn new(netinfo_mutex: Arc<Mutex<NetworkInfoMap>>) -> Self {
        FaultyShareAdversary {
            share_triggers: BTreeMap::new(),
            netinfo_mutex,
        }
    }
}

impl Adversary<UsizeHoneyBadger> for FaultyShareAdversary {
    #[inline]
    fn pre_crank<R: Rng>(
        &mut self,
        mut net: NetMutHandle<'_, UsizeHoneyBadger, Self>,
        rng: &mut R,
    ) {
        sort_by_random_node(&mut net, rng);
    }

    #[inline]
    fn tamper<R: Rng>(
        &mut self,
        mut net: NetMutHandle<'_, UsizeHoneyBadger, Self>,
        msg: HoneyBadgerMessage,
        rng: &mut R,
    ) -> Result<CpStep<UsizeHoneyBadger>, CrankError<UsizeHoneyBadger>> {
        if let sender_queue::Message::Algo(hb_msg) = msg.payload() {
            let epoch = hb_msg.epoch();
            // Set the trigger to simulate decryption share messages
            // if epoch has not been encountered yet.
            self.share_triggers.entry(epoch).or_insert(true);
        }

        let mut step = net.dispatch_message(msg, rng)?;

        let fake_proposal = &Vec::from("X marks the spot");
        // For each untriggered epoch, send fake shares
        for (epoch, trigger_set) in &mut self.share_triggers {
            if *trigger_set {
                // Unset the trigger.
                *trigger_set = false;

                // Get node id vectors up-front to avoid borrow issues
                let faulty_node_ids: Vec<NodeId> =
                    net.faulty_nodes_mut().map(|node| *node.id()).collect();
                let all_node_ids: Vec<NodeId> = net.nodes_mut().map(|node| node.id()).collect();

                // Broadcast fake decryption shares from all adversarial nodes.
                for faulty_node_id in faulty_node_ids {
                    // get the adversarial's net info
                    let netinfo = self
                        .netinfo_mutex
                        .lock()
                        .unwrap()
                        .get(&faulty_node_id)
                        .cloned()
                        .expect("Adversary netinfo mutex not populated");

                    // encrypt false share
                    let fake_ciphertext = (*netinfo)
                        .public_key_set()
                        .public_key()
                        .encrypt(fake_proposal);
                    let share = netinfo
                        .secret_key_share()
                        .expect("missing adversary key share")
                        .decrypt_share(&fake_ciphertext)
                        .expect("decryption share");

                    // Send the share to remote nodes.
                    for proposer_id in &all_node_ids {
                        step.messages.push(
                            Target::All.message(sender_queue::Message::Algo(
                                MessageContent::DecryptionShare {
                                    proposer_id: *proposer_id,
                                    share: threshold_decrypt::Message(share.clone()),
                                }
                                .with_epoch(*epoch),
                            )),
                        );
                    }
                }
            }
        }

        Ok(step)
    }
}

/// Proposes `num_txs` values and expects nodes to output and order them.
fn test_honey_badger<A>(
    mut net: VirtualNet<UsizeHoneyBadger, A>,
    num_txs: usize,
    mut rng: &mut TestRng,
) where
    A: Adversary<UsizeHoneyBadger>,
{
    let mut queues: BTreeMap<_, _> = net
        .correct_nodes()
        .map(|node| (*node.id(), (0..num_txs).collect::<Vec<usize>>()))
        .collect();

    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &Node<UsizeHoneyBadger>| {
        node.outputs().iter().flat_map(Batch::iter).unique().count() < num_txs
    };

    // Handle messages in random order until all nodes have output all transactions.
    while net.correct_nodes().any(node_busy) {
        // If a node is expecting input, take it from the queue. Otherwise handle a message.
        let input_ids: Vec<_> = net
            .correct_nodes()
            .filter(|node| !node.algorithm().algo().has_input())
            .map(|node| *node.id())
            .collect();

        if let Some(id) = input_ids[..].choose(&mut rng) {
            let queue = queues.get_mut(id).unwrap();
            queue.remove_multiple(net.get(*id).unwrap().outputs().iter().flat_map(Batch::iter));
            let _ = net.send_input(*id, queue.choose(&mut rng, 3, 10), &mut rng);
        } else {
            let _ = net.crank_expect(&mut rng);
        }
    }
    verify_output_sequence(&net);
}

/// Verifies that all instances output the same sequence of batches.
fn verify_output_sequence<A>(network: &VirtualNet<UsizeHoneyBadger, A>)
where
    A: Adversary<UsizeHoneyBadger>,
{
    let mut expected: Option<BTreeMap<u64, &_>> = None;
    for node in network.correct_nodes() {
        assert!(!node.outputs().is_empty());
        let outputs: BTreeMap<u64, &BTreeMap<NodeId, Vec<usize>>> = node
            .outputs()
            .iter()
            .map(|batch| (batch.epoch, &batch.contributions))
            .collect();
        if expected.is_none() {
            expected = Some(outputs);
        } else if let Some(expected) = &expected {
            assert_eq!(expected, &outputs);
        }
    }
}

fn new_honey_badger(
    netinfo: Arc<NetworkInfo<NodeId>>,
) -> (UsizeHoneyBadger, Step<HoneyBadger<Vec<usize>, NodeId>>) {
    let nc = netinfo.clone();
    let peer_ids = nc.other_ids().cloned();
    let hb = HoneyBadger::builder(netinfo)
        .encryption_schedule(EncryptionSchedule::EveryNthEpoch(2))
        .build();
    let our_id = *nc.our_id();
    SenderQueue::builder(hb, peer_ids).build(our_id)
}

fn test_honey_badger_different_sizes<A, F>(
    new_adversary: F,
    num_txs: usize,
    seed: TestRngSeed,
    adversary_netinfo: &Arc<Mutex<NetworkInfoMap>>,
) where
    A: Adversary<UsizeHoneyBadger>,
    F: Fn() -> A,
{
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    let mut rng: TestRng = TestRng::from_seed(seed);
    let sizes = vec![1, 2, 3, 5, rng.gen_range(6, 10)];
    for size in sizes {
        // cloning since it gets moved into a closure
        let cloned_netinfo_map = adversary_netinfo.clone();

        let num_adv_nodes = util::max_faulty(size);
        let num_good_nodes = size - num_adv_nodes;
        info!(
            "Network size: {} good nodes, {} faulty nodes",
            num_good_nodes, num_adv_nodes
        );

        let (net, _) = NetBuilder::new(0..size as u16)
            .num_faulty(num_adv_nodes as usize)
            .message_limit(10_000 * size as usize)
            .no_time_limit()
            .adversary(new_adversary())
            .using_step(move |info: NewNodeInfo<_>| {
                let netinfo = Arc::new(info.netinfo);
                cloned_netinfo_map
                    .lock()
                    .unwrap()
                    .insert(info.id, netinfo.clone());
                new_honey_badger(netinfo)
            })
            .build(&mut rng)
            .expect("Could not construct test network.");

        test_honey_badger(net, num_txs, &mut rng);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1, .. ProptestConfig::default()
    })]

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_honey_badger_random_delivery_silent(seed in gen_seed()) {
        do_test_honey_badger_random_delivery_silent(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_honey_badger_first_delivery_silent(seed in gen_seed()) {
        do_test_honey_badger_first_delivery_silent(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_honey_badger_faulty_share(seed in gen_seed()) {
        do_test_honey_badger_faulty_share(seed)
    }

    #[test]
    #[allow(clippy::unnecessary_operation)]
    fn test_honey_badger_random_adversary(seed in gen_seed()) {
        do_test_honey_badger_random_adversary(seed)
    }
}

fn do_test_honey_badger_random_delivery_silent(seed: TestRngSeed) {
    test_honey_badger_different_sizes(ReorderingAdversary::new, 30, seed, &Default::default());
}

fn do_test_honey_badger_first_delivery_silent(seed: TestRngSeed) {
    test_honey_badger_different_sizes(NodeOrderAdversary::new, 30, seed, &Default::default());
}

fn do_test_honey_badger_faulty_share(seed: TestRngSeed) {
    let adversary_netinfo: Arc<Mutex<NetworkInfoMap>> = Default::default();
    let new_adversary = || FaultyShareAdversary::new(adversary_netinfo.clone());
    test_honey_badger_different_sizes(new_adversary, 8, seed, &adversary_netinfo);
}

fn do_test_honey_badger_random_adversary(seed: TestRngSeed) {
    let new_adversary = || {
        // A 10% injection chance is roughly ~13k extra messages added.
        RandomAdversary::new(0.1, 0.1)
    };
    test_honey_badger_different_sizes(new_adversary, 8, seed, &Default::default());
}
