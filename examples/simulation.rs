extern crate colored;
extern crate docopt;
extern crate hbbft;
extern crate itertools;
extern crate rand;
#[macro_use(Deserialize)]
extern crate serde_derive;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::{cmp, u64};

use colored::*;
use docopt::Docopt;
use itertools::Itertools;
use rand::Rng;

use hbbft::honey_badger::{self, Batch, HoneyBadger};
use hbbft::messaging::{DistAlgorithm, Target, TargetedMessage};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USAGE: &str = "
Benchmark example

Usage:
  benchmark [options]
  benchmark (--help | -h )
  benchmark --version

Options:
  -h, --help             Show this message.
  --version              Show the version of hbbft.
  -n <n>, --nodes <n>    The total number of nodes [default: 10]
  -f <f>, --faulty <f>   The number of faulty nodes [default: 0]
  -t <txs>, --txs <txs>  The number of transactions to process [default: 1000]
  -b <b>, --batch <b>    The batch size, i.e. txs per epoch [default: 100]
  -l <lag>, --lag <lag>  The network lag between sending and receiving [default: 100]
";

#[derive(Deserialize)]
struct Args {
    flag_n: usize,
    flag_f: usize,
    flag_txs: usize,
    flag_b: usize,
    flag_lag: u64,
}

/// A node identifier. In the simulation, nodes are simply numbered.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Clone, Copy)]
pub struct NodeUid(pub usize);

/// A message with a sender and the timestamp of arrival.
#[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
struct TimestampedMessage<D: DistAlgorithm> {
    time: u64,
    sender_id: D::NodeUid,
    message: D::Message,
}

impl<D: DistAlgorithm> Clone for TimestampedMessage<D>
where
    D::Message: Clone,
{
    fn clone(&self) -> Self {
        TimestampedMessage {
            time: self.time,
            sender_id: self.sender_id.clone(),
            message: self.message.clone(),
        }
    }
}

/// A "node" running an instance of the algorithm `D`.
pub struct TestNode<D: DistAlgorithm> {
    /// This node's own ID.
    id: D::NodeUid,
    /// The instance of the broadcast algorithm.
    algo: D,
    /// The number of (virtual) milliseconds for which this node has already been simulated.
    time: u64,
    /// Incoming messages from other nodes that this node has not yet handled, with timestamps.
    queue: VecDeque<TimestampedMessage<D>>,
    /// The values this node has output so far, with timestamps.
    outputs: Vec<(u64, D::Output)>,
    /// The number of messages this node has handled so far.
    message_count: usize,
}

impl<D: DistAlgorithm> TestNode<D> {
    /// Creates a new test node with the given broadcast instance.
    fn new(mut algo: D) -> TestNode<D> {
        let outputs = algo.output_iter().map(|out| (0, out)).collect();
        TestNode {
            id: algo.our_id().clone(),
            algo,
            time: 0,
            queue: VecDeque::new(),
            outputs,
            message_count: 0,
        }
    }

    /// Handles the first message in the node's queue.
    fn handle_message(&mut self) {
        let ts_msg = self.queue.pop_front().expect("message not found");
        self.time = cmp::max(self.time, ts_msg.time);
        self.message_count += 1;
        self.algo
            .handle_message(&ts_msg.sender_id, ts_msg.message)
            .expect("handling message");
        let time = self.time;
        self.outputs
            .extend(self.algo.output_iter().map(|out| (time, out)));
    }

    /// Returns the time when the next message can be handled.
    fn next_event_time(&self) -> Option<u64> {
        match self.queue.front() {
            None => None,
            Some(ts_msg) => Some(cmp::max(ts_msg.time, self.time)),
        }
    }

    /// Returns the number of messages this node has handled so far.
    fn message_count(&self) -> usize {
        self.message_count
    }
}

/// A collection of `TestNode`s representing a network.
pub struct TestNetwork<D: DistAlgorithm> {
    nodes: BTreeMap<D::NodeUid, TestNode<D>>,
    /// The delay between a message being sent and received.
    net_lag: u64,
}

impl<D: DistAlgorithm<NodeUid = NodeUid>> TestNetwork<D>
where
    D::Message: Clone,
{
    /// Creates a new network with `good_num` good nodes, and `dead_num` dead nodes.
    pub fn new<F>(good_num: usize, dead_num: usize, new_algo: F, net_lag: u64) -> TestNetwork<D>
    where
        F: Fn(NodeUid, BTreeSet<NodeUid>) -> D,
    {
        let node_ids: BTreeSet<NodeUid> = (0..(good_num + dead_num)).map(NodeUid).collect();
        let new_node_by_id = |id: NodeUid| (id, TestNode::new(new_algo(id, node_ids.clone())));
        let mut network = TestNetwork {
            nodes: (0..good_num).map(NodeUid).map(new_node_by_id).collect(),
            net_lag,
        };
        let mut initial_msgs: Vec<(D::NodeUid, u64, Vec<_>)> = Vec::new();
        for (id, node) in &mut network.nodes {
            initial_msgs.push((*id, node.time, node.algo.message_iter().collect()));
        }
        for (id, time, ts_msgs) in initial_msgs {
            network.dispatch_messages(id, time, ts_msgs);
        }
        network
    }

    /// Pushes the messages into the queues of the corresponding recipients.
    fn dispatch_messages<Q>(&mut self, sender_id: NodeUid, time: u64, msgs: Q)
    where
        Q: IntoIterator<Item = TargetedMessage<D::Message, NodeUid>> + Debug,
    {
        for msg in msgs {
            let ts_msg = TimestampedMessage {
                sender_id,
                time: time + self.net_lag,
                message: msg.message,
            };
            match msg.target {
                Target::All => {
                    for node in self.nodes.values_mut() {
                        if node.id != sender_id {
                            node.queue.push_back(ts_msg.clone())
                        }
                    }
                }
                Target::Node(to_id) => {
                    if let Some(node) = self.nodes.get_mut(&to_id) {
                        node.queue.push_back(ts_msg);
                    }
                }
            }
        }
    }

    /// Handles a queued message in one of the nodes with the earliest timestamp.
    pub fn step(&mut self) -> NodeUid {
        let min_time = self
            .nodes
            .values()
            .filter_map(TestNode::next_event_time)
            .min()
            .expect("no more messages in queue");
        let min_ids: Vec<NodeUid> = self
            .nodes
            .iter()
            .filter(|(_, node)| node.next_event_time() == Some(min_time))
            .map(|(id, _)| *id)
            .collect();
        let next_id = *rand::thread_rng().choose(&min_ids).unwrap();
        let msgs: Vec<_> = {
            let node = self.nodes.get_mut(&next_id).unwrap();
            node.handle_message();
            node.algo.message_iter().collect()
        };
        self.dispatch_messages(next_id, min_time, msgs);
        next_id
    }

    /// Returns the number of messages that have been handled so far.
    pub fn message_count(&self) -> usize {
        self.nodes.values().map(TestNode::message_count).sum()
    }
}

/// The timestamped batches for a particular epoch that have already been output.
#[derive(Clone, Default)]
struct EpochInfo {
    nodes: BTreeMap<NodeUid, (u64, Batch<usize>)>,
}

impl EpochInfo {
    /// Adds a batch to this epoch. Prints information if the epoch is complete.
    fn add(&mut self, id: NodeUid, time: u64, batch: &Batch<usize>, node_num: usize, msgs: usize) {
        if self.nodes.contains_key(&id) {
            return;
        }
        self.nodes.insert(id, (time, batch.clone()));
        if self.nodes.len() < node_num {
            return;
        }
        // TODO: Once bandwidth, CPU time and/or randomized lag are simulated, `min_t` and `max_t`
        // will probably differ. Print both.
        let (_min_t, max_t) = self
            .nodes
            .values()
            .map(|&(time, _)| time)
            .minmax()
            .into_option()
            .unwrap();
        let txs = batch.transactions.len();
        println!(
            "{:>5} {:6} {:5} {:7}",
            batch.epoch.to_string().cyan(),
            max_t,
            txs,
            msgs,
        );
    }
}

/// Proposes `num_txs` values and expects nodes to output and order them.
fn simulate_honey_badger(mut network: TestNetwork<HoneyBadger<usize, NodeUid>>, num_txs: usize) {
    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &mut TestNode<HoneyBadger<usize, NodeUid>>| {
        let mut min_missing = 0;
        for &(_, ref batch) in &node.outputs {
            for tx in &batch.transactions {
                if *tx >= min_missing {
                    min_missing = tx + 1;
                }
            }
        }
        if min_missing < num_txs {
            return true;
        }
        if node.outputs.last().unwrap().1.transactions.is_empty() {
            let last = node.outputs.last().unwrap().1.epoch;
            node.queue.retain(|ts_msg| match ts_msg.message {
                honey_badger::Message::CommonSubset(e, _) => e < last,
            });
        }
        false
    };

    // Handle messages until all nodes have output all transactions.
    println!("{}", "Epoch   Time   Txs    Msgs".bold());
    let mut epochs = Vec::new();
    while network.nodes.values_mut().any(node_busy) {
        let id = network.step();
        for &(time, ref batch) in &network.nodes[&id].outputs {
            if epochs.len() <= batch.epoch as usize {
                epochs.resize(batch.epoch as usize + 1, EpochInfo::default());
            }
            let msg_count = network.message_count();
            epochs[batch.epoch as usize].add(id, time, batch, network.nodes.len(), msg_count);
        }
    }
}

/// Parses the command line arguments.
fn parse_args() -> Result<Args, docopt::Error> {
    Docopt::new(USAGE)?
        .version(Some(VERSION.to_string()))
        .parse()?
        .deserialize()
}

fn main() {
    let args = parse_args().unwrap_or_else(|e| e.exit());
    if args.flag_n <= 3 * args.flag_f {
        let msg = "Honey Badger only works if less than one third of the nodes are faulty.";
        println!("{}", msg.red().bold());
    }
    println!("Simulating Honey Badger with:");
    println!("{} nodes, {} faulty", args.flag_n, args.flag_f);
    println!(
        "{} transactions, ≤{} per epoch",
        args.flag_txs, args.flag_b
    );
    println!("Network lag: {}", args.flag_lag);
    println!();
    let num_good_nodes = args.flag_n - args.flag_f;
    let new_honey_badger = |id: NodeUid, all_ids: BTreeSet<NodeUid>| {
        HoneyBadger::new(id, all_ids, args.flag_b, 0..args.flag_txs)
            .expect("Instantiate honey_badger")
    };
    let network = TestNetwork::new(num_good_nodes, args.flag_f, new_honey_badger, args.flag_lag);
    simulate_honey_badger(network, args.flag_txs);
}
