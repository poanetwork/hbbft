extern crate bincode;
extern crate colored;
extern crate docopt;
extern crate env_logger;
extern crate hbbft;
extern crate itertools;
extern crate pairing;
extern crate rand;
extern crate serde;
#[macro_use(Deserialize, Serialize)]
extern crate serde_derive;
extern crate signifix;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use std::time::{Duration, Instant};
use std::{cmp, u64};

use colored::*;
use docopt::Docopt;
use itertools::Itertools;
use rand::Rng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use signifix::{metric, TryFrom};

use hbbft::crypto::SecretKeySet;
use hbbft::honey_badger::{Batch, HoneyBadger, HoneyBadgerBuilder};
use hbbft::messaging::{DistAlgorithm, NetworkInfo, Target};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USAGE: &str = "
Benchmark example

Usage:
  benchmark [options]
  benchmark (--help | -h )
  benchmark --version

Options:
  -h, --help              Show this message.
  --version               Show the version of hbbft.
  -n <n>, --nodes <n>     The total number of nodes [default: 10]
  -f <f>, --faulty <f>    The number of faulty nodes [default: 0]
  -t <txs>, --txs <txs>   The number of transactions to process [default: 1000]
  -b <b>, --batch <b>     The batch size, i.e. txs per epoch [default: 100]
  -l <lag>, --lag <lag>   The network lag between sending and receiving [default: 100]
  --bw <bw>               The bandwidth, in kbit/s [default: 2000]
  --cpu <cpu>             The CPU speed, in percent of this machine's [default: 100]
  --tx-size <size>        The size of a transaction, in bytes [default: 10]
";

#[derive(Deserialize)]
struct Args {
    flag_n: usize,
    flag_f: usize,
    flag_txs: usize,
    flag_b: usize,
    flag_lag: u64,
    flag_bw: u32,
    flag_cpu: f32,
    flag_tx_size: usize,
}

/// A node identifier. In the simulation, nodes are simply numbered.
#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Clone, Copy)]
pub struct NodeUid(pub usize);

/// A transaction.
#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd, Debug, Clone)]
pub struct Transaction(pub Vec<u8>);

impl Transaction {
    fn new(len: usize) -> Transaction {
        Transaction(rand::thread_rng().gen_iter().take(len).collect())
    }
}

/// A serialized message with a sender and the timestamp of arrival.
#[derive(Eq, PartialEq, Debug)]
struct TimestampedMessage<D: DistAlgorithm> {
    time: Duration,
    sender_id: D::NodeUid,
    target: Target<D::NodeUid>,
    message: Vec<u8>,
}

impl<D: DistAlgorithm> Clone for TimestampedMessage<D>
where
    D::Message: Clone,
{
    fn clone(&self) -> Self {
        TimestampedMessage {
            time: self.time,
            sender_id: self.sender_id.clone(),
            target: self.target.clone(),
            message: self.message.clone(),
        }
    }
}

/// Performance parameters of a node's hardware and Internet connection. For simplicity, only the
/// sender's lag and bandwidth are taken into account. (I.e. infinite downstream, limited
/// upstream.)
#[derive(Clone, Copy)]
pub struct HwQuality {
    /// The network latency. This is added once for every message.
    latency: Duration,
    /// The inverse bandwidth, in time per byte.
    inv_bw: Duration,
    /// The CPU time multiplier: how much slower, in percent, is this node than your computer?
    cpu_factor: u32,
}

/// A "node" running an instance of the algorithm `D`.
pub struct TestNode<D: DistAlgorithm> {
    /// This node's own ID.
    id: D::NodeUid,
    /// The instance of the broadcast algorithm.
    algo: D,
    /// The duration for which this node's CPU has already been simulated.
    time: Duration,
    /// The time when this node last sent data over the network.
    sent_time: Duration,
    /// Incoming messages from other nodes that this node has not yet handled, with timestamps.
    in_queue: VecDeque<TimestampedMessage<D>>,
    /// Outgoing messages to other nodes, with timestamps.
    out_queue: VecDeque<TimestampedMessage<D>>,
    /// The values this node has output so far, with timestamps.
    outputs: Vec<(Duration, D::Output)>,
    /// The number of messages this node has handled so far.
    message_count: usize,
    /// The total size of messages this node has handled so far, in bytes.
    message_size: u64,
    /// The hardware and network quality of this node.
    hw_quality: HwQuality,
}

impl<D: DistAlgorithm> TestNode<D>
where
    D::Message: Serialize + DeserializeOwned,
{
    /// Creates a new test node with the given broadcast instance.
    fn new(algo: D, hw_quality: HwQuality) -> TestNode<D> {
        let mut node = TestNode {
            id: algo.our_id().clone(),
            algo,
            time: Duration::default(),
            sent_time: Duration::default(),
            in_queue: VecDeque::new(),
            out_queue: VecDeque::new(),
            outputs: Vec::new(),
            message_count: 0,
            message_size: 0,
            hw_quality,
        };
        node.send_output_and_msgs();
        node
    }

    /// Handles the first message in the node's queue.
    fn handle_message(&mut self) {
        let ts_msg = self.in_queue.pop_front().expect("message not found");
        self.time = cmp::max(self.time, ts_msg.time);
        self.message_count += 1;
        self.message_size += ts_msg.message.len() as u64;
        let start = Instant::now();
        let msg = bincode::deserialize::<D::Message>(&ts_msg.message).expect("deserialize");
        self.algo
            .handle_message(&ts_msg.sender_id, msg)
            .expect("handling message");
        self.time += start.elapsed() * self.hw_quality.cpu_factor / 100;
        self.send_output_and_msgs()
    }

    /// Handles the algorithm's output and messages.
    fn send_output_and_msgs(&mut self) {
        let start = Instant::now();
        let out_msgs: Vec<_> = self
            .algo
            .message_iter()
            .map(|msg| {
                (
                    msg.target,
                    bincode::serialize(&msg.message).expect("serialize"),
                )
            })
            .collect();
        self.time += start.elapsed() * self.hw_quality.cpu_factor / 100;
        let time = self.time;
        self.outputs
            .extend(self.algo.output_iter().map(|out| (time, out)));
        self.sent_time = cmp::max(self.time, self.sent_time);
        for (target, message) in out_msgs {
            self.sent_time += self.hw_quality.inv_bw * message.len() as u32;
            self.out_queue.push_back(TimestampedMessage {
                time: self.sent_time + self.hw_quality.latency,
                sender_id: self.id.clone(),
                target,
                message,
            });
        }
    }

    /// Returns the time when the next message can be handled.
    fn next_event_time(&self) -> Option<Duration> {
        match self.in_queue.front() {
            None => None,
            Some(ts_msg) => Some(cmp::max(ts_msg.time, self.time)),
        }
    }

    /// Returns the number of messages this node has handled so far.
    fn message_count(&self) -> usize {
        self.message_count
    }

    /// Returns the size of messages this node has handled so far.
    fn message_size(&self) -> u64 {
        self.message_size
    }

    /// Adds a message into the incoming queue.
    fn add_message(&mut self, msg: TimestampedMessage<D>) {
        match self.in_queue.iter().position(|other| other.time > msg.time) {
            None => self.in_queue.push_back(msg),
            Some(i) => self.in_queue.insert(i, msg),
        }
    }
}

/// A collection of `TestNode`s representing a network.
pub struct TestNetwork<D: DistAlgorithm> {
    nodes: BTreeMap<D::NodeUid, TestNode<D>>,
}

impl<D: DistAlgorithm<NodeUid = NodeUid>> TestNetwork<D>
where
    D::Message: Serialize + DeserializeOwned + Clone,
{
    /// Creates a new network with `good_num` good nodes, and `dead_num` dead nodes.
    pub fn new<F>(
        good_num: usize,
        dead_num: usize,
        new_algo: F,
        hw_quality: HwQuality,
    ) -> TestNetwork<D>
    where
        F: Fn(NodeUid, BTreeSet<NodeUid>) -> D,
    {
        let node_ids: BTreeSet<NodeUid> = (0..(good_num + dead_num)).map(NodeUid).collect();
        let new_node_by_id = |id: NodeUid| {
            (
                id,
                TestNode::new(new_algo(id, node_ids.clone()), hw_quality),
            )
        };
        let mut network = TestNetwork {
            nodes: (0..good_num).map(NodeUid).map(new_node_by_id).collect(),
        };
        let initial_msgs: Vec<_> = network
            .nodes
            .values_mut()
            .flat_map(|node| node.out_queue.drain(..))
            .collect();
        network.dispatch_messages(initial_msgs);
        network
    }

    /// Pushes the messages into the queues of the corresponding recipients.
    fn dispatch_messages<Q>(&mut self, msgs: Q)
    where
        Q: IntoIterator<Item = TimestampedMessage<D>>,
    {
        for ts_msg in msgs {
            match ts_msg.target {
                Target::All => {
                    for node in self.nodes.values_mut() {
                        if node.id != ts_msg.sender_id {
                            node.add_message(ts_msg.clone())
                        }
                    }
                }
                Target::Node(to_id) => {
                    if let Some(node) = self.nodes.get_mut(&to_id) {
                        node.add_message(ts_msg);
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
            node.out_queue.drain(..).collect()
        };
        self.dispatch_messages(msgs);
        next_id
    }

    /// Returns the number of messages that have been handled so far.
    pub fn message_count(&self) -> usize {
        self.nodes.values().map(TestNode::message_count).sum()
    }

    /// Returns the total size of messages that have been handled so far.
    pub fn message_size(&self) -> u64 {
        self.nodes.values().map(TestNode::message_size).sum()
    }
}

/// The timestamped batches for a particular epoch that have already been output.
#[derive(Clone, Default)]
struct EpochInfo {
    nodes: BTreeMap<NodeUid, (Duration, Batch<Transaction, NodeUid>)>,
}

impl EpochInfo {
    /// Adds a batch to this epoch. Prints information if the epoch is complete.
    fn add(
        &mut self,
        id: NodeUid,
        time: Duration,
        batch: &Batch<Transaction, NodeUid>,
        network: &TestNetwork<HoneyBadger<Transaction, NodeUid>>,
    ) {
        if self.nodes.contains_key(&id) {
            return;
        }
        self.nodes.insert(id, (time, batch.clone()));
        if self.nodes.len() < network.nodes.len() {
            return;
        }
        let (min_t, max_t) = self
            .nodes
            .values()
            .map(|&(time, _)| time)
            .minmax()
            .into_option()
            .unwrap();
        let txs = batch.len();
        println!(
            "{:>5} {:6} {:6} {:5} {:9} {:>9}B",
            batch.epoch.to_string().cyan(),
            min_t.as_secs() * 1000 + max_t.subsec_nanos() as u64 / 1_000_000,
            max_t.as_secs() * 1000 + max_t.subsec_nanos() as u64 / 1_000_000,
            txs,
            network.message_count() / network.nodes.len(),
            metric::Signifix::try_from(network.message_size() / network.nodes.len() as u64)
                .unwrap(),
        );
    }
}

/// Proposes `num_txs` values and expects nodes to output and order them.
fn simulate_honey_badger(
    mut network: TestNetwork<HoneyBadger<Transaction, NodeUid>>,
    num_txs: usize,
) {
    // Returns `true` if the node has not output all transactions yet.
    // If it has, and has advanced another epoch, it clears all messages for later epochs.
    let node_busy = |node: &mut TestNode<HoneyBadger<Transaction, NodeUid>>| {
        node.outputs
            .iter()
            .map(|&(_, ref batch)| batch.len())
            .sum::<usize>() < num_txs
    };

    // Handle messages until all nodes have output all transactions.
    println!(
        "{}",
        "Epoch  Min/Max Time   Txs Msgs/Node  Size/Node".bold()
    );
    let mut epochs = Vec::new();
    while network.nodes.values_mut().any(node_busy) {
        let id = network.step();
        for &(time, ref batch) in &network.nodes[&id].outputs {
            if epochs.len() <= batch.epoch as usize {
                epochs.resize(batch.epoch as usize + 1, EpochInfo::default());
            }
            epochs[batch.epoch as usize].add(id, time, batch, &network);
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
    env_logger::init();
    let args = parse_args().unwrap_or_else(|e| e.exit());
    if args.flag_n <= 3 * args.flag_f {
        let msg = "Honey Badger only works if less than one third of the nodes are faulty.";
        println!("{}", msg.red().bold());
    }
    println!("Simulating Honey Badger with:");
    println!("{} nodes, {} faulty", args.flag_n, args.flag_f);
    println!(
        "{} transactions, {} bytes each, ≤{} per epoch",
        args.flag_txs, args.flag_tx_size, args.flag_b
    );
    println!(
        "Network lag: {} ms, bandwidth: {} kbit/s, {:5.2}% CPU speed",
        args.flag_lag, args.flag_bw, args.flag_cpu
    );
    println!();
    let num_good_nodes = args.flag_n - args.flag_f;
    let txs = (0..args.flag_txs).map(|_| Transaction::new(args.flag_tx_size));
    let sk_set = SecretKeySet::random(args.flag_f, &mut rand::thread_rng());
    let pk_set = sk_set.public_keys();
    let new_honey_badger = |id: NodeUid, all_ids: BTreeSet<NodeUid>| {
        let netinfo = Rc::new(NetworkInfo::new(
            id,
            all_ids,
            sk_set.secret_key_share(id.0 as u64),
            pk_set.clone(),
        ));
        HoneyBadgerBuilder::new(netinfo)
            .batch_size(args.flag_b)
            .build_with_transactions(txs.clone())
            .expect("Instantiate honey_badger")
    };
    let hw_quality = HwQuality {
        latency: Duration::from_millis(args.flag_lag),
        inv_bw: Duration::new(0, 8_000_000 / args.flag_bw),
        cpu_factor: (10_000f32 / args.flag_cpu) as u32,
    };
    let network = TestNetwork::new(num_good_nodes, args.flag_f, new_honey_badger, hw_quality);
    simulate_honey_badger(network, args.flag_txs);
}
