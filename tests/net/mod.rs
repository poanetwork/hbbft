//! A test network.
//!
//! Test networks simulate a real networking environment that includes an adversary as well as the
//! plumbing to pass messages back and forth between nodes.
//!
//! Networks are "cranked" to move things forward; each crank of a network causes one message to be
//! delivered to a node.

// We need to allow writes with newlines, resulting from `net_trace!` calls.
#![cfg_attr(feature = "cargo-clippy", allow(write_with_newline))]
// Almost all of our types are fairly readable, but trigger the type complexity checks, probably
// due to associated types.
#![cfg_attr(feature = "cargo-clippy", allow(type_complexity))]

pub mod adversary;
pub mod err;
pub mod proptest;
pub mod util;

use std::io::Write;
use std::{cmp, collections, env, fmt, fs, io, ops, process, time};

use rand;
use rand::{Rand, Rng};
use threshold_crypto as crypto;

use hbbft::dynamic_honey_badger::Batch;
use hbbft::util::SubRng;
use hbbft::{self, Contribution, DaStep, DistAlgorithm, Fault, NetworkInfo, NodeIdT, Step};

use try_some;

pub use self::adversary::Adversary;
pub use self::err::CrankError;

/// The time limit for any network if none was specified.
const DEFAULT_TIME_LIMIT: Option<time::Duration> = Some(time::Duration::from_secs(60 * 5));

/// Helper macro for tracing.
///
/// If tracing is enabled (that is the `Option` is not `None`), writes out a traced packet.
macro_rules! net_trace {
    ($self:expr, $fmt:expr, $($arg:tt)*) => (
        if let Some(ref mut dest) = $self.trace {
            write!(dest, $fmt, $($arg)*).expect("could not write to test's trace")
    });
}

/// Open trace file for writing.
fn open_trace() -> Result<io::BufWriter<fs::File>, io::Error> {
    let mut rng = rand::thread_rng();

    let exec_path = env::current_exe()?;
    let name = format!(
        "net-trace_{}_{}_{}.txt",
        exec_path
            .file_name()
            .expect("could not get executable filename")
            .to_string_lossy()
            .into_owned(),
        process::id(),
        u16::rand(&mut rng),
    );

    Ok(io::BufWriter::new(fs::File::create(name)?))
}

/// A node in the test network.
pub struct Node<D: DistAlgorithm> {
    /// Algorithm instance of node.
    algorithm: D,
    /// Whether or not the node is faulty.
    is_faulty: bool,
    /// Captured algorithm outputs, in order.
    outputs: Vec<D::Output>,
    /// Collected fault log.
    faults: Vec<Fault<D::NodeId>>,
}

impl<D> fmt::Debug for Node<D>
where
    D: DistAlgorithm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Node")
            .field("algorithm", &"yes")
            .field("is_faulty", &self.is_faulty)
            .field("outputs", &self.outputs.len())
            .finish()
    }
}

impl<D: DistAlgorithm> Node<D> {
    /// Create a new node.
    #[inline]
    fn new(algorithm: D, is_faulty: bool) -> Self {
        Node {
            algorithm,
            is_faulty,
            outputs: Vec::new(),
            faults: Vec::new(),
        }
    }

    /// Get algorithm instance.
    #[inline]
    pub fn algorithm(&self) -> &D {
        &self.algorithm
    }

    /// Get mutable algorithm instance.
    #[inline]
    pub fn algorithm_mut(&mut self) -> &mut D {
        &mut self.algorithm
    }

    /// Check whether or not node is marked faulty.
    #[inline]
    pub fn is_faulty(&self) -> bool {
        self.is_faulty
    }

    /// Get node's ID.
    ///
    /// A node's ID is equal to its underlying algorithm instance's ID.
    #[inline]
    pub fn id(&self) -> &D::NodeId {
        self.algorithm.our_id()
    }

    /// List outputs so far.
    ///
    /// Any output made by a node is captured by the node for easy comparison.
    #[inline]
    pub fn outputs(&self) -> &[D::Output] {
        self.outputs.as_slice()
    }

    /// List faults so far.
    ///
    /// All faults are collected for reference purposes.
    #[inline]
    pub fn faults(&self) -> &[Fault<D::NodeId>] {
        self.faults.as_slice()
    }

    /// Collects all outputs and faults (not required for network operation) for user convenience.
    fn store_step(&mut self, step: &DaStep<D>)
    where
        D::Output: Clone,
    {
        self.outputs.extend(step.output.iter().cloned());
        self.faults.extend(step.fault_log.0.iter().cloned());
    }
}

/// A network message on the virtual network.
// Note: We do not use `hbbft::TargetedMessage` and `hbbft::SourceMessage` here, the nesting
//       is inconvenient and we do not want to support broadcasts at this level.
#[derive(Clone, Debug)]
pub struct NetworkMessage<M, N> {
    /// Message sender.
    from: N,
    /// Destined receiver.
    to: N,
    /// The actual message contents.
    payload: M,
}

impl<M, N> NetworkMessage<M, N> {
    /// Create a new network message.
    #[inline]
    pub fn new(from: N, payload: M, to: N) -> NetworkMessage<M, N> {
        NetworkMessage { from, to, payload }
    }

    /// Returns the source of the message
    #[inline]
    pub fn from(&self) -> &N {
        &self.from
    }

    /// Returns the destination of the message
    #[inline]
    pub fn to(&self) -> &N {
        &self.to
    }

    /// Returns the contents of the message
    #[inline]
    pub fn payload(&self) -> &M {
        &self.payload
    }
}

/// Mapping from node IDs to actual node instances.
pub type NodeMap<D> = collections::BTreeMap<<D as DistAlgorithm>::NodeId, Node<D>>;

/// A virtual network message tied to a distributed algorithm.
pub type NetMessage<D> =
    NetworkMessage<<D as DistAlgorithm>::Message, <D as DistAlgorithm>::NodeId>;

/// Process a step.
///
/// Expands every message in the step by turning all broadcast messages into peer-to-peer messages,
/// and appends them to the network queue. Additionally, saves a copy of each output to the output
/// buffer of the `sender` node.
///
/// At the end, the number of additional messages created by non-faulty nodes is returned.
///
/// # Panics
///
/// The function will panic if the `sender` ID is not a valid node ID in `nodes`.
// This function is defined outside `VirtualNet` and takes arguments "piecewise" to work around
// borrow-checker restrictions.
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn process_step<'a, D>(
    nodes: &'a mut collections::BTreeMap<D::NodeId, Node<D>>,
    sender: D::NodeId,
    step: &DaStep<D>,
    dest: &mut collections::VecDeque<NetMessage<D>>,
) -> usize
where
    D: DistAlgorithm + 'a,
    D::Message: Clone,
    D::Output: Clone,
{
    // For non-faulty nodes, we count the number of messages.
    let faulty = nodes
        .get(&sender)
        .expect("Trying to process a step with non-existing node ID")
        .is_faulty();
    let mut message_count: usize = 0;

    // Queue all messages for processing.
    for tmsg in &step.messages {
        match &tmsg.target {
            // Single target message.
            hbbft::Target::Node(to) => {
                if !faulty {
                    message_count = message_count.saturating_add(1);
                }

                dest.push_back(NetworkMessage::new(
                    sender.clone(),
                    tmsg.message.clone(),
                    to.clone(),
                ));
            }
            // Broadcast messages get expanded into multiple direct messages.
            hbbft::Target::All => {
                for to in nodes.keys().filter(|&to| to != &sender) {
                    if !faulty {
                        message_count = message_count.saturating_add(1);
                    }

                    dest.push_back(NetworkMessage::new(
                        sender.clone(),
                        tmsg.message.clone(),
                        to.clone(),
                    ));
                }
            }
        }
    }

    nodes
        .get_mut(&sender)
        .expect("Trying to process a step with non-existing node ID")
        .store_step(step);
    // Verify that no correct node is reported as faulty.
    for fault in &step.fault_log.0 {
        if nodes.get(&fault.node_id).map(|n| !n.is_faulty()) == Some(true) {
            panic!("Unexpected fault: {:?}", fault);
        }
    }

    message_count
}

/// New network node construction information.
///
/// Helper structure passed to node constructors when building virtual networks.
pub struct NewNodeInfo<D>
where
    D: DistAlgorithm,
{
    /// The node ID for the new node.
    pub id: D::NodeId,
    /// Network info struct, containing keys and other information.
    pub netinfo: NetworkInfo<D::NodeId>,
    /// Whether or not the node is marked faulty.
    pub faulty: bool,
    /// An initialized random number generated for exclusive use by the node.
    ///
    /// Can be ignored, but usually comes in handy with algorithms that require additional
    /// randomness for instantiation or operation.
    ///
    /// Note that the random number generator type may differ from the one set for generation on
    /// the `VirtualNet`, due to limitations of the `rand` crates API.
    pub rng: Box<dyn rand::Rng>,
}

impl<D> fmt::Debug for NewNodeInfo<D>
where
    D: DistAlgorithm,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("NewNodeInfo")
            .field("id", &self.id)
            .field("netinfo", &self.netinfo)
            .field("faulty", &self.faulty)
            .field("rng", &"<RNG>")
            .finish()
    }
}

/// Virtual network builder.
///
/// The `NetBuilder` is used to create `VirtualNet` instances and offers convenient methods to
/// configure the construction process.
///
/// Note that, in addition to the constructor `new`, either `using` or `using_step` must be called,
/// otherwise the construction will fail and panic.
pub struct NetBuilder<D, I>
where
    D: DistAlgorithm,
{
    /// Iterator used to create node ids.
    node_ids: I,
    /// Number of faulty nodes in the network.
    num_faulty: usize,
    /// Dist-algorithm constructor function.
    cons: Option<Box<Fn(NewNodeInfo<D>) -> (D, DaStep<D>)>>,
    /// Network adversary.
    adversary: Option<Box<dyn Adversary<D>>>,
    /// Trace-enabling flag. `None` means use environment.
    trace: Option<bool>,
    /// Optional crank limit.
    crank_limit: Option<usize>,
    /// Optional message limit.
    message_limit: Option<usize>,
    /// Optional time limit.
    time_limit: Option<time::Duration>,
    /// Random number generator used to generate keys.
    rng: Option<Box<dyn Rng>>,
}

impl<D, I> fmt::Debug for NetBuilder<D, I>
where
    D: DistAlgorithm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NetBuilder")
            .field("node_ids", &())
            .field("num_faulty", &self.num_faulty)
            .field("cons", &self.cons.is_some())
            .field("adversary", &self.cons.is_some())
            .field("trace", &self.trace)
            .field("crank_limit", &self.crank_limit)
            .field("message_limit", &self.message_limit)
            .field("time_limit", &self.time_limit)
            .field("rng", &"<RNG>")
            .finish()
    }
}

impl<D, I> NetBuilder<D, I>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
    I: IntoIterator<Item = D::NodeId>,
{
    /// Construct a new network builder.
    ///
    /// `node_ids` must be an iterator of the node ids to use for the new node. In many test cases,
    /// a `Range(usize)` is a convenient value:
    ///
    /// ```rust,ignore
    /// let builder = NetBuilder::new(0..10) // ...
    /// ```
    #[inline]
    pub fn new(node_ids: I) -> Self {
        NetBuilder {
            node_ids,
            num_faulty: 0,
            cons: None,
            adversary: None,
            trace: None,
            crank_limit: None,
            message_limit: None,
            time_limit: DEFAULT_TIME_LIMIT,
            rng: None,
        }
    }

    /// Set an adversary.
    ///
    /// If not set, the virtual network is constructed with a `NullAdversary`.
    #[inline]
    pub fn adversary<A>(mut self, adversary: A) -> Self
    where
        A: Adversary<D> + 'static,
    {
        self.adversary = Some(Box::new(adversary));
        self
    }

    /// Set a crank limit.
    ///
    /// Crank limits are useful to limit execution time and rein in adversary. Otherwise, message
    /// limits are typically more useful. After the limit is hit, any call to `crank` will return a
    /// `CrankError::CrankLimitExceeded`.
    #[inline]
    pub fn crank_limit(mut self, crank_limit: usize) -> Self {
        self.crank_limit = Some(crank_limit);
        self
    }

    /// Message limit.
    ///
    /// Limit the number of messages, as soon as the limit of messages is exceeded (regardless of
    /// whether they have been processed yet), the `crank` function will return a
    /// `CrankError::MessageLimitExceeded`.
    #[inline]
    pub fn message_limit(mut self, message_limit: usize) -> Self {
        self.message_limit = Some(message_limit);
        self
    }

    /// Remove the time limit.
    ///
    /// Removes any time limit from the builder.
    #[inline]
    pub fn no_time_limit(mut self) -> Self {
        self.time_limit = None;
        self
    }

    /// Number of faulty nodes.
    ///
    /// Indicates the number of nodes that should be marked faulty.
    #[inline]
    pub fn num_faulty(mut self, num_faulty: usize) -> Self {
        self.num_faulty = num_faulty;
        self
    }

    /// Random number generator.
    ///
    /// Overrides the random number generator used. If not specified, a `thread_rng` will be
    /// used on construction.
    ///
    /// The passed in generator is used for key generation.
    pub fn rng<R>(mut self, rng: R) -> Self
    where
        R: Rng + 'static,
    {
        self.rng = Some(Box::new(rng));
        self
    }

    /// Time limit.
    ///
    /// Sets the time limit; `crank` will fail if called after this much time as elapsed since
    /// the network was instantiated.
    #[inline]
    pub fn time_limit(mut self, limit: time::Duration) -> Self {
        self.time_limit = Some(limit);
        self
    }

    /// Override tracing.
    ///
    /// If set, overrides the environment setting of whether or not tracing should be enabled.
    #[inline]
    pub fn trace(mut self, trace: bool) -> Self {
        self.trace = Some(trace);
        self
    }

    /// Constructor function (with step).
    ///
    /// The constructor function is used to construct each node in the network. Any step returned
    /// is processed normally.
    #[inline]
    pub fn using_step<F>(mut self, cons: F) -> Self
    where
        F: Fn(NewNodeInfo<D>) -> (D, DaStep<D>) + 'static,
    {
        self.cons = Some(Box::new(cons));
        self
    }

    /// Constructor function.
    ///
    /// Convenience function for algorithms that do not require an initial `Step`, calls
    /// `using_step` with a default/empty `Step` instance.
    #[inline]
    pub fn using<F>(self, cons_simple: F) -> Self
    where
        F: Fn(NewNodeInfo<D>) -> D + 'static,
    {
        self.using_step(move |node| (cons_simple(node), Default::default()))
    }

    /// Create the network.
    ///
    /// Finalizes the builder and creates the network.
    ///
    /// # Panics
    ///
    /// If the total number of nodes is not `> 3 * num_faulty`, construction will panic.
    #[inline]
    pub fn build(self) -> Result<VirtualNet<D>, crypto::error::Error> {
        let rng: Box<dyn Rng> = self.rng.unwrap_or_else(|| Box::new(rand::thread_rng()));

        // The time limit can be overriden through environment variables:
        let override_time_limit = env::var("HBBFT_NO_TIME_LIMIT")
            // We fail early, to avoid tricking the user into thinking that they have set the time
            // limit when they haven't.
            .map(|s| s.parse().expect("could not parse `HBBFT_NO_TIME_LIMIT`"))
            .unwrap_or(false);

        let time_limit = if override_time_limit {
            eprintln!("WARNING: The time limit for individual tests has been manually disabled through `HBBFT_NO_TIME_LIMIT`.");
            None
        } else {
            self.time_limit
        };

        let cons = self
            .cons
            .as_ref()
            .expect("cannot build network without a constructor function for the nodes");

        // Note: Closure is not redundant, won't compile without it.
        #[cfg_attr(feature = "cargo-clippy", allow(redundant_closure))]
        let mut net = VirtualNet::new(self.node_ids, self.num_faulty as usize, rng, move |node| {
            cons(node)
        })?;

        if self.adversary.is_some() {
            net.adversary = self.adversary;
        }

        // If the trace setting is not overriden, we use the setting from the environment.
        let trace = self.trace.unwrap_or_else(|| {
            match env::var("HBBFT_TEST_TRACE").as_ref().map(|s| s.as_str()) {
                Ok("true") | Ok("1") => true,
                _ => false,
            }
        });

        if trace {
            net.trace = Some(open_trace().expect("could not open trace file"));
        }

        net.crank_limit = self.crank_limit;
        net.message_limit = self.message_limit;
        net.time_limit = time_limit;

        Ok(net)
    }
}

/// Virtual network instance.
pub struct VirtualNet<D>
where
    D: DistAlgorithm,
{
    /// Maps node IDs to actual node instances.
    nodes: NodeMap<D>,
    /// A collection of all network messages queued up for delivery.
    messages: collections::VecDeque<NetMessage<D>>,
    /// An Adversary that controls the network delivery schedule and all faulty nodes.
    /// Always present (initialized to `NullAdversary` by default), but an `Option` to be swappable
    /// during execution, allowing a `&mut self` to be passed to the adversary without running afoul
    /// of the borrow checker.
    adversary: Option<Box<dyn Adversary<D>>>,
    /// Trace output; if active, writes out a log of all messages.
    trace: Option<io::BufWriter<fs::File>>,
    /// The number of times the network has been cranked.
    crank_count: usize,
    /// The limit set for cranking the network.
    crank_limit: Option<usize>,
    /// The number of messages seen by the network.
    message_count: usize,
    /// The limit set for the number of messages.
    message_limit: Option<usize>,
    /// Limits the maximum running time between construction and last call to `crank()`.
    time_limit: Option<time::Duration>,
    /// The instant the network was created.
    start_time: time::Instant,
}

impl<D> fmt::Debug for VirtualNet<D>
where
    D: DistAlgorithm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VirtualNet")
            .field("nodes", &self.nodes.len())
            .field("messages", &self.messages)
            .field("adversary", &self.adversary.is_some())
            .field("trace", &self.trace.is_some())
            .field("crank_count", &self.crank_count)
            .field("crank_limit", &self.crank_limit)
            .field("message_count", &self.message_count)
            .field("message_limit", &self.message_limit)
            .finish()
    }
}

/// A virtual network
///
/// Virtual networks host a number of nodes that are marked either correct or faulty. Each time a
/// node emits a `Step`, the contained messages are queued for delivery, which happens whenever
/// `crank()` is called. Additionally, inputs (see `DistAlgorithm::Input`) can be sent to any node.
///
/// An adversary can be hooked into the network to affect the order of message delivery or the
/// behaviour of faulty nodes.
impl<D> VirtualNet<D>
where
    D: DistAlgorithm,
{
    /// Returns an iterator over *all* nodes in the network.
    #[inline]
    pub fn nodes(&self) -> impl Iterator<Item = &Node<D>> {
        self.nodes.values()
    }

    /// Returns an iterator that allows modifying *all* nodes in the network.
    #[inline]
    pub fn nodes_mut(&mut self) -> impl Iterator<Item = &mut Node<D>> {
        self.nodes.values_mut()
    }

    /// Returns an iterator over all faulty nodes in the network.
    #[inline]
    pub fn faulty_nodes(&self) -> impl Iterator<Item = &Node<D>> {
        self.nodes().filter(|n| n.is_faulty())
    }

    /// Returns an iterator that allows modifying all faulty nodes in the network.
    #[inline]
    pub fn faulty_nodes_mut(&mut self) -> impl Iterator<Item = &mut Node<D>> {
        self.nodes_mut().filter(|n| n.is_faulty())
    }

    /// Returns an iterator over all correct nodes in the network.
    #[inline]
    pub fn correct_nodes(&self) -> impl Iterator<Item = &Node<D>> {
        self.nodes().filter(|n| !n.is_faulty())
    }

    /// Returns an iterator that allows modifying all correct nodes in the network.
    #[inline]
    pub fn correct_nodes_mut(&mut self) -> impl Iterator<Item = &mut Node<D>> {
        self.nodes_mut().filter(|n| !n.is_faulty())
    }

    /// Retrieve a node by ID.
    ///
    /// Returns `None` if the node ID is not part of the network.
    #[inline]
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn get<'a>(&'a self, id: D::NodeId) -> Option<&'a Node<D>> {
        self.nodes.get(&id)
    }

    /// Retrieve a node mutably by ID.
    ///
    /// Returns `None` if the node ID is not part of the network.
    #[inline]
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn get_mut<'a>(&'a mut self, id: D::NodeId) -> Option<&'a mut Node<D>> {
        self.nodes.get_mut(&id)
    }

    /// Returns an iterator over all messages currently queued.
    #[inline]
    pub fn messages(&self) -> impl Iterator<Item = &NetMessage<D>> {
        self.messages.iter()
    }

    /// Returns an iterator that allows modifying all messages currently queued.
    #[inline]
    pub fn messages_mut(&mut self) -> impl Iterator<Item = &mut NetMessage<D>> {
        self.messages.iter_mut()
    }

    /// Length of the message queue.
    #[inline]
    pub fn messages_len(&self) -> usize {
        self.messages.len()
    }

    /// Swap two queued messages at indices `i` and `j`.
    #[inline]
    pub fn swap_messages(&mut self, i: usize, j: usize) {
        self.messages.swap(i, j)
    }

    /// Sort queued messages by a function.
    ///
    /// The underlying sort function is stable and has `O(n log n)` bounded runtime; but comes with
    /// an `O(5n)` copying cost.
    #[inline]
    pub fn sort_messages_by<F>(&mut self, f: F)
    where
        F: FnMut(&NetMessage<D>, &NetMessage<D>) -> cmp::Ordering,
    {
        // We use stable sorting, which uses Tim sort internally. Adversaries are probably sorting
        // almost-sorted sequences fairly often (e.g. on every iteration), for which Tim sort is a
        // nice fit.

        // Create a `Vec` from the `VecDeque`, which does not support sorting out-of-the-box.
        let l = self.messages.len();
        let mut msgs: Vec<_> = self.messages.drain(0..l).collect();

        // Perform sorting and drain `Vec` back into `VecDeque`.
        msgs.sort_by(f);
        self.messages.extend(msgs);
    }
}

impl<D> VirtualNet<D>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
{
    /// Create new virtual network with step constructor.
    ///
    /// Creates a new network from `node_ids`, with the first `faulty` nodes marked faulty. To
    /// construct nodes, the `cons` function is passed the ID and the generated `NetworkInfo` and
    /// expected to return a (`DistAlgorithm`, `Step`) tuple.
    ///
    /// All messages from the resulting step are queued for delivery.
    ///
    /// This function is not used directly, instead the `NetBuilder` should be used.
    ///
    /// # Panics
    ///
    /// The total number of nodes, that is `node_ids.count()` must be `> 3 * faulty`, otherwise
    /// the construction function will panic.
    fn new<F, I, R>(
        node_ids: I,
        faulty: usize,
        mut rng: R,
        cons: F,
    ) -> Result<Self, crypto::error::Error>
    where
        F: Fn(NewNodeInfo<D>) -> (D, DaStep<D>),
        I: IntoIterator<Item = D::NodeId>,
        R: rand::Rng,
    {
        // Generate a new set of cryptographic keys for threshold cryptography.
        let net_infos = NetworkInfo::generate_map(node_ids, &mut rng)?;

        assert!(
            faulty * 3 < net_infos.len(),
            "Too many faulty nodes requested, `f` must satisfy `3f < total_nodes`."
        );

        let mut steps = collections::BTreeMap::new();
        let mut messages = collections::VecDeque::new();

        let mut nodes = net_infos
            .into_iter()
            .enumerate()
            .map(|(idx, (id, netinfo))| {
                let is_faulty = idx < faulty;

                let (algorithm, step) = cons(NewNodeInfo {
                    id: id.clone(),
                    netinfo,
                    faulty: is_faulty,
                    rng: rng.sub_rng(),
                });
                steps.insert(id.clone(), step);
                (id, Node::new(algorithm, is_faulty))
            }).collect();

        let mut message_count: usize = 0;
        // For every recorded step, apply it.
        for (sender, step) in steps {
            message_count = message_count.saturating_add(process_step(
                &mut nodes,
                sender,
                &step,
                &mut messages,
            ));
        }

        Ok(VirtualNet {
            nodes,
            messages,
            adversary: Some(Box::new(adversary::NullAdversary::new())),
            trace: None,
            crank_count: 0,
            crank_limit: None,
            message_count,
            message_limit: None,
            time_limit: None,
            start_time: time::Instant::now(),
        })
    }

    /// Helper function to dispatch messages.
    ///
    /// Retrieves the receiving node for a `msg` and hands over the payload.
    #[inline]
    pub fn dispatch_message(&mut self, msg: NetMessage<D>) -> Result<DaStep<D>, CrankError<D>> {
        let node = self
            .nodes
            .get_mut(&msg.to)
            .ok_or_else(|| CrankError::NodeDisappeared(msg.to.clone()))?;

        // Store a copy of the message, in case we need to pass it to the error variant.
        // By reducing the information in `CrankError::AlgorithmError`, we could reduce overhead
        // here if necessary.
        let msg_copy = msg.clone();
        let step = node
            .algorithm
            .handle_message(&msg.from, msg.payload)
            .map_err(move |err| CrankError::AlgorithmError { msg: msg_copy, err })?;

        Ok(step)
    }

    /// Send input to a specific node.
    ///
    /// Sends the specified `input` to the respective node identified by `id`. The messages of the
    /// resulting `step` are added to the network's queue.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not name a valid node.
    #[inline]
    pub fn send_input(&mut self, id: D::NodeId, input: D::Input) -> Result<DaStep<D>, D::Error> {
        let step = self
            .nodes
            .get_mut(&id)
            .expect("cannot handle input on non-existing node")
            .algorithm
            .handle_input(input)?;

        self.message_count = self.message_count.saturating_add(process_step(
            &mut self.nodes,
            id,
            &step,
            &mut self.messages,
        ));

        Ok(step)
    }

    /// Advance the network.
    ///
    /// Picks a message to deliver, delivers it and returns the handling node's ID and the result
    /// of the message handling. If the network message queue is empty, returns `None`.
    ///
    /// If a successful `Step` was generated, all of its messages are queued on the network and the
    /// `Step` is returned.
    #[inline]
    pub fn crank(&mut self) -> Option<Result<(D::NodeId, DaStep<D>), CrankError<D>>> {
        // Check limits.
        if let Some(limit) = self.crank_limit {
            if self.crank_count >= limit {
                return Some(Err(CrankError::CrankLimitExceeded(limit)));
            }
        }

        if let Some(limit) = self.message_limit {
            if self.message_count >= limit {
                return Some(Err(CrankError::MessageLimitExceeded(limit)));
            }
        }

        if let Some(limit) = self.time_limit {
            if time::Instant::now().duration_since(self.start_time) > limit {
                return Some(Err(CrankError::TimeLimitHit(limit)));
            }
        }

        // Step 0: We give the Adversary a chance to affect the network.

        // We need to swap out the adversary, to avoid ownership/borrowing issues.
        let mut adv = self.adversary.take();
        if let Some(ref mut adversary) = adv {
            // If an adversary was set, we let it affect the network now.
            adversary.pre_crank(adversary::NetMutHandle::new(self))
        }
        self.adversary = adv;

        // Step 1: Pick a message from the queue and deliver it; returns `None` if queue is empty.
        let msg = self.messages.pop_front()?;

        net_trace!(
            self,
            "[{:?}] -> [{:?}]: {:?}\n",
            msg.from,
            msg.to,
            msg.payload
        );
        let receiver = msg.to.clone();

        // Unfortunately, we have to re-borrow the target node further down to make the borrow
        // checker happy. First, we check if the receiving node is faulty, so we can dispatch
        // through the adversary if it is.
        let is_faulty = try_some!(
            self.nodes
                .get(&msg.to)
                .ok_or_else(|| CrankError::NodeDisappeared(msg.to.clone()))
        ).is_faulty();

        let step: Step<_, _, _> = if is_faulty {
            // The swap-dance is painful here, as we are creating an `opt_step` just to avoid
            // borrow issues.
            let mut adv = self.adversary.take();
            let opt_tamper_result = adv.as_mut().map(|adversary| {
                // If an adversary was set, we let it affect the network now.
                adversary.tamper(adversary::NetMutHandle::new(self), msg)
            });
            self.adversary = adv;

            // A missing adversary here could technically be a panic, but is impossible since we
            // initialize with a `NullAdversary` upon construction.
            try_some!(
                opt_tamper_result.expect("No adversary defined (expected at least NullAdversary)")
            )
        } else {
            // A correct node simply handles the message.
            try_some!(self.dispatch_message(msg))
        };

        // All messages are expanded and added to the queue. We opt for copying them, so we can
        // return unaltered step later on for inspection.
        self.message_count = self.message_count.saturating_add(process_step(
            &mut self.nodes,
            receiver.clone(),
            &step,
            &mut self.messages,
        ));

        // Increase the crank count.
        self.crank_count += 1;

        Some(Ok((receiver, step)))
    }

    /// Convenience function for cranking.
    ///
    /// Shortcut for cranking the network, expecting both progress to be made as well as processing
    /// to proceed.
    pub fn crank_expect(&mut self) -> (D::NodeId, DaStep<D>) {
        self.crank()
            .expect("crank: network queue empty")
            .expect("crank: node failed to process step")
    }
}

impl<D> VirtualNet<D>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Input: Clone,
    D::Output: Clone,
{
    /// Send input to all nodes.
    ///
    /// Equivalent to sending the same input to all nodes in order. Returns a vector of the
    /// resulting `Step`s, which have had their messages queued already.
    ///
    /// If an error occurs, the first error is returned and broadcasting aborted.
    #[inline]
    pub fn broadcast_input<'a>(
        &'a mut self,
        input: &'a D::Input,
    ) -> Result<Vec<(D::NodeId, DaStep<D>)>, D::Error> {
        // Note: The tricky lifetime annotation basically says that the input value given must
        //       live as long as the iterator returned lives (because it is cloned on every step,
        //       with steps only evaluated each time `next()` is called. For the same reason the
        //       network should not go away ealier either.

        // Note: It's unfortunately not possible to loop and call `send_input`,

        let steps: Vec<_> = self
            .nodes
            .values_mut()
            .map(move |node| {
                Ok((
                    node.id().clone(),
                    node.algorithm.handle_input(input.clone())?,
                ))
            }).collect::<Result<_, _>>()?;

        // Process all messages from all steps in the queue.
        steps.iter().for_each(|(id, step)| {
            self.message_count = self.message_count.saturating_add(process_step(
                &mut self.nodes,
                id.clone(),
                step,
                &mut self.messages,
            ));
        });

        Ok(steps)
    }
}

impl<C, D, N> VirtualNet<D>
where
    D: DistAlgorithm<Output = Batch<C, N>>,
    C: Contribution + Clone,
    N: NodeIdT,
{
    /// Verifies that all nodes' outputs agree, and returns the output.
    pub fn verify_batches(&self) -> &[Batch<C, N>] {
        let first = self.correct_nodes().nth(0).unwrap().outputs();
        let pub_eq = |(b0, b1): (&Batch<C, _>, &Batch<C, _>)| b0.public_eq(b1);
        for (i, node) in self.correct_nodes().enumerate().skip(0) {
            assert!(
                first.iter().zip(node.outputs()).all(pub_eq),
                "Outputs of nodes 0 and {} differ: {:?} != {:?}",
                i,
                first,
                node.outputs()
            );
        }
        first
    }
}

impl<D> ops::Index<D::NodeId> for VirtualNet<D>
where
    D: DistAlgorithm,
{
    type Output = Node<D>;

    #[inline]
    fn index(&self, index: D::NodeId) -> &Self::Output {
        self.get(index).expect("indexed node not found")
    }
}

impl<D> ops::IndexMut<D::NodeId> for VirtualNet<D>
where
    D: DistAlgorithm,
{
    #[inline]
    fn index_mut(&mut self, index: D::NodeId) -> &mut Self::Output {
        self.get_mut(index).expect("indexed node not found")
    }
}

/// Convenient iterator implementation, calls crank repeatedly until the message queue is empty.
///
/// Accessing the network during iterator would require
/// [streaming iterators](https://crates.io/crates/streaming-iterator), an alternative is using
/// a `while let` loop:
///
/// ```rust,no_run
/// while let Some(rstep) = net.crank() {
///     // `net` can still be mutable borrowed here.
/// }
/// ```
impl<D> Iterator for VirtualNet<D>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
{
    type Item = Result<(D::NodeId, DaStep<D>), CrankError<D>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.crank()
    }
}
