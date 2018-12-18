//! A test network.
//!
//! Test networks simulate a real networking environment that includes an adversary as well as the
//! plumbing to pass messages back and forth between nodes.
//!
//! Networks are "cranked" to move things forward; each crank of a network causes one message to be
//! delivered to a node.

// We need to allow writes with newlines, resulting from `net_trace!` calls.
#![allow(clippy::write_with_newline)]
// Almost all of our types are fairly readable, but trigger the type complexity checks, probably
// due to associated types.
#![allow(clippy::type_complexity)]
// Some of our constructors return results.
#![allow(clippy::new_ret_no_self)]

pub mod adversary;
pub mod err;
pub mod proptest;
pub mod util;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write;
use std::{cmp, env, fmt, fs, io, ops, process, time};

use rand::{self, Rng};

use hbbft::dynamic_honey_badger::Batch;
use hbbft::sender_queue::SenderQueueableOutput;
use hbbft::{self, Contribution, DaStep, DistAlgorithm, Fault, NetworkInfo, NodeIdT, Step};

use crate::try_some;

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
        rng.gen::<u16>()
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
    /// Collected fault log, in order.
    faults: Vec<Fault<D::NodeId, D::FaultKind>>,
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
    pub fn faults(&self) -> &[Fault<D::NodeId, D::FaultKind>] {
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
pub type NodeMap<D> = BTreeMap<<D as DistAlgorithm>::NodeId, Node<D>>;

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
#[allow(clippy::needless_pass_by_value)]
fn process_step<'a, D>(
    nodes: &'a mut BTreeMap<D::NodeId, Node<D>>,
    sender: D::NodeId,
    step: &DaStep<D>,
    dest: &mut VecDeque<NetMessage<D>>,
    error_on_fault: bool,
) -> Result<usize, CrankError<D>>
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
    if error_on_fault {
        // Verify that no correct node is reported as faulty.
        for fault in &step.fault_log.0 {
            if nodes.get(&fault.node_id).map_or(false, |n| !n.is_faulty()) {
                return Err(CrankError::Fault(fault.clone()));
            }
        }
    }
    Ok(message_count)
}

/// New network node construction information.
///
/// Helper structure passed to node constructors when building virtual networks.
#[derive(Debug)]
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
}

/// Virtual network builder.
///
/// The `NetBuilder` is used to create `VirtualNet` instances and offers convenient methods to
/// configure the construction process.
///
/// Note that, in addition to the constructor `new`, either `using` or `using_step` must be called,
/// otherwise the construction will fail and panic.
pub struct NetBuilder<D, I, A>
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
    adversary: Option<A>,
    /// Trace-enabling flag. `None` means use environment.
    trace: Option<bool>,
    /// Optional crank limit.
    crank_limit: Option<usize>,
    /// Optional message limit.
    message_limit: Option<usize>,
    /// Optional time limit.
    time_limit: Option<time::Duration>,
    /// Property to cause an error if a `Fault` is output from a correct node. By default,
    /// encountering a fault leads to an error.
    error_on_fault: bool,
}

impl<D, I, A> fmt::Debug for NetBuilder<D, I, A>
where
    D: DistAlgorithm,
    A: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NetBuilder")
            .field("node_ids", &())
            .field("num_faulty", &self.num_faulty)
            .field("cons", &self.cons.is_some())
            .field("adversary", &self.adversary)
            .field("trace", &self.trace)
            .field("crank_limit", &self.crank_limit)
            .field("message_limit", &self.message_limit)
            .field("time_limit", &self.time_limit)
            .field("error_on_fault", &self.error_on_fault)
            .finish()
    }
}

impl<D, I, A> NetBuilder<D, I, A>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
    I: IntoIterator<Item = D::NodeId>,
    A: Adversary<D>,
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
            error_on_fault: true,
        }
    }

    /// Set an adversary.
    ///
    /// If not set, the virtual network is constructed with a `NullAdversary`.
    #[inline]
    pub fn adversary(mut self, adversary: A) -> Self {
        self.adversary = Some(adversary);
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

    /// Property to cause an error if a `Fault` is output from a correct node. By default,
    /// encountering a fault leads to an error.
    ///
    /// The default setting `true` can be changed using this function.
    #[inline]
    pub fn error_on_fault(mut self, error_on_fault: bool) -> Self {
        self.error_on_fault = error_on_fault;
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
    pub fn build<R: Rng>(
        self,
        rng: &mut R,
    ) -> Result<(VirtualNet<D, A>, Vec<(D::NodeId, DaStep<D>)>), CrankError<D>> {
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
        #[allow(clippy::redundant_closure)]
        let (mut net, steps) = VirtualNet::new(
            self.node_ids,
            self.num_faulty as usize,
            rng,
            move |node| cons(node),
            self.error_on_fault,
        )?;

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

        Ok((net, steps))
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
#[derive(Debug)]
pub struct VirtualNet<D, A>
where
    D: DistAlgorithm,
    A: Adversary<D>,
    D::Message: Clone,
    D::Output: Clone,
{
    /// Maps node IDs to actual node instances.
    nodes: NodeMap<D>,
    /// A collection of all network messages queued up for delivery.
    messages: VecDeque<NetMessage<D>>,
    /// An optional `Adversary` that controls the network delivery schedule and all faulty nodes.
    adversary: Option<A>,
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
    /// Property to cause an error if a `Fault` is output from a correct node. Setting this to
    /// `false` switches allows to carry on with the test despite `Fault`s reported for a correct
    /// node.
    error_on_fault: bool,
}

impl<D, A> VirtualNet<D, A>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>,
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

    /// Inserts a new node into the network. Returns the old node with the same ID if it existed on
    /// the network at the time of insertion.
    #[inline]
    pub fn insert_node(&mut self, node: Node<D>) -> Option<Node<D>> {
        self.nodes.insert(node.id().clone(), node)
    }

    /// Removes a node with the given ID from the network. Returns the removed node if there was a
    /// node with this ID at the time of removal.
    #[inline]
    pub fn remove_node(&mut self, id: &D::NodeId) -> Option<Node<D>> {
        self.messages.retain(|msg| msg.to != *id);
        self.nodes.remove(id)
    }

    /// Retrieve a node by ID.
    ///
    /// Returns `None` if the node ID is not part of the network.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get<'a>(&'a self, id: D::NodeId) -> Option<&'a Node<D>> {
        self.nodes.get(&id)
    }

    /// Retrieve a node mutably by ID.
    ///
    /// Returns `None` if the node ID is not part of the network.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
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

impl<D, A> VirtualNet<D, A>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>,
{
    /// Create new virtual network with step constructor.
    ///
    /// Creates a new network from `node_ids`, with the first `faulty` nodes marked faulty. To
    /// construct nodes, the `cons` function is passed the ID and the generated `NetworkInfo` and
    /// expected to return a (`DistAlgorithm`, `Step`) tuple.
    ///
    /// All messages from the resulting step are queued for delivery. The function outputs the
    /// initial steps of the nodes in the constructed network for testing purposes.
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
        error_on_fault: bool,
    ) -> Result<(Self, Vec<(D::NodeId, DaStep<D>)>), CrankError<D>>
    where
        F: Fn(NewNodeInfo<D>) -> (D, DaStep<D>),
        I: IntoIterator<Item = D::NodeId>,
        R: rand::Rng,
    {
        // Generate a new set of cryptographic keys for threshold cryptography.
        let net_infos = NetworkInfo::generate_map(node_ids, &mut rng)
            .map_err(CrankError::InitialKeyGeneration)?;

        assert!(
            faulty * 3 < net_infos.len(),
            "Too many faulty nodes requested, `f` must satisfy `3f < total_nodes`."
        );

        let mut steps = BTreeMap::new();
        let mut messages = VecDeque::new();

        let mut nodes = net_infos
            .into_iter()
            .enumerate()
            .map(|(idx, (id, netinfo))| {
                let is_faulty = idx < faulty;

                let (algorithm, step) = cons(NewNodeInfo {
                    id: id.clone(),
                    netinfo,
                    faulty: is_faulty,
                });
                steps.insert(id.clone(), step);
                (id, Node::new(algorithm, is_faulty))
            })
            .collect();

        let mut message_count: usize = 0;
        // For every recorded step, apply it.
        for (sender, step) in &steps {
            let n = process_step(
                &mut nodes,
                sender.clone(),
                step,
                &mut messages,
                error_on_fault,
            )?;
            message_count = message_count.saturating_add(n);
        }

        Ok((
            VirtualNet {
                nodes,
                messages,
                adversary: None,
                trace: None,
                crank_count: 0,
                crank_limit: None,
                message_count,
                message_limit: None,
                time_limit: None,
                start_time: time::Instant::now(),
                error_on_fault: true,
            },
            steps.into_iter().collect(),
        ))
    }

    /// Helper function to dispatch messages.
    ///
    /// Retrieves the receiving node for a `msg` and hands over the payload.
    #[inline]
    pub fn dispatch_message<R: Rng>(
        &mut self,
        msg: NetMessage<D>,
        rng: &mut R,
    ) -> Result<DaStep<D>, CrankError<D>> {
        let node = self
            .nodes
            .get_mut(&msg.to)
            .ok_or_else(|| CrankError::NodeDisappearedInDispatch(msg.to.clone()))?;

        // Store a copy of the message, in case we need to pass it to the error variant.
        // By reducing the information in `CrankError::HandleMessage`, we could reduce overhead
        // here if necessary.
        let msg_copy = msg.clone();
        let step = node
            .algorithm
            .handle_message(&msg.from, msg.payload, rng)
            .map_err(move |err| CrankError::HandleMessage { msg: msg_copy, err })?;

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
    pub fn send_input<R: Rng>(
        &mut self,
        id: D::NodeId,
        input: D::Input,
        rng: &mut R,
    ) -> Result<DaStep<D>, CrankError<D>> {
        let step = self
            .nodes
            .get_mut(&id)
            .expect("cannot handle input on non-existing node")
            .algorithm
            .handle_input(input, rng)
            .map_err(CrankError::HandleInput)?;
        self.process_step(id, &step)?;
        Ok(step)
    }

    /// Processes a step of a given node. The results of the processing are stored internally in the
    /// test network.
    #[must_use = "The result of processing a step must be used."]
    pub fn process_step(&mut self, id: D::NodeId, step: &DaStep<D>) -> Result<(), CrankError<D>> {
        self.message_count = self.message_count.saturating_add(process_step(
            &mut self.nodes,
            id,
            step,
            &mut self.messages,
            self.error_on_fault,
        )?);
        Ok(())
    }

    /// Advance the network.
    ///
    /// Picks a message to deliver, delivers it and returns the handling node's ID and the result
    /// of the message handling. If the network message queue is empty, returns `None`.
    ///
    /// If a successful `Step` was generated, all of its messages are queued on the network and the
    /// `Step` is returned.
    #[inline]
    pub fn crank<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Option<Result<(D::NodeId, DaStep<D>), CrankError<D>>> {
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
            adversary.pre_crank(adversary::NetMutHandle::new(self), rng)
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
        let is_faulty = try_some!(self
            .nodes
            .get(&msg.to)
            .ok_or_else(|| CrankError::NodeDisappearedInCrank(msg.to.clone())))
        .is_faulty();

        let step: Step<_, _, _, _> = if is_faulty {
            // The swap-dance is painful here, as we are creating an `opt_step` just to avoid
            // borrow issues.
            let mut adv = self.adversary.take();
            let opt_tamper_result = adv.as_mut().map(|adversary| {
                // If an adversary was set, we let it affect the network now.
                adversary.tamper(adversary::NetMutHandle::new(self), msg, rng)
            });
            self.adversary = adv;

            // A missing adversary here could technically be a panic, but is impossible since we
            // initialize with a `NullAdversary` upon construction.
            try_some!(
                opt_tamper_result.expect("No adversary defined (expected at least NullAdversary)")
            )
        } else {
            // A correct node simply handles the message.
            try_some!(self.dispatch_message(msg, rng))
        };

        // All messages are expanded and added to the queue. We opt for copying them, so we can
        // return unaltered step later on for inspection.
        try_some!(self.process_step(receiver.clone(), &step));

        // Increase the crank count.
        self.crank_count += 1;

        Some(Ok((receiver, step)))
    }

    /// Convenience function for cranking.
    ///
    /// Shortcut for cranking the network, expecting both progress to be made as well as processing
    /// to proceed.
    pub fn crank_expect<R: Rng>(&mut self, rng: &mut R) -> (D::NodeId, DaStep<D>) {
        self.crank(rng)
            .expect("crank: network queue empty")
            .expect("crank: node failed to process step")
    }
}

impl<D, A> VirtualNet<D, A>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Input: Clone,
    D::Output: Clone,
    A: Adversary<D>,
{
    /// Send input to all nodes.
    ///
    /// Equivalent to sending the same input to all nodes in order. Returns a vector of the
    /// resulting `Step`s, which have had their messages queued already.
    ///
    /// If an error occurs, the first error is returned and broadcasting aborted.
    #[inline]
    pub fn broadcast_input<'a, R: Rng>(
        &'a mut self,
        input: &'a D::Input,
        rng: &mut R,
    ) -> Result<Vec<(D::NodeId, DaStep<D>)>, CrankError<D>> {
        let steps: Vec<_> = self
            .nodes
            .values_mut()
            .map(move |node| {
                Ok((
                    node.id().clone(),
                    node.algorithm
                        .handle_input(input.clone(), rng)
                        .map_err(CrankError::HandleInputAll)?,
                ))
            })
            .collect::<Result<_, _>>()?;

        // Process all messages from all steps in the queue.
        for (id, step) in &steps {
            self.process_step(id.clone(), step)?;
        }

        Ok(steps)
    }
}

impl<C, D, N, A> VirtualNet<D, A>
where
    D: DistAlgorithm<NodeId = N, Output = Batch<C, N>>,
    D::Message: Clone,
    A: Adversary<D>,
    C: Contribution + Clone,
    N: NodeIdT,
{
    /// Verifies that all nodes' outputs agree, given a correct "full" node that output all
    /// batches in a total order and with no gaps.
    ///
    /// The output of the full node is used to derive in expected output of other nodes in every
    /// epoch. After that the check ensures that correct nodes output the same batches in epochs
    /// when those nodes were participants (either validators or candidates).
    pub fn verify_batches<E>(&self, full_node: &Node<D>)
    where
        Batch<C, N>: SenderQueueableOutput<N, E>,
    {
        let mut participants: BTreeSet<N> = self.nodes().map(Node::id).cloned().collect();
        let mut expected: BTreeMap<N, Vec<_>> = BTreeMap::new();
        for batch in &full_node.outputs {
            for id in &participants {
                expected.entry(id.clone()).or_default().push(batch);
            }
            if let Some(new_participants) = batch.participant_change() {
                participants = new_participants;
            }
        }
        for node in self.correct_nodes().filter(|n| n.id() != full_node.id()) {
            assert_eq!(
                node.outputs.len(),
                expected[node.id()].len(),
                "The output length of node {:?} is incorrect",
                node.id()
            );
            assert!(node
                .outputs
                .iter()
                .zip(
                    expected
                        .get(node.id())
                        .expect("outputs don't match the expectation")
                )
                .all(|(a, b)| a.public_eq(b)));
        }
    }
}

impl<D, A> ops::Index<D::NodeId> for VirtualNet<D, A>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>,
{
    type Output = Node<D>;

    #[inline]
    fn index(&self, index: D::NodeId) -> &Self::Output {
        self.get(index).expect("indexed node not found")
    }
}

impl<D, A> ops::IndexMut<D::NodeId> for VirtualNet<D, A>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>,
{
    #[inline]
    fn index_mut(&mut self, index: D::NodeId) -> &mut Self::Output {
        self.get_mut(index).expect("indexed node not found")
    }
}
