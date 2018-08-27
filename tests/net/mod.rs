//! A test network.
//!
//! Test networks simulate a real networking that includes an adversary as well as the plumbing to
//! pass messages back and forth between nodes.
//!
//! Networks are "cranked" to move things forward; each crank of a network causes one message to be
//! delivered to a node.

// pub mod types;
pub mod adversary;
pub mod err;
#[macro_use]
pub mod util;

use std::io::Write;
use std::{collections, env, fs, io, mem, ops, process};

use rand;
use rand::Rand;
use threshold_crypto as crypto;

// pub use self::types::{FaultyMessageIdx, FaultyNodeIdx, MessageIdx, NetworkOp, NodeIdx, OpList};
use hbbft::messaging::{self, DistAlgorithm, NetworkInfo, Step};

pub use self::adversary::Adversary;
pub use self::err::CrankError;

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

    let exec_path = env::current_exe();
    let name = format!(
        "net-trace_{}_{}_{}.txt",
        exec_path.map(|pb| pb
            .file_name()
            .expect("could not get executable filename")
            .to_string_lossy()
            .into_owned())?,
        process::id(),
        u16::rand(&mut rng),
    );

    Ok(io::BufWriter::new(fs::File::create(name)?))
}

/// A node in the test network.
#[derive(Debug)]
pub struct Node<D: DistAlgorithm> {
    /// Algorithm instance of node.
    algorithm: D,
    /// Whether or not the node is faulty.
    is_faulty: bool,
    /// Captured algorithm outputs, in order.
    outputs: Vec<D::Output>,
}

impl<D: DistAlgorithm> Node<D> {
    /// Create a new node.
    #[inline]
    fn new(algorithm: D, is_faulty: bool) -> Self {
        Node {
            algorithm,
            is_faulty,
            outputs: Vec::new(),
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

    /// Get nodes ID.
    ///
    /// A node's ID is equal to its underlying algorithm instance's ID.
    #[inline]
    pub fn id(&self) -> &D::NodeUid {
        self.algorithm.our_id()
    }

    /// List outputs so far.
    ///
    /// Any output made by a node is captured by the node for easy comparison.
    pub fn outputs(&self) -> &[D::Output] {
        self.outputs.as_slice()
    }
}

/// A network message on the virtual network.
// Note: We do not use `messaging::TargetedMessage` and `messaging::SourceMessage` here, since we
//       the nesting is inconvenient and we do not want to support broadcasts at this level.
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
    fn new(from: N, payload: M, to: N) -> NetworkMessage<M, N> {
        NetworkMessage { from, to, payload }
    }
}

/// Mapping from node IDs to actual node instances.
pub type NodeMap<D> = collections::BTreeMap<<D as DistAlgorithm>::NodeUid, Node<D>>;

/// A virtual network message tied to a distributed algorithm.
pub type NetMessage<D> =
    NetworkMessage<<D as DistAlgorithm>::Message, <D as DistAlgorithm>::NodeUid>;

/// Process a step.
///
/// Expands every message in the step by turning all broadcast-messages into peer-to-peer messages,
/// and appends them to the network queue. Additionally, saves a copy of each output to the output
/// buffer of the `sender` node.
///
/// At the end, the number of additional messages created by non-faulty nodes will be returned.
///
/// # Panics
///
/// The function will panic if the `sender` ID is not a valid node ID in `nodes`.
// This function is defined outside `VirtualNet` and takes arguments "piecewise" to work around
// borrow-checker restrictions.
#[inline]
fn process_step<'a, D>(
    nodes: &'a mut collections::BTreeMap<D::NodeUid, Node<D>>,
    sender: D::NodeUid,
    step: &Step<D>,
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
    for tmsg in step.messages.iter() {
        match &tmsg.target {
            /// Single target message.
            messaging::Target::Node(to) => {
                if !faulty {
                    message_count = message_count.saturating_add(1);
                }

                dest.push_back(NetworkMessage::new(
                    sender.clone(),
                    tmsg.message.clone(),
                    to.clone(),
                ));
            }
            /// Broadcast messages get expanded into multiple direct messages.
            messaging::Target::All => for to in nodes.keys() {
                if *to == sender {
                    continue;
                }

                if !faulty {
                    message_count = message_count.saturating_add(1);
                }

                dest.push_back(NetworkMessage::new(
                    sender.clone(),
                    tmsg.message.clone(),
                    to.clone(),
                ));
            },
        }
    }

    // Collect all outputs (not required for network operation) as a convenience for the user.
    nodes
        .get_mut(&sender)
        .expect("Trying to process a step with non-existing node ID")
        .outputs
        .extend(step.output.iter().cloned());

    message_count
}

/// Virtual network builder.
pub struct NetBuilder<D, I>
where
    D: DistAlgorithm,
{
    /// Iterator used to create node ids.
    node_ids: I,
    /// Number of faulty nodes in the network.
    num_faulty: usize,
    /// Constructor function.
    cons: Option<Box<Fn(D::NodeUid, NetworkInfo<D::NodeUid>) -> (D, Step<D>)>>,
    adversary: Option<Box<dyn Adversary<D>>>,
    trace: Option<bool>,
    crank_limit: Option<usize>,
    message_limit: Option<usize>,
}

impl<D, I> NetBuilder<D, I>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
    I: IntoIterator<Item = D::NodeUid>,
{
    #[inline]
    pub fn new(node_ids: I) -> Self {
        NetBuilder {
            node_ids: node_ids,
            num_faulty: 0,
            cons: None,
            adversary: None,
            trace: None,
            crank_limit: None,
            message_limit: None,
        }
    }

    #[inline]
    pub fn adversary<A>(mut self, adversary: A) -> Self
    where
        A: Adversary<D> + 'static,
    {
        self.adversary = Some(Box::new(adversary));
        self
    }

    #[inline]
    pub fn crank_limit(mut self, crank_limit: usize) -> Self {
        self.crank_limit = Some(crank_limit);
        self
    }

    #[inline]
    pub fn message_limit(mut self, message_limit: usize) -> Self {
        self.message_limit = Some(message_limit);
        self
    }

    #[inline]
    pub fn num_faulty(mut self, num_faulty: usize) -> Self {
        self.num_faulty = num_faulty;
        self
    }

    #[inline]
    pub fn trace(mut self, trace: bool) -> Self {
        self.trace = Some(trace);
        self
    }

    #[inline]
    pub fn using_step<F>(mut self, cons: F) -> Self
    where
        F: Fn(D::NodeUid, NetworkInfo<D::NodeUid>) -> (D, Step<D>) + 'static,
    {
        self.cons = Some(Box::new(cons));
        self
    }

    #[inline]
    pub fn using<F>(self, cons_simple: F) -> Self
    where
        F: Fn(D::NodeUid, NetworkInfo<D::NodeUid>) -> D + 'static,
    {
        self.using_step(move |id, netinfo| (cons_simple(id, netinfo), Default::default()))
    }

    #[inline]
    pub fn build(self) -> Result<VirtualNet<D>, crypto::error::Error> {
        let cons = self
            .cons
            .as_ref()
            .expect("cannot build network without a constructor function for the nodes");

        let mut net = VirtualNet::new(self.node_ids, self.num_faulty, move |id, info| {
            cons(id, info)
        })?;

        if self.adversary.is_some() {
            net.adversary = self.adversary;
        }

        let trace = self.trace.unwrap_or_else(|| {
            // If the trace setting is not overriden, we use the setting from the environment.
            let setting = env::var("HBBFT_TEST_TRACE").unwrap_or("true".to_string());
            !(setting == "false" || setting == "0")
        });

        if trace {
            net.trace = Some(open_trace().expect("could not open trace file"));
        }

        net.crank_limit = self.crank_limit;
        net.message_limit = self.message_limit;

        Ok(net)
    }
}

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
}

/// A virtual network
///
/// Virtual networks host a number of nodes that are marked either correct or faulty. Each time the
/// node emits a `Step`, the contained messages are queued for delivery, which happens whenever
/// `crank()` is called.
///
/// An adversary can be hooked into the network to affect the order of message delivery or the
/// behaviour of faulty nodes.
impl<D> VirtualNet<D>
where
    D: DistAlgorithm,
{
    #[inline]
    pub fn nodes(&self) -> impl Iterator<Item = &Node<D>> {
        self.nodes.values()
    }

    #[inline]
    pub fn faulty_nodes(&self) -> impl Iterator<Item = &Node<D>> {
        self.nodes().filter(|n| n.is_faulty())
    }

    #[inline]
    pub fn correct_nodes(&self) -> impl Iterator<Item = &Node<D>> {
        self.nodes().filter(|n| !n.is_faulty())
    }

    #[inline]
    pub fn get<'a>(&'a self, id: D::NodeUid) -> Option<&'a Node<D>> {
        self.nodes.get(&id)
    }

    #[inline]
    pub fn get_mut<'a>(&'a mut self, id: D::NodeUid) -> Option<&'a mut Node<D>> {
        self.nodes.get_mut(&id)
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
    /// # Panics
    ///
    /// The total number of nodes, that is `node_ids.count()` must be `> 3 * faulty`, otherwise
    /// the construction function will panic.
    fn new<F, I>(node_ids: I, faulty: usize, cons: F) -> Result<Self, crypto::error::Error>
    where
        F: Fn(D::NodeUid, NetworkInfo<D::NodeUid>) -> (D, Step<D>),
        I: IntoIterator<Item = D::NodeUid>,
    {
        // Generate a new set of cryptographic keys for threshold cryptography.
        let net_infos = messaging::NetworkInfo::generate_map(node_ids)?;

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
                let (algorithm, step) = cons(id.clone(), netinfo);
                steps.insert(id.clone(), step);
                (id, Node::new(algorithm, idx < faulty))
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
        })
    }

    #[inline]
    fn dispatch_message(&mut self, msg: NetMessage<D>) -> Result<Step<D>, CrankError<D>> {
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

    /// Send input to a specific node
    ///
    /// Sends the specified `input` to the respective node identified by `id`. The messages of the
    /// resulting `step` are added to the network's queue.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not name a valid node.
    #[inline]
    pub fn send_input(&mut self, id: D::NodeUid, input: D::Input) -> Result<Step<D>, D::Error> {
        let step = self
            .nodes
            .get_mut(&id)
            .expect("cannot handle input on non-existing node")
            .algorithm
            .input(input)?;

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
    pub fn crank(&mut self) -> Option<Result<(D::NodeUid, Step<D>), CrankError<D>>> {
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

        // Step 0: We give the Adversary a chance to affect the network.

        // Swap the adversary out with a dummy, to get around ownership restrictions.
        let mut adv = mem::replace(&mut self.adversary, None);
        if let Some(ref mut adversary) = adv {
            // If an adversary was set, we let it affect the network now.
            adversary.pre_crank(self)
        }
        mem::replace(&mut self.adversary, adv);

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

        let step: Step<_> = if is_faulty {
            // The swap-dance is painful here, as we are creating an `opt_step` just to avoid
            // borrow issues.
            let mut adv = mem::replace(&mut self.adversary, None);
            let opt_tamper_result = adv.as_mut().map(|adversary| {
                // If an adversary was set, we let it affect the network now.
                adversary.tamper(self, msg)
            });
            mem::replace(&mut self.adversary, adv);

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
    /// If an error occurs, the first error will be returned and broadcasting aborted.
    #[inline]
    pub fn broadcast_input<'a>(
        &'a mut self,
        input: &'a D::Input,
    ) -> Result<Vec<(D::NodeUid, Step<D>)>, D::Error> {
        // Note: The tricky lifetime annotation basically says that the input value given must
        //       live as long as the iterator returned lives (because it is cloned on every step,
        //       with steps only evaluated each time `next()` is called. For the same reason the
        //       network should not go away ealier either.

        let steps: Vec<_> = self
            .nodes
            .values_mut()
            .map(move |node| Ok((node.id().clone(), node.algorithm.input(input.clone())?)))
            .collect::<Result<_, _>>()?;

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

impl<D> ops::Index<D::NodeUid> for VirtualNet<D>
where
    D: DistAlgorithm,
{
    type Output = Node<D>;

    #[inline]
    fn index(&self, index: D::NodeUid) -> &Self::Output {
        self.get(index).expect("indexed node not found")
    }
}

impl<D> ops::IndexMut<D::NodeUid> for VirtualNet<D>
where
    D: DistAlgorithm,
{
    #[inline]
    fn index_mut(&mut self, index: D::NodeUid) -> &mut Self::Output {
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
    type Item = Result<(D::NodeUid, Step<D>), CrankError<D>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.crank()
    }
}
