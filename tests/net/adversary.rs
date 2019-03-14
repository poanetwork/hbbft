//! Adversaries for test networks
//!
//! Adversaries can alter message ordering, inject messages and control the behavior of any faulty
//! node. These functions are handled through callbacks, implemented individually by each adversary.
//!
//! This module contains algorithm-agnostic adversaries, which should work for (or rather, against)
//! any `ConsensusProtocol`. Specific adversaries tailored to individual algorithms are implemented
//! alongside their other test cases.
//!
//! ## Adversary model
//!
//! The adversary is assumed to have the following capabilities:
//!
//! 1. Manipulation of the order in which messages are delivered.
//! 1. Eavesdropping on any message on the wire, regardless of sender or receiver.
//! 1. Full control over any node marked as faulty.
//!
//! As a consequence, injecting arbitrary messages from faulty nodes into the network is possible,
//! by sending a message and re-ordering it.
//!
//! The following capabilities are explicitly not included:
//!
//! 1. Dropping of messages. The networking layer is expected to ensure that no messages
//!    are lost. A node that drops messages regardless is considered faulty in real-world
//!    deployments.
//! 1. Forging message senders. The networking layer is also expected to sign messages and ensure
//!    that they are not forged.
//!
//! ## Handles
//!
//! The adversary manipulates the network and nodes exclusively through handles that ensure they do
//! not violate the constraints defined above. Handles are either mutable or immutable and can, in
//! some cases be upgraded to actual references, if the underlying node is faulty (see
//! `NodeHandle::node()` and `NodeHandle::node_mut()`).

use std::cmp;
use std::collections::VecDeque;

use rand::Rng;

use hbbft::{ConsensusProtocol, CpStep};

use crate::net::util::randomly;
use crate::net::{CrankError, NetMessage, NetworkMessage, Node, VirtualNet};

/// Immutable network handle.
///
/// Allows querying public information of the network or getting immutable handles to any node.
#[derive(Debug)]
pub struct NetHandle<'a, D, A>(&'a VirtualNet<D, A>)
where
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>;

impl<'a, D: 'a, A> NetHandle<'a, D, A>
where
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>,
{
    /// Returns a node handle iterator over all nodes in the network.
    #[inline]
    pub fn nodes(&self) -> impl Iterator<Item = NodeHandle<'_, D>> {
        self.0.nodes().map(NodeHandle::new)
    }

    /// Returns an iterator over all faulty nodes in the network.
    ///
    /// Instead of a handle, returns the node directly, as the adversary gets full access to all
    /// nodes in the network.
    #[inline]
    pub fn faulty_nodes(&self) -> impl Iterator<Item = &Node<D>> {
        // FIXME: Add an API to handle a step?
        // Not wrapped in a `NodeHandle`, the adversary gets full access to their own nodes.
        self.0.faulty_nodes()
    }

    /// Returns a node handle iterator over all correct nodes in the network.
    #[inline]
    pub fn correct_nodes(&self) -> impl Iterator<Item = NodeHandle<'_, D>> {
        self.0.correct_nodes().map(NodeHandle::new)
    }

    /// Returns an iterator over all messages in the network.
    #[inline]
    pub fn messages(&'a self) -> impl Iterator<Item = &'a NetMessage<D>> {
        self.0.messages()
    }

    /// Returns a handle to a specific node handle.
    #[inline]
    pub fn get(&self, id: D::NodeId) -> Option<NodeHandle<'_, D>> {
        self.0.get(id).map(NodeHandle::new)
    }
}

/// Insert-position for networking queue.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QueuePosition {
    /// Front of the queue (equivalent to `Before(0)`).
    Front,
    /// Back of the queue.
    Back,
    /// Before a specific a position.
    Before(usize),
}

/// Mutable network handle.
///
/// Allows reordering of messages, injecting new ones into the network queue and getting mutable
/// handles to nodes.
#[derive(Debug)]
pub struct NetMutHandle<'a, D, A>(&'a mut VirtualNet<D, A>)
where
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>;

impl<'a, D, A> NetMutHandle<'a, D, A>
where
    D: ConsensusProtocol,
    A: Adversary<D>,
    D::NodeId: Clone,
    D::Message: Clone,
    D::Output: Clone,
{
    pub fn new(net: &'a mut VirtualNet<D, A>) -> Self {
        NetMutHandle(net)
    }

    /// Returns a mutable node handle iterator over all nodes in the network.
    #[inline]
    pub fn nodes_mut(&mut self) -> impl Iterator<Item = NodeMutHandle<'_, D>> {
        self.0.nodes_mut().map(NodeMutHandle::new)
    }

    /// Returns an iterator that allows changes to all faulty nodes in the network.
    ///
    /// Instead of a handle, returns the node directly, as the adversary gets full access to all
    /// nodes in the network.
    #[inline]
    pub fn faulty_nodes_mut(&mut self) -> impl Iterator<Item = &mut Node<D>> {
        self.0.faulty_nodes_mut()
    }

    /// Returns a mutable node handle iterator over all nodes in the network.
    #[inline]
    pub fn correct_nodes_mut(&mut self) -> impl Iterator<Item = NodeMutHandle<'_, D>> {
        self.0.correct_nodes_mut().map(NodeMutHandle::new)
    }

    /// Normally dispatch a message
    pub fn dispatch_message<R: Rng>(
        &mut self,
        msg: NetMessage<D>,
        rng: &mut R,
    ) -> Result<CpStep<D>, CrankError<D>> {
        self.0.dispatch_message(msg, rng)
    }

    /// Injects a message into the network.
    ///
    /// Allows the injection of `msg` at `position` into the message queue.
    ///
    /// # Panics
    ///
    /// Panics if `msg.from` is not a faulty node or either `msg.from` or `msg.to` do not exist.
    /// Panics if `position` is equal to `Before(idx)`, with `idx` being out of bounds.
    #[inline]
    pub fn inject_message(&mut self, position: QueuePosition, msg: NetMessage<D>) {
        // Ensure the source node is faulty.
        assert!(
            self.0
                .get(msg.from.clone())
                .expect("inject: unknown sender node")
                .is_faulty(),
            "Tried to inject message not originating from a faulty node."
        );

        // Sender must exist.
        self.0
            .get(msg.to.clone())
            .expect("inject: unknown recipient node");

        // Insert into queue. `insert` will panic on out-of-bounds.
        match position {
            QueuePosition::Front => self.0.messages.push_front(msg),
            QueuePosition::Back => self.0.messages.push_back(msg),
            QueuePosition::Before(idx) => self.0.messages.insert(idx, msg),
        }
    }

    /// Swap two messages in the message queue.
    ///
    /// # Panics
    ///
    /// Panics if either `i` or `j` are out-of-bounds.
    #[inline]
    pub fn swap_messages(&mut self, i: usize, j: usize) {
        self.0.swap_messages(i, j);
    }

    /// Reorder all messages.
    ///
    /// Sorts all message with a comparator function.
    ///
    /// Sorting is not cheap, but not prohitibively so, since message queues tend to be small for
    /// most test cases. See `VirtualNet::sort_messages_by` for notes about sorting efficiency.
    #[inline]
    pub fn sort_messages_by<F>(&mut self, f: F)
    where
        F: FnMut(&NetMessage<D>, &NetMessage<D>) -> cmp::Ordering,
    {
        self.0.sort_messages_by(f)
    }

    /// Returns a reference to the queue of messages
    #[inline]
    pub fn get_messages(&self) -> &VecDeque<NetMessage<D>> {
        &self.0.messages
    }
}

// Downgrade-conversion.
impl<'a, D, A> From<NetMutHandle<'a, D, A>> for NetHandle<'a, D, A>
where
    D: ConsensusProtocol,
    A: Adversary<D>,
    D::Message: Clone,
    D::Output: Clone,
{
    #[inline]
    fn from(n: NetMutHandle<'_, D, A>) -> NetHandle<'_, D, A> {
        NetHandle(n.0)
    }
}

/// Immutable node handle.
#[derive(Debug)]
pub struct NodeHandle<'a, D>(&'a Node<D>)
where
    D: ConsensusProtocol;

impl<'a, D> NodeHandle<'a, D>
where
    D: ConsensusProtocol,
{
    /// Construct a new immutable node handle.
    #[inline]
    fn new(inner: &'a Node<D>) -> Self {
        NodeHandle(inner)
    }

    /// Return node ID.
    #[inline]
    pub fn id(&self) -> D::NodeId {
        self.0.id().clone()
    }

    /// Returns a reference to the faulty node.
    ///
    /// # Panics
    ///
    /// Panics if the node is not faulty.
    #[inline]
    pub fn node(&self) -> &'a Node<D> {
        self.try_node()
            .expect("could not access inner node of handle, node is not faulty")
    }

    /// If the inner node is faulty, returns a reference to it.
    #[inline]
    pub fn try_node(&self) -> Option<&'a Node<D>> {
        if self.0.is_faulty() {
            Some(self.0)
        } else {
            None
        }
    }
}

/// Mutable node handle.
#[derive(Debug)]
pub struct NodeMutHandle<'a, D>(&'a mut Node<D>)
where
    D: ConsensusProtocol;

impl<'a, D: 'a> NodeMutHandle<'a, D>
where
    D: ConsensusProtocol,
{
    /// Construct a new mutable node handle.
    fn new(inner: &'a mut Node<D>) -> Self {
        NodeMutHandle(inner)
    }

    /// Return node ID.
    #[inline]
    pub fn id(&self) -> D::NodeId {
        self.0.id().clone()
    }

    /// Returns a mutable reference to the faulty node.
    ///
    /// # Panics
    ///
    /// Panics if the node is not faulty.
    #[inline]
    pub fn node_mut(&'a mut self) -> &'a mut Node<D> {
        self.try_node_mut()
            .expect("could not access inner node of handle, node is not faulty")
    }

    /// If the inner node is faulty, returns a mutable reference to it.
    #[inline]
    pub fn try_node_mut(&mut self) -> Option<&mut Node<D>> {
        if self.0.is_faulty() {
            Some(self.0)
        } else {
            None
        }
    }
}

/// Network adversary.
pub trait Adversary<D>
where
    Self: Sized,
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
{
    /// Pre-crank hook.
    ///
    /// Executed before each crank, the `pre_crank` function allows the adversary to manipulate the
    /// order of network messages by manipulating the `net` parameter.
    ///
    /// The default implementation does not alter the passed network in any way.
    #[inline]
    fn pre_crank<R: Rng>(&mut self, _net: NetMutHandle<'_, D, Self>, _rng: &mut R) {}

    /// Tamper with a faulty node's operation.
    ///
    /// You can (but are not required to) run faulty nodes like regular nodes. However, if a node
    /// is marked faulty, a message is not passed directly to the node. It is handed to 'tamper'
    /// instead.
    ///
    /// The return value replaces what would otherwise have been output by the algorithm, the
    /// returned step is processed normally by the network (messages are queued and outputs
    /// are recorded).
    ///
    /// The default implementation does not perform any tampering, but instead calls
    /// `VirtualNet::dispatch_message`, which results in the message being processed as if the node
    /// was not faulty.
    #[inline]
    fn tamper<R: Rng>(
        &mut self,
        mut net: NetMutHandle<'_, D, Self>,
        msg: NetMessage<D>,
        rng: &mut R,
    ) -> Result<CpStep<D>, CrankError<D>> {
        net.dispatch_message(msg, rng)
    }
}

/// Utility function to sort messages in the given net handle ascending by receiving node id
#[inline]
pub fn sort_ascending<D, A>(net: &mut NetMutHandle<'_, D, A>)
where
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>,
{
    net.sort_messages_by(|a, b| a.to().cmp(&b.to()))
}

/// Utility function to swap the topmost message with a random message in the queue
#[inline]
pub fn swap_random<R, D, A>(net: &mut NetMutHandle<'_, D, A>, rng: &mut R)
where
    R: Rng,
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>,
{
    let l = net.get_messages().len();
    if l > 0 {
        net.swap_messages(0, rng.gen_range(0, l));
    }
}

/// Selects a random node and returns its id
#[inline]
pub fn random_node<R, D, A>(net: &mut NetMutHandle<'_, D, A>, rng: &mut R) -> Option<D::NodeId>
where
    R: Rng,
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>,
{
    let l = net.nodes_mut().count();
    if l > 0 {
        // Pick a node id at random
        return Some(
            net.nodes_mut()
                .nth(rng.gen_range(0, l))
                .expect("nodes list changed since last call")
                .id(),
        );
    }
    None
}

/// Utility function to sweep the messages for a randomly chosen node to the top
/// of the message queue. Relative message order is preserved by using
/// the available stable sort algorithm.
#[inline]
pub fn sort_by_random_node<R, D, A>(net: &mut NetMutHandle<'_, D, A>, rng: &mut R)
where
    R: Rng,
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
    A: Adversary<D>,
{
    if let Some(picked_node) = random_node(net, rng) {
        // To make the picked node's messages sorted to the top of the queue
        // it always has to be less than the others, regardless of its actual id.
        net.sort_messages_by(|a, b| {
            let a = a.to().clone();
            let b = b.to().clone();

            if a == b {
                cmp::Ordering::Equal
            } else if a == picked_node {
                cmp::Ordering::Less
            } else if b == picked_node {
                cmp::Ordering::Greater
            } else {
                a.cmp(&b)
            }
        });
    }
}

/// Passive adversary.
///
/// The `NullAdversary` does not interfere with operation in any way, it neither reorders messages
/// nor tampers with message, passing them through unchanged instead.
#[derive(Debug, Default)]
pub struct NullAdversary;

impl NullAdversary {
    /// Create a new `NullAdversary`.
    #[inline]
    pub fn new() -> Self {
        NullAdversary {}
    }
}

impl<D> Adversary<D> for NullAdversary
where
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
{
}

/// Ascending node id message order adversary.
///
/// An adversary that processes messages in ascending order by the node id that sent the message
/// (i.e. the lowest node IDs always being chosen first).
///
/// Note: This behavior is equivalent to the default scheduling used by the preceding testing
///       framework.
#[derive(Debug, Default)]
pub struct NodeOrderAdversary;

impl NodeOrderAdversary {
    #[inline]
    pub fn new() -> Self {
        NodeOrderAdversary {}
    }
}

impl<D> Adversary<D> for NodeOrderAdversary
where
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
{
    #[inline]
    fn pre_crank<R: Rng>(&mut self, mut net: NetMutHandle<'_, D, Self>, _rng: &mut R) {
        // Message are sorted by NodeID on each step.
        sort_ascending(&mut net);
    }
}

/// Message reordering adversary.
///
/// An adversary that swaps the message at the front of the message queue for a random message
/// within the queue before every `crank`. Thus the order in which messages are received by nodes is
/// random, which allows to test randomized message delivery.
#[derive(Copy, Clone, Debug, Default)]
pub struct ReorderingAdversary {}

impl ReorderingAdversary {
    pub fn new() -> Self {
        ReorderingAdversary {}
    }
}

impl<D> Adversary<D> for ReorderingAdversary
where
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
{
    #[inline]
    fn pre_crank<R: Rng>(&mut self, mut net: NetMutHandle<'_, D, Self>, rng: &mut R) {
        swap_random(&mut net, rng);
    }
}

/// An adversary that performs naive replay attacks.
///
/// The adversary will randomly take a message that is sent to one of its nodes
/// and re-send it to a different node.
///
/// Additionally it will broadcast unrelated random messages,
/// and the message queue by a random node id.
#[derive(Copy, Clone, Debug, Default)]
pub struct RandomAdversary {
    /// Probability of a message replay
    p_replay: f32,
    /// Probability of a message injection
    p_inject: f32,
}

impl RandomAdversary {
    pub fn new(p_replay: f32, p_inject: f32) -> Self {
        RandomAdversary { p_replay, p_inject }
    }
}

impl<D> Adversary<D> for RandomAdversary
where
    D: ConsensusProtocol,
    D::Message: Clone,
    D::Output: Clone,
    rand::distributions::Standard:
        rand::distributions::Distribution<<D as ConsensusProtocol>::Message>,
{
    #[inline]
    fn pre_crank<R: Rng>(&mut self, mut net: NetMutHandle<'_, D, Self>, rng: &mut R) {
        sort_by_random_node(&mut net, rng);
    }

    #[inline]
    fn tamper<R: Rng>(
        &mut self,
        mut net: NetMutHandle<'_, D, Self>,
        msg: NetMessage<D>,
        rng: &mut R,
    ) -> Result<CpStep<D>, CrankError<D>> {
        // only replay a message in some cases
        if randomly(self.p_replay, rng) {
            // randomly choose a target to send the message to
            if let Some(picked_node) = random_node(&mut net, rng) {
                let mut new_msg = msg.clone();
                new_msg.from = new_msg.to;
                new_msg.to = picked_node;
                net.inject_message(QueuePosition::Back, new_msg);
            }
        }

        // Possibly inject more messages
        while randomly(self.p_inject, rng) {
            // Messages must originate from the current node
            let sender = msg.to.clone();
            // Generate a random message
            let message: D::Message = rand::random();

            // Collect receivers
            let node_ids: Vec<<D as ConsensusProtocol>::NodeId> = net
                .nodes_mut()
                .map(|node| node.id())
                .filter(|node_id| *node_id != sender)
                .collect();

            // Broadcast message
            for node_id in node_ids {
                let new_msg = NetworkMessage::new(sender.clone(), message.clone(), node_id);
                net.inject_message(QueuePosition::Back, new_msg);
            }
        }

        net.dispatch_message(msg, rng)
    }
}
