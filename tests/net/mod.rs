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
mod macros;

use std::{collections, mem, ops};

// pub use self::types::{FaultyMessageIdx, FaultyNodeIdx, MessageIdx, NetworkOp, NodeIdx, OpList};
use hbbft::messaging::{self, DistAlgorithm, NetworkInfo, Step};

pub use self::adversary::Adversary;
pub use self::err::CrankError;

#[derive(Debug)]
pub struct Node<D: DistAlgorithm> {
    algorithm: D,
    is_faulty: bool,
}

impl<D: DistAlgorithm> Node<D> {
    #[inline]
    pub fn new(algorithm: D, is_faulty: bool) -> Self {
        Node {
            algorithm,
            is_faulty,
        }
    }

    #[inline]
    pub fn is_faulty(&self) -> bool {
        self.is_faulty
    }

    #[inline]
    pub fn id(&self) -> &D::NodeUid {
        self.algorithm.our_id()
    }
}

// Note: We do not use `messaging::TargetedMessage` and `messaging::SourceMessage` here, since we
//       the nesting is inconvenient and we do not want to support broadcasts at this level.
#[derive(Clone, Debug)]
pub struct NetworkMessage<M, N> {
    from: N,
    to: N,
    payload: M,
}

impl<M, N> NetworkMessage<M, N> {
    fn new(from: N, payload: M, to: N) -> NetworkMessage<M, N> {
        NetworkMessage { from, to, payload }
    }
}

pub type NodeMap<D> = collections::BTreeMap<<D as DistAlgorithm>::NodeUid, Node<D>>;
pub type NetMessage<D> =
    NetworkMessage<<D as DistAlgorithm>::Message, <D as DistAlgorithm>::NodeUid>;

pub struct VirtualNet<D>
where
    D: DistAlgorithm,
{
    /// Maps node IDs to actual node instances.
    nodes: NodeMap<D>,
    /// A collection of all network messages queued up for delivery.
    messages: collections::VecDeque<NetMessage<D>>,
    /// An Adversary that controls the network delivery schedule and all faulty nodes. Optional
    /// only when no faulty nodes are defined.
    adversary: Option<Box<dyn Adversary<D>>>,
}

impl<D> VirtualNet<D>
where
    D: DistAlgorithm,
{
    #[inline]
    pub fn new_with_adversary(nodes: NodeMap<D>, adversary: Box<dyn Adversary<D>>) -> Self {
        VirtualNet {
            nodes,
            messages: collections::VecDeque::new(),
            adversary: Some(adversary),
        }
    }

    pub fn new_with_step<F, I>(node_ids: I, faulty: usize, cons: F) -> Self
    where
        F: Fn(D::NodeUid, NetworkInfo<D::NodeUid>) -> (D, Step<D>),
        I: IntoIterator<Item = D::NodeUid>,
    {
        let net_infos = messaging::NetworkInfo::generate_map(node_ids);

        assert!(
            faulty * 3 < net_infos.len(),
            "Too many faulty nodes requested, `f` must satisfy `3f < total_nodes`."
        );

        let mut steps = collections::BTreeMap::new();
        let nodes = net_infos
            .into_iter()
            .enumerate()
            .map(move |(idx, (id, netinfo))| {
                let (algorithm, step) = cons(id.clone(), netinfo);
                steps.insert(id.clone(), step);
                (id, Node::new(algorithm, idx < faulty))
            })
            .collect();

        // TODO: Handle steps.

        VirtualNet {
            nodes,
            messages: collections::VecDeque::new(),
            adversary: None,
        }
    }

    pub fn new<F, I>(node_ids: I, faulty: usize, cons: F) -> Self
    where
        F: Fn(D::NodeUid, NetworkInfo<D::NodeUid>) -> D,
        I: IntoIterator<Item = D::NodeUid>,
    {
        Self::new_with_step(node_ids, faulty, |id, netinfo| {
            (cons(id, netinfo), Default::default())
        })
    }

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
{
    #[inline]
    fn dispatch_message(&mut self, msg: NetMessage<D>) -> Result<Step<D>, CrankError<D>> {
        let node = self.nodes
            .get_mut(&msg.to)
            .ok_or_else(|| CrankError::NodeDisappeared(msg.to.clone()))?;

        // Store a copy of the message, in case we need to pass it to the error variant.
        // By reducing the information in `CrankError::AlgorithmError`, we could reduce overhead
        // here if necessary.
        let msg_copy = msg.clone();
        let step = node.algorithm
            .handle_message(&msg.from, msg.payload)
            .map_err(move |err| CrankError::AlgorithmError { msg: msg_copy, err })?;

        Ok(step)
    }

    // # Panics
    // ...
    #[inline]
    pub fn send_input(&mut self, id: D::NodeUid, input: D::Input) -> Result<Step<D>, D::Error> {
        let step = self.nodes
            .get_mut(&id)
            .expect("cannot handle input on non-existing node")
            .algorithm
            .input(input)?;

        self.process_messages(id, step.messages.iter());

        Ok(step)
    }

    #[inline]
    fn process_messages<'a, I>(&mut self, sender: D::NodeUid, messages: I)
    where
        D: 'a,
        I: Iterator<Item = &'a messaging::TargetedMessage<D::Message, D::NodeUid>>,
    {
        for tmsg in messages {
            match &tmsg.target {
                messaging::Target::Node(to) => {
                    NetworkMessage::new(sender.clone(), tmsg.message.clone(), to.clone());
                }
                messaging::Target::All => for to in self.nodes.keys() {
                    NetworkMessage::new(sender.clone(), tmsg.message.clone(), to.clone());
                },
            }
        }
    }

    #[inline]
    pub fn crank(&mut self) -> Option<Result<Step<D>, CrankError<D>>> {
        // Step 0: We give the Adversary a chance to affect the network.

        // Swap the adversary out with a dummy, to get around ownership restrictions.
        let mut adv = mem::replace(&mut self.adversary, None);
        if let Some(ref mut adversary) = adv {
            // If an adversary was set, we let it affect the network now.
            adversary.pre_crank(self)
        }
        mem::replace(&mut self.adversary, adv);

        // Step 1: Pick a message from the queue and deliver it.
        if let Some(msg) = self.messages.pop_front() {
            let sender = msg.from.clone();

            // Unfortunately, we have to re-borrow the target node further down to make the borrow
            // checker happy. First, we check if the receiving node is faulty, so we can dispatch
            // through the adversary if it is.
            let is_faulty = try_some!(
                self.nodes
                    .get(&msg.to)
                    .ok_or_else(|| CrankError::NodeDisappeared(msg.to.clone()))
            ).is_faulty();

            let step: Step<_> = if is_faulty {
                let receiver = msg.to.clone();

                // The swap-dance is painful here, as we are creating an `opt_step` just to avoid
                // borrow issues.
                let mut adv = mem::replace(&mut self.adversary, None);
                let opt_tamper_result = adv.as_mut().map(|adversary| {
                    // If an adversary was set, we let it affect the network now.
                    adversary.tamper(self, msg)
                });
                mem::replace(&mut self.adversary, adv);

                // An error will be returned here, if the adversary was missing.
                let tamper_result = try_some!(
                    opt_tamper_result.ok_or_else(|| CrankError::FaultyNodeButNoAdversary(receiver))
                );

                // A missing adversary here could technically be a panic, as it is almost always
                // a programming error. Since it can occur fairly far down the stack, it's
                // reported using as a regular `Err` here, to allow carrying more context.
                try_some!(tamper_result)
            } else {
                // A correct node simply handles the message.
                try_some!(self.dispatch_message(msg))
            };

            // All messages are expanded and added to the queue. We opt for copying them, so we can
            // return unaltered step later on for inspection.
            self.process_messages(sender, step.messages.iter());
            Some(Ok(step))
        } else {
            // There are no more network messages in the queue.
            None
        }
    }
}

impl<D> VirtualNet<D>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Input: Clone,
{
    #[inline]
    pub fn broadcast_input<'a>(
        &'a mut self,
        input: &'a D::Input,
    ) -> impl Iterator<Item = Result<Step<D>, D::Error>> + 'a {
        // Note: The tricky lifetime annotation basically says that the input value given must
        //       live as long as the iterator returned lives (because it is cloned on every step,
        //       with steps only evaluated each time `next()` is called. For the same reason the
        //       network should not go away ealier either.
        self.nodes.values_mut().map(move |node| {
            let step = node.algorithm.input(input.clone())?;
            self.process_messages(*node.id(), step.messages.iter());
            Ok(step)
        })
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
/// while let Some(rstep) = net.step() {
///     // `net` can still be mutable borrowed here.
/// }
/// ```
impl<D> Iterator for VirtualNet<D>
where
    D: DistAlgorithm,
    D::Message: Clone,
{
    type Item = Result<Step<D>, CrankError<D>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.crank()
    }
}
