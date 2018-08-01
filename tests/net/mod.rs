//! A test network.
//!
//! Test networks simulate a real networking that includes an adversary as well as the plumbing to
//! pass messages back and forth between nodes.
//!
//! Networks are "cranked" to move things forward; each crank of a network causes one message to be
//! delivered to a node.

// FIXME: It would be nice to stick this macro somewhere reusable.
/// Like `try!`, but wraps into an `Option::Some` as well.
macro_rules! try_some {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Some(Err(From::from(e))),
        }
    };
}

pub mod types;

use std::{collections, sync};

pub use self::types::{FaultyMessageIdx, FaultyNodeIdx, MessageIdx, NetworkOp, NodeIdx, OpList};
use hbbft::messaging::{self, DistAlgorithm, NetworkInfo, Step};

#[derive(Debug)]
struct Node<D: DistAlgorithm> {
    netinfo: sync::Arc<NetworkInfo<D::NodeUid>>,
    algorithm: D,
    is_faulty: bool,
}

impl<D: DistAlgorithm> Node<D> {
    #[inline]
    fn is_faulty(&self) -> bool {
        self.is_faulty
    }
    #[inline]
    fn node_id(&self) -> &D::NodeUid {
        self.netinfo.our_uid()
    }
}

// Note: We do not use `messaging::TargetedMessage` and `messaging::SourceMessage` here, since we
//       the nesting is inconvenient and we do not want to support broadcasts at this level.
#[derive(Clone, Debug)]
struct NetworkMessage<M, N> {
    from: N,
    to: N,
    payload: M,
}

impl<M, N> NetworkMessage<M, N> {
    fn new(from: N, payload: M, to: N) -> NetworkMessage<M, N> {
        NetworkMessage { from, to, payload }
    }
}

type NodeMap<D: DistAlgorithm> = collections::BTreeMap<D::NodeUid, Node<D>>;

struct VirtualNet<D>
where
    D: DistAlgorithm,
{
    /// Maps node IDs to actual node instances.
    nodes: NodeMap<D>,
    /// A collection of all network messages queued up for delivery.
    messages: collections::VecDeque<NetworkMessage<D::Message, D::NodeUid>>,
}

#[derive(Debug, Fail)]
enum CrankError<D: DistAlgorithm> {
    #[fail(display = "Node error'd processing network message {:?}. Error: {:?}", msg, err)]
    CorrectNodeErr {
        msg: NetworkMessage<D::Message, D::NodeUid>,
        #[cause]
        err: D::Error,
    },
}

impl<D> VirtualNet<D>
where
    D: DistAlgorithm,
    D::Message: Clone,
{
    #[inline]
    pub fn new(nodes: NodeMap<D>) -> Self {
        VirtualNet {
            nodes,
            messages: collections::VecDeque::new(),
        }
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

    // FIXME: correct return type
    #[inline]
    pub fn crank(&mut self) -> Option<Result<Step<D>, CrankError<D>>> {
        // Missing: Step 0: Give Adversary a chance to do things/

        // Step 1: Pick a message from the queue and deliver it.
        if let Some(msg) = self.messages.pop_front() {
            // Unfortunately, we have to re-borrow the target node further down to make the borrow
            // checker happy. First, we check if the receiving node is faulty, so we can dispatch
            // through the adversary if it is.
            let is_faulty = self.nodes[&msg.to].is_faulty();

            // We always expect a step to be produced (an adversary wanting to swallow a message
            // can do this either in the earlier step or by returning an empty step).
            let step = if is_faulty {
                // FIXME: Messages for faulty nodes are passed to the adversary instead, who can
                // modify them at will.
                unimplemented!()
            } else {
                // While not very performant, we copy every message once and keep it around for
                // better error handling in case something goes wrong. We have to let go of the
                // original message when moving the payload into `handle_message`.
                let msg_copy = msg.clone();

                try_some!(
                    self.nodes
                        .get_mut(&msg.to)
                        .expect("node disappeared during cranking")
                        .algorithm
                        .handle_message(&msg.from, msg.payload)
                        .map_err(move |err| CrankError::CorrectNodeErr { msg: msg_copy, err })
                )
            };

            // All messages are expanded and added to the queue. We opt for copying them, so we can
            // return unaltered step later on for inspection.
            self.process_messages(msg.from, step.messages.iter());
            Some(Ok(step))
        } else {
            // There are no more network messages in the queue.
            None
        }
    }

    // pub fn faulty_nodes(&self) -> impl Iterator<Item = &Node<N>> {
    //     self.nodes.values().filter(|n| n.is_faulty())
    // }

    // fn nth_faulty_node(&self, n: usize) -> Option<&Node<N>> {
    //     let count = self.faulty_nodes().count();
    //     if count == 0 {
    //         return None;
    //     }
    //     self.faulty_nodes().nth(n % count)
    // }

    // pub fn faulty_messages_idxs<'a>(&'a self) -> impl Iterator<Item = usize> + 'a {
    //     self.messages
    //         .iter()
    //         .enumerate()
    //         .filter_map(move |(idx, m)| {
    //             if self.nodes.get(&m.source).expect("node missing").is_faulty() {
    //                 Some(idx)
    //             } else {
    //                 None
    //             }
    //         })
    // }

    // fn nth_faulty_message_idx(&self, n: usize) -> Option<usize> {
    //     let count = self.faulty_messages_idxs().count();
    //     if count == 0 {
    //         return None;
    //     }
    //     self.faulty_messages_idxs().nth(n % count)
    // }

    // pub fn process_op(&mut self, op: NetworkOp<M>) {
    //     match op {
    //         NetworkOp::Swap(MessageIdx(i), MessageIdx(k)) => {
    //             let mlen = self.messages.len();
    //             self.messages.swap(i % mlen, k % mlen);
    //         }
    //         NetworkOp::DropFaulty(FaultyMessageIdx(f)) => {
    //             self.nth_faulty_message_idx(f)
    //                 .map(|idx| self.messages.remove(idx));
    //         }
    //         NetworkOp::InjectFaulty(FaultyNodeIdx(from), NodeIdx(to), msg) => {
    //             // FIXME: We currently have quadratic complexity here, but we will optimize this
    //             //        once access patterns are clear. But for this reason, it is desirable to
    //             //        have short circuiting.

    //             // First, we get the sender...
    //             self.nth_faulty_node(from)
    //                 .map(|n| n.node_id().clone())
    //                 .and_then(|sender| {
    //                     self.nodes
    //                         .keys()
    //                         .nth(to & self.nodes.len())
    //                         .cloned()
    //                         .map(|receiver| (sender, receiver))
    //                 })
    //                 .map(|(sender, receiver)| {
    //                     /// A new message will be added at the end of the queue. To put it in a
    //                     /// different position, a `Swap(...)` operation can be added afterwards.
    //                     self.messages.push_back(messaging::SourcedMessage {
    //                         source: sender,
    //                         message: messaging::TargetedMessage {
    //                             target: messaging::Target::Node(receiver),
    //                             message: msg,
    //                         },
    //                     })
    //                 });
    //         }
    //         NetworkOp::InjectFaultyBroadcast(FaultyNodeIdx(from), msg) => {
    //             self.nth_faulty_node(from)
    //                 .map(|n| n.node_id().clone())
    //                 .map(|sender| {
    //                     self.messages.push_back(messaging::SourcedMessage {
    //                         source: sender,
    //                         message: messaging::TargetedMessage {
    //                             target: messaging::Target::All,
    //                             message: msg,
    //                         },
    //                     })
    //                 });
    //         }
    //         NetworkOp::ReplayFaulty(FaultyMessageIdx(fnode), NodeIdx(to)) => {
    //             // self.nth_faulty_node(fnode)
    //             unimplemented!()
    //         }
    //         _ => unimplemented!(),
    //     }
    // }
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

// impl<D: DistAlgorithm> VirtualNet<N> {
//     fn new(node_ids: &[N]) -> Self {
//         for id in node_ids.into_iter() {}

//         VirtualNet {
//             nodes: BTreeMap::new(),
//             messages: VecDeque::new(),
//         }
//     }

//     // fn create_node(&mut self, node_id: N, secret_key: SecretKey, public_key_set: PublicKeySet) {
//     //     00
//     // }
// }

// struct Message<K, T> {
//     from: K,
//     to: K,
//     payload: T,
// }

// struct VirtualNet<K, N, T> {
//     nodes: HashMap<K, N>,
//     queue: VecDeque<Message<K, T>>,
// }

// impl VirtualNet {
//     fn deliver_message() {}
// }
