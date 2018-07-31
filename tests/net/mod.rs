use hbbft::messaging;

use std::collections;

pub mod types;

pub use self::types::{FaultyMessageIdx, FaultyNodeIdx, MessageIdx, NetworkOp, NodeIdx, OpList};

#[derive(Debug)]
struct Node<N> {
    client_info: messaging::NetworkInfo<N>,
    is_faulty: bool,
}

impl<N> Node<N> {
    #[inline]
    fn is_faulty(&self) -> bool {
        self.is_faulty
    }
}

impl<N: Ord + Clone> Node<N> {
    #[inline]
    fn node_id(&self) -> &N {
        self.client_info.our_uid()
    }
}

type NetworkMessage<M, N> = messaging::SourcedMessage<messaging::TargetedMessage<M, N>, N>;
type NodeMap<N> = collections::BTreeMap<N, Node<N>>;

// type NetworkMessage<D: messaging::DistAlgorithm> =
//     messaging::SourcedMessage<messaging::TargetedMessage<D::Message, D::NodeUid>, D::NodeUid>;

// impl<N> Node<N> {
//     fn new(id: N) -> Node<N> {
//         let client_info = messaging::NetworkInfo::new{

//         };
//         Node{
//             client_info
//         }
//     }
// }

// struct SimpleNetwork<D: messaging::DistAlgorithm> {
//     nodes: BTreeMap<D::NodeUid, Node<D::NodeUid>>,
//     messages: VecDeque<NetworkMessage<D>>,
// }
struct SimpleNetwork<M, N> {
    nodes: NodeMap<N>,
    messages: collections::VecDeque<NetworkMessage<M, N>>,
}

// FIXME: Remove clone (only used for process_op)
impl<M, N: Ord + Clone> SimpleNetwork<M, N> {
    pub fn new(nodes: NodeMap<N>) -> Self {
        SimpleNetwork {
            nodes,
            messages: collections::VecDeque::new(),
        }
    }

    pub fn faulty_nodes(&self) -> impl Iterator<Item = &Node<N>> {
        self.nodes.values().filter(|n| n.is_faulty())
    }

    fn nth_faulty_node(&self, n: usize) -> Option<&Node<N>> {
        let count = self.faulty_nodes().count();
        if count == 0 {
            return None;
        }
        self.faulty_nodes().nth(n % count)
    }

    pub fn faulty_messages_idxs<'a>(&'a self) -> impl Iterator<Item = usize> + 'a {
        self.messages
            .iter()
            .enumerate()
            .filter_map(move |(idx, m)| {
                if self.nodes.get(&m.source).expect("node missing").is_faulty() {
                    Some(idx)
                } else {
                    None
                }
            })
    }

    fn nth_faulty_message_idx(&self, n: usize) -> Option<usize> {
        let count = self.faulty_messages_idxs().count();
        if count == 0 {
            return None;
        }
        self.faulty_messages_idxs().nth(n % count)
    }

    pub fn process_op(&mut self, op: NetworkOp<M>) {
        match op {
            NetworkOp::Swap(MessageIdx(i), MessageIdx(k)) => {
                let mlen = self.messages.len();
                self.messages.swap(i % mlen, k % mlen);
            }
            NetworkOp::DropFaulty(FaultyMessageIdx(f)) => {
                self.nth_faulty_message_idx(f)
                    .map(|idx| self.messages.remove(idx));
            }
            NetworkOp::InjectFaulty(FaultyNodeIdx(from), NodeIdx(to), msg) => {
                // FIXME: We currently have quadratic complexity here, but we will optimize this
                //        once access patterns are clear. But for this reason, it is desirable to
                //        have short circuiting.

                // First, we get the sender...
                self.nth_faulty_node(from)
                    .map(|n| n.node_id().clone())
                    .and_then(|sender| {
                        self.nodes
                            .keys()
                            .nth(to & self.nodes.len())
                            .cloned()
                            .map(|receiver| (sender, receiver))
                    })
                    .map(|(sender, receiver)| {
                        /// A new message will be added at the end of the queue. To put it in a
                        /// different position, a `Swap(...)` operation can be added afterwards.
                        self.messages.push_back(messaging::SourcedMessage {
                            source: sender,
                            message: messaging::TargetedMessage {
                                target: messaging::Target::Node(receiver),
                                message: msg,
                            },
                        })
                    });
            }
            NetworkOp::InjectFaultyBroadcast(FaultyNodeIdx(from), msg) => {
                self.nth_faulty_node(from)
                    .map(|n| n.node_id().clone())
                    .map(|sender| {
                        self.messages.push_back(messaging::SourcedMessage {
                            source: sender,
                            message: messaging::TargetedMessage {
                                target: messaging::Target::All,
                                message: msg,
                            },
                        })
                    });
            }
            NetworkOp::ReplayFaulty(FaultyMessageIdx(fnode), NodeIdx(to)) => {
                // self.nth_faulty_node(fnode)
                unimplemented!()
            }
            _ => unimplemented!(),
        }
    }
}

// impl<D: messaging::DistAlgorithm> SimpleNetwork<N> {
//     fn new(node_ids: &[N]) -> Self {
//         for id in node_ids.into_iter() {}

//         SimpleNetwork {
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

// struct SimpleNetwork<K, N, T> {
//     nodes: HashMap<K, N>,
//     queue: VecDeque<Message<K, T>>,
// }

// impl SimpleNetwork {
//     fn deliver_message() {}
// }
