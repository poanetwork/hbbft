use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::rc::Rc;

use rand::{self, Rng};

use hbbft::crypto::{PublicKeySet, SecretKeySet};
use hbbft::messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};

/// A node identifier. In the tests, nodes are simply numbered.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NodeUid(pub usize);

/// A "node" running an instance of the algorithm `D`.
pub struct TestNode<D: DistAlgorithm> {
    /// This node's own ID.
    id: D::NodeUid,
    /// The instance of the broadcast algorithm.
    algo: D,
    /// Incoming messages from other nodes that this node has not yet handled.
    pub queue: VecDeque<(D::NodeUid, D::Message)>,
    /// The values this node has output so far.
    outputs: Vec<D::Output>,
}

impl<D: DistAlgorithm> TestNode<D> {
    /// Returns the list of outputs received by this node.
    pub fn outputs(&self) -> &[D::Output] {
        &self.outputs
    }

    /// Returns whether the algorithm has terminated.
    #[allow(unused)] // Not used in all tests.
    pub fn terminated(&self) -> bool {
        self.algo.terminated()
    }

    /// Inputs a value into the instance.
    pub fn input(&mut self, input: D::Input) {
        self.algo.input(input).expect("input");
        self.outputs.extend(self.algo.output_iter());
    }

    /// Creates a new test node with the given broadcast instance.
    fn new(mut algo: D) -> TestNode<D> {
        let outputs = algo.output_iter().collect();
        TestNode {
            id: algo.our_id().clone(),
            algo,
            queue: VecDeque::new(),
            outputs,
        }
    }

    /// Handles the first message in the node's queue.
    fn handle_message(&mut self) {
        let (from_id, msg) = self.queue.pop_front().expect("message not found");
        debug!("Handling {:?} -> {:?}: {:?}", from_id, self.id, msg);
        self.algo
            .handle_message(&from_id, msg)
            .expect("handling message");
        self.outputs.extend(self.algo.output_iter());
    }
}

/// A strategy for picking the next good node to handle a message.
pub enum MessageScheduler {
    /// Picks a random node.
    Random,
    /// Picks the first non-idle node.
    First,
}

impl MessageScheduler {
    /// Chooses a node to be the next one to handle a message.
    pub fn pick_node<D: DistAlgorithm>(
        &self,
        nodes: &BTreeMap<D::NodeUid, TestNode<D>>,
    ) -> D::NodeUid {
        match *self {
            MessageScheduler::First => nodes
                .iter()
                .find(|(_, node)| !node.queue.is_empty())
                .map(|(id, _)| id.clone())
                .expect("no more messages in queue"),
            MessageScheduler::Random => {
                let ids: Vec<D::NodeUid> = nodes
                    .iter()
                    .filter(|(_, node)| !node.queue.is_empty())
                    .map(|(id, _)| id.clone())
                    .collect();
                rand::thread_rng()
                    .choose(&ids)
                    .expect("no more messages in queue")
                    .clone()
            }
        }
    }
}

pub type MessageWithSender<D> = (
    <D as DistAlgorithm>::NodeUid,
    TargetedMessage<<D as DistAlgorithm>::Message, <D as DistAlgorithm>::NodeUid>,
);

/// An adversary that can control a set of nodes and pick the next good node to receive a message.
pub trait Adversary<D: DistAlgorithm> {
    /// Chooses a node to be the next one to handle a message.
    fn pick_node(&self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid;

    /// Adds a message sent to one of the adversary's nodes.
    fn push_message(&mut self, sender_id: D::NodeUid, msg: TargetedMessage<D::Message, D::NodeUid>);

    /// Produces a list of messages to be sent from the adversary's nodes.
    fn step(&mut self) -> Vec<MessageWithSender<D>>;
}

/// An adversary whose nodes never send any messages.
pub struct SilentAdversary {
    scheduler: MessageScheduler,
}

impl SilentAdversary {
    /// Creates a new silent adversary with the given message scheduler.
    pub fn new(scheduler: MessageScheduler) -> SilentAdversary {
        SilentAdversary { scheduler }
    }
}

impl<D: DistAlgorithm> Adversary<D> for SilentAdversary {
    fn pick_node(&self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid {
        self.scheduler.pick_node(nodes)
    }

    fn push_message(&mut self, _: D::NodeUid, _: TargetedMessage<D::Message, D::NodeUid>) {
        // All messages are ignored.
    }

    fn step(&mut self) -> Vec<MessageWithSender<D>> {
        vec![] // No messages are sent.
    }
}

/// A collection of `TestNode`s representing a network.
pub struct TestNetwork<A: Adversary<D>, D: DistAlgorithm>
where
    <D as DistAlgorithm>::NodeUid: Hash,
{
    pub nodes: BTreeMap<D::NodeUid, TestNode<D>>,
    pub observer: TestNode<D>,
    pub adv_nodes: BTreeMap<D::NodeUid, Rc<NetworkInfo<D::NodeUid>>>,
    pub pk_set: PublicKeySet,
    adversary: A,
}

impl<A: Adversary<D>, D: DistAlgorithm<NodeUid = NodeUid>> TestNetwork<A, D>
where
    D::Message: Clone,
{
    /// Creates a new network with `good_num` good nodes, and the given `adversary` controlling
    /// `adv_num` nodes.
    pub fn new<F, G>(
        good_num: usize,
        adv_num: usize,
        adversary: G,
        new_algo: F,
    ) -> TestNetwork<A, D>
    where
        F: Fn(Rc<NetworkInfo<NodeUid>>) -> D,
        G: Fn(BTreeMap<D::NodeUid, Rc<NetworkInfo<D::NodeUid>>>) -> A,
    {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(adv_num, &mut rng);
        let pk_set = sk_set.public_keys();

        let node_ids: BTreeSet<NodeUid> = (0..(good_num + adv_num)).map(NodeUid).collect();
        let new_node_by_id = |NodeUid(i): NodeUid| {
            (
                NodeUid(i),
                TestNode::new(new_algo(Rc::new(NetworkInfo::new(
                    NodeUid(i),
                    node_ids.clone(),
                    sk_set.secret_key_share(i as u64),
                    pk_set.clone(),
                )))),
            )
        };
        let new_adv_node_by_id = |NodeUid(i): NodeUid| {
            (
                NodeUid(i),
                Rc::new(NetworkInfo::new(
                    NodeUid(i),
                    node_ids.clone(),
                    sk_set.secret_key_share(i as u64),
                    pk_set.clone(),
                )),
            )
        };
        let adv_nodes: BTreeMap<D::NodeUid, Rc<NetworkInfo<D::NodeUid>>> = (good_num
            ..(good_num + adv_num))
            .map(NodeUid)
            .map(new_adv_node_by_id)
            .collect();
        let mut network = TestNetwork {
            nodes: (0..good_num).map(NodeUid).map(new_node_by_id).collect(),
            observer: new_node_by_id(NodeUid(good_num + adv_num)).1,
            adversary: adversary(adv_nodes.clone()),
            pk_set: pk_set.clone(),
            adv_nodes,
        };
        let msgs = network.adversary.step();
        for (sender_id, msg) in msgs {
            network.dispatch_messages(sender_id, vec![msg]);
        }
        let mut initial_msgs: Vec<(D::NodeUid, Vec<_>)> = Vec::new();
        for (id, node) in &mut network.nodes {
            initial_msgs.push((*id, node.algo.message_iter().collect()));
        }
        for (id, msgs) in initial_msgs {
            network.dispatch_messages(id, msgs);
        }
        network
    }

    /// Pushes the messages into the queues of the corresponding recipients.
    fn dispatch_messages<Q>(&mut self, sender_id: NodeUid, msgs: Q)
    where
        Q: IntoIterator<Item = TargetedMessage<D::Message, NodeUid>> + Debug,
    {
        for msg in msgs {
            match msg.target {
                Target::All => {
                    for node in self.nodes.values_mut() {
                        if node.id != sender_id {
                            node.queue.push_back((sender_id, msg.message.clone()))
                        }
                    }
                    self.observer
                        .queue
                        .push_back((sender_id, msg.message.clone()));
                    self.adversary.push_message(sender_id, msg);
                }
                Target::Node(to_id) => {
                    if self.adv_nodes.contains_key(&to_id) {
                        self.adversary.push_message(sender_id, msg);
                    } else if let Some(node) = self.nodes.get_mut(&to_id) {
                        node.queue.push_back((sender_id, msg.message));
                    } else {
                        warn!(
                            "Unknown recipient {:?} for message: {:?}",
                            to_id, msg.message
                        );
                    }
                }
            }
        }
        while !self.observer.queue.is_empty() {
            self.observer.handle_message();
        }
    }

    /// Handles a queued message in a randomly selected node and returns the selected node's ID.
    pub fn step(&mut self) -> NodeUid {
        let msgs = self.adversary.step();
        for (sender_id, msg) in msgs {
            self.dispatch_messages(sender_id, Some(msg));
        }
        // Pick a random non-idle node..
        let id = self.adversary.pick_node(&self.nodes);
        let msgs: Vec<_> = {
            let node = self.nodes.get_mut(&id).unwrap();
            node.handle_message();
            node.algo.message_iter().collect()
        };
        self.dispatch_messages(id, msgs);
        id
    }

    /// Inputs a value in node `id`.
    pub fn input(&mut self, id: NodeUid, value: D::Input) {
        let msgs: Vec<_> = {
            let node = self.nodes.get_mut(&id).expect("input instance");
            node.input(value);
            node.algo.message_iter().collect()
        };
        self.dispatch_messages(id, msgs);
    }

    /// Inputs a value in all nodes.
    #[allow(unused)] // Not used in all tests.
    pub fn input_all(&mut self, value: D::Input)
    where
        D::Input: Clone,
    {
        let ids: Vec<D::NodeUid> = self.nodes.keys().cloned().collect();
        for id in ids {
            self.input(id, value.clone());
        }
    }
}
