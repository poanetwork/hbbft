use std::collections::{BTreeMap, VecDeque};
use std::fmt::{self, Debug};
use std::mem;
use std::sync::Arc;

use crypto::SecretKeyShare;
use rand::{self, Rng};

use hbbft::messaging::{DistAlgorithm, NetworkInfo, Step, Target, TargetedMessage};

/// A node identifier. In the tests, nodes are simply numbered.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Clone, Copy, Serialize, Deserialize, Rand)]
pub struct NodeUid(pub usize);

/// A "node" running an instance of the algorithm `D`.
pub struct TestNode<D: DistAlgorithm> {
    /// This node's own ID.
    pub id: D::NodeUid,
    /// The instance of the broadcast algorithm.
    algo: D,
    /// Incoming messages from other nodes that this node has not yet handled.
    pub queue: VecDeque<(D::NodeUid, D::Message)>,
    /// The values this node has output so far.
    outputs: Vec<D::Output>,
    /// Outgoing messages to be sent to other nodes.
    messages: VecDeque<TargetedMessage<D::Message, D::NodeUid>>,
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
        let step = self.algo.input(input).expect("input");
        self.outputs.extend(step.output);
        self.messages.extend(step.messages);
    }

    /// Returns the internal algorithm's instance.
    #[allow(unused)] // Not used in all tests.
    pub fn instance(&self) -> &D {
        &self.algo
    }

    /// Creates a new test node with the given broadcast instance.
    fn new((algo, step): (D, Step<D>)) -> TestNode<D> {
        TestNode {
            id: algo.our_id().clone(),
            algo,
            queue: VecDeque::new(),
            outputs: step.output.into_iter().collect(),
            messages: step.messages,
        }
    }

    /// Handles the first message in the node's queue.
    fn handle_message(&mut self) {
        let (from_id, msg) = self.queue.pop_front().expect("message not found");
        debug!("Handling {:?} -> {:?}: {:?}", from_id, self.id, msg);
        let step = self
            .algo
            .handle_message(&from_id, msg)
            .expect("handling message");
        self.outputs.extend(step.output);
        self.messages.extend(step.messages);
    }

    /// Checks whether the node has messages to process
    fn is_idle(&self) -> bool {
        self.queue.is_empty()
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

/// A message combined with a sender.
pub struct MessageWithSender<D: DistAlgorithm> {
    /// The sender of the message.
    pub sender: <D as DistAlgorithm>::NodeUid,
    /// The targeted message (recipient and message body).
    pub tm: TargetedMessage<<D as DistAlgorithm>::Message, <D as DistAlgorithm>::NodeUid>,
}

// The Debug implementation cannot be derived automatically, possibly due to a compiler bug. For
// this reason, it is implemented manually here.
impl<D: DistAlgorithm> fmt::Debug for MessageWithSender<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MessageWithSender {{ sender: {:?}, tm: {:?} }}",
            self.sender, self.tm.target
        )
    }
}

impl<D: DistAlgorithm> MessageWithSender<D> {
    /// Creates a new message with a sender.
    pub fn new(
        sender: D::NodeUid,
        tm: TargetedMessage<D::Message, D::NodeUid>,
    ) -> MessageWithSender<D> {
        MessageWithSender { sender, tm }
    }
}

/// An adversary that can control a set of nodes and pick the next good node to receive a message.
///
/// See `TestNetwork::step()` for a more detailed description of its capabilities.
pub trait Adversary<D: DistAlgorithm> {
    /// Chooses a node to be the next one to handle a message.
    ///
    /// Starvation is illegal, i.e. in every iteration a node that has pending incoming messages
    /// must be chosen.
    fn pick_node(&self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid;

    /// Called when a node controlled by the adversary receives a message.
    fn push_message(&mut self, sender_id: D::NodeUid, msg: TargetedMessage<D::Message, D::NodeUid>);

    /// Produces a list of messages to be sent from the adversary's nodes.
    fn step(&mut self) -> Vec<MessageWithSender<D>>;

    /// Initialize an adversary. This function's primary purpose is to inform the adversary over
    /// some aspects of the network, such as which nodes they control.
    fn init(
        &mut self,
        _all_nodes: &BTreeMap<D::NodeUid, TestNode<D>>,
        _adv_nodes: &BTreeMap<D::NodeUid, Arc<NetworkInfo<D::NodeUid>>>,
    ) {
        // default: does nothing
    }
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

/// Return true with a certain `probability` ([0 .. 1.0]).
fn randomly(probability: f32) -> bool {
    assert!(probability <= 1.0);
    assert!(probability >= 0.0);

    let mut rng = rand::thread_rng();
    rng.gen_range(0.0, 1.0) <= probability
}

#[test]
fn test_randomly() {
    assert!(randomly(1.0));
    assert!(!randomly(0.0));
}

/// An adversary that performs naive replay attacks.
///
/// The adversary will randomly take a message that is sent to one of its nodes and re-send it to
/// a different node. Additionally, it will inject unrelated messages at random.
#[allow(unused)] // not used in all tests
pub struct RandomAdversary<D: DistAlgorithm, F> {
    /// The underlying scheduler used
    scheduler: MessageScheduler,

    /// Node ids seen by the adversary.
    known_node_ids: Vec<D::NodeUid>,
    /// Node ids under control of adversary
    known_adversarial_ids: Vec<D::NodeUid>,

    /// Internal queue for messages to be returned on the next `Adversary::step()` call
    outgoing: Vec<MessageWithSender<D>>,
    /// Generates random messages to be injected
    generator: F,

    /// Probability of a message replay
    p_replay: f32,
    /// Probability of a message injection
    p_inject: f32,
}

impl<D: DistAlgorithm, F> RandomAdversary<D, F> {
    /// Creates a new random adversary instance.
    #[allow(unused)]
    pub fn new(p_replay: f32, p_inject: f32, generator: F) -> RandomAdversary<D, F> {
        assert!(
            p_inject < 0.95,
            "injections are repeated, p_inject must be smaller than 0.95"
        );

        RandomAdversary {
            // The random adversary, true to its name, always schedules randomly.
            scheduler: MessageScheduler::Random,
            known_node_ids: Vec::new(),
            known_adversarial_ids: Vec::new(),
            outgoing: Vec::new(),
            generator,
            p_replay,
            p_inject,
        }
    }
}

impl<D: DistAlgorithm, F: Fn() -> TargetedMessage<D::Message, D::NodeUid>> Adversary<D>
    for RandomAdversary<D, F>
{
    fn init(
        &mut self,
        all_nodes: &BTreeMap<D::NodeUid, TestNode<D>>,
        nodes: &BTreeMap<D::NodeUid, Arc<NetworkInfo<D::NodeUid>>>,
    ) {
        self.known_adversarial_ids = nodes.keys().cloned().collect();
        self.known_node_ids = all_nodes.keys().cloned().collect();
    }

    fn pick_node(&self, nodes: &BTreeMap<D::NodeUid, TestNode<D>>) -> D::NodeUid {
        // Just let the scheduler pick a node.
        self.scheduler.pick_node(nodes)
    }

    fn push_message(&mut self, _: D::NodeUid, msg: TargetedMessage<D::Message, D::NodeUid>) {
        // If we have not discovered the network topology yet, abort.
        if self.known_node_ids.is_empty() {
            return;
        }

        // only replay a message in some cases
        if !randomly(self.p_replay) {
            return;
        }

        let TargetedMessage { message, target } = msg;

        match target {
            Target::All => {
                // Ideally, we would want to handle broadcast messages as well; however the
                // adversary API is quite cumbersome at the moment in regards to access to the
                // network topology. To re-send a broadcast message from one of the attacker
                // controlled nodes, we would have to get a list of attacker controlled nodes
                // here and use a random one as the origin/sender, this is not done here.
                return;
            }
            Target::Node(our_node_id) => {
                // Choose a new target to send the message to. The unwrap never fails, because we
                // ensured that `known_node_ids` is non-empty earlier.
                let mut rng = rand::thread_rng();
                let new_target_node = rng.choose(&self.known_node_ids).unwrap().clone();

                // TODO: We could randomly broadcast it instead, if we had access to topology
                //       information.
                self.outgoing.push(MessageWithSender::new(
                    our_node_id,
                    TargetedMessage {
                        target: Target::Node(new_target_node),
                        message,
                    },
                ));
            }
        }
    }

    fn step(&mut self) -> Vec<MessageWithSender<D>> {
        // Clear messages.
        let mut tmp = Vec::new();
        mem::swap(&mut tmp, &mut self.outgoing);

        // Possibly inject more messages:
        while randomly(self.p_inject) {
            let mut rng = rand::thread_rng();

            // Pick a random adversarial node and create a message using the generator.
            if let Some(sender) = rng.choose(&self.known_adversarial_ids[..]) {
                let tm = (self.generator)();

                // Add to outgoing queue.
                tmp.push(MessageWithSender::new(sender.clone(), tm));
            }
        }

        if !tmp.is_empty() {
            println!("Injecting random messages: {:?}", tmp);
        }
        tmp
    }
}

/// A collection of `TestNode`s representing a network.
///
/// Each `TestNetwork` type is tied to a specific adversary and a distributed algorithm. It consists
/// of a set of nodes, some of which are controlled by the adversary and some of which may be
/// observer nodes, as well as a set of threshold-cryptography public keys.
///
/// In addition to being able to participate correctly in the network using his nodes, the
/// adversary can:
///
/// 1. Decide which node is the next one to make progress,
/// 2. Send arbitrary messages to any node originating from one of the nodes they control.
///
/// See the `step` function for details on actual operation of the network.
pub struct TestNetwork<A: Adversary<D>, D: DistAlgorithm> {
    pub nodes: BTreeMap<D::NodeUid, TestNode<D>>,
    pub observer: TestNode<D>,
    pub adv_nodes: BTreeMap<D::NodeUid, Arc<NetworkInfo<D::NodeUid>>>,
    adversary: A,
}

impl<A: Adversary<D>, D: DistAlgorithm<NodeUid = NodeUid>> TestNetwork<A, D>
where
    D::Message: Clone,
{
    /// Creates a new network with `good_num` good nodes, and the given `adversary` controlling
    /// `adv_num` nodes.
    #[allow(unused)] // Not used in all tests.
    pub fn new<F, G>(
        good_num: usize,
        adv_num: usize,
        adversary: G,
        new_algo: F,
    ) -> TestNetwork<A, D>
    where
        F: Fn(Arc<NetworkInfo<NodeUid>>) -> D,
        G: Fn(BTreeMap<D::NodeUid, Arc<NetworkInfo<D::NodeUid>>>) -> A,
    {
        Self::new_with_step(good_num, adv_num, adversary, |netinfo| {
            (new_algo(netinfo), Step::default())
        })
    }

    /// Creates a new network with `good_num` good nodes, and the given `adversary` controlling
    /// `adv_num` nodes.
    pub fn new_with_step<F, G>(
        good_num: usize,
        adv_num: usize,
        adversary: G,
        new_algo: F,
    ) -> TestNetwork<A, D>
    where
        F: Fn(Arc<NetworkInfo<NodeUid>>) -> (D, Step<D>),
        G: Fn(BTreeMap<D::NodeUid, Arc<NetworkInfo<D::NodeUid>>>) -> A,
    {
        let mut rng = rand::thread_rng();
        let mut netinfos = NetworkInfo::generate_map((0..(good_num + adv_num)).map(NodeUid));
        let obs_netinfo = {
            let node_ni = netinfos.values().next().unwrap();
            NetworkInfo::new(
                NodeUid(good_num + adv_num),
                SecretKeyShare::default(),
                node_ni.public_key_set().clone(),
                rng.gen(),
                node_ni.public_key_map().clone(),
            )
        };
        let adv_netinfos = netinfos.split_off(&NodeUid(good_num));

        let new_node = |(uid, netinfo): (NodeUid, NetworkInfo<_>)| {
            (uid, TestNode::new(new_algo(Arc::new(netinfo))))
        };
        let new_adv_node = |(uid, netinfo): (NodeUid, NetworkInfo<_>)| (uid, Arc::new(netinfo));
        let adv_nodes: BTreeMap<_, _> = adv_netinfos.into_iter().map(new_adv_node).collect();

        let observer = TestNode::new(new_algo(Arc::new(obs_netinfo)));

        let mut network = TestNetwork {
            nodes: netinfos.into_iter().map(new_node).collect(),
            observer,
            adversary: adversary(adv_nodes.clone()),
            adv_nodes,
        };

        // Inform the adversary about their nodes.
        network.adversary.init(&network.nodes, &network.adv_nodes);

        let msgs = network.adversary.step();
        for MessageWithSender { sender, tm } in msgs {
            network.dispatch_messages(sender, vec![tm]);
        }
        let mut initial_msgs: Vec<(D::NodeUid, Vec<_>)> = Vec::new();
        for (id, node) in &mut network.nodes {
            initial_msgs.push((*id, node.messages.drain(..).collect()));
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

    /// Performs one iteration of the network, consisting of the following steps:
    ///
    /// 1. Give the adversary a chance to send messages of his choosing through `Adversary::step()`,
    /// 2. Let the adversary pick a node that receives its next message through
    ///    `Adversary::pick_node()`.
    ///
    /// Returns the node ID of the node that made progress.
    pub fn step(&mut self) -> NodeUid {
        // We let the adversary send out messages to any number of nodes.
        let msgs = self.adversary.step();
        for MessageWithSender { sender, tm } in msgs {
            self.dispatch_messages(sender, Some(tm));
        }

        // Now one node is chosen to make progress, we let the adversary decide which.
        let id = self.adversary.pick_node(&self.nodes);

        // The node handles the incoming message and creates new outgoing ones to be dispatched.
        let msgs: Vec<_> = {
            let mut node = self.nodes.get_mut(&id).unwrap();

            // Ensure the adversary is playing fair by selecting a node that will result in actual
            // progress being made, otherwise `TestNode::handle_message()` will panic on `expect()`
            // with a much more cryptic error message.
            assert!(
                !node.is_idle(),
                "adversary illegally selected an idle node in pick_node()"
            );

            node.handle_message();
            node.messages.drain(..).collect()
        };
        self.dispatch_messages(id, msgs);

        id
    }

    /// Inputs a value in node `id`.
    pub fn input(&mut self, id: NodeUid, value: D::Input) {
        let msgs: Vec<_> = {
            let mut node = self.nodes.get_mut(&id).expect("input instance");
            node.input(value);
            node.messages.drain(..).collect()
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
