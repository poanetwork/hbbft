//! The local message delivery system.
use crossbeam::{Scope, ScopedJoinHandle};
use crossbeam_channel;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use proto::Message;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::RwLock;

/// Unique ID of a node.
pub type NodeUid = SocketAddr;

/// Type of algorithm primitive used in HoneyBadgerBFT.
///
/// TODO: Add the epoch parameter?
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Encryption stage.
    Encryption,
    /// Decryption stage.
    Decryption,
    /// Asynchronous Common Subset.
    CommonSubset,
    /// Reliable Broadcast instance.
    Broadcast(NodeUid),
    /// Binary Agreement instance.
    Agreement(NodeUid),
}

impl Iterator for Algorithm {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        Some(format!("{:?}", self))
    }
}

/// Type of proposed (encrypted) value for consensus.
pub type ProposedValue = Vec<u8>;

/// Kinds of messages sent between algorithm instances.
#[derive(Clone)]
pub enum AlgoMessage {
    /// Asynchronous common subset input.
    CommonSubsetInput(ProposedValue),
    /// Asynchronous common subset output.
    CommonSubsetOutput(HashSet<ProposedValue>),
    /// Broadcast instance input.
    BroadcastInput(ProposedValue),
    /// Broadcast instance output.
    BroadcastOutput(NodeUid, ProposedValue),
    /// Binary agreement instance input.
    AgreementInput(bool),
    /// Binary agreement instance output.
    AgreementOutput(NodeUid, bool),
}

/// A message sent between algorithm instances.
#[derive(Clone)]
pub struct LocalMessage {
    /// Identifier of the message destination algorithm.
    pub dst: Algorithm,
    /// Payload
    pub message: AlgoMessage,
}

/// The message destinations corresponding to a remote node `i`. It can be
/// either of the two:
///
/// 1) `All`: all nodes if sent to socket tasks, or all local algorithm
/// instances if received from socket tasks.
///
/// 2) `Node(i)`: node `i` or local algorithm instances with the node ID `i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteNode {
    All,
    Node(NodeUid),
}

/// Message to or from a remote node.
#[derive(Clone, Debug, PartialEq)]
pub struct RemoteMessage {
    pub node: RemoteNode,
    pub message: Message<ProposedValue>,
}

/// The union type of local and remote messages.
#[derive(Clone)]
pub enum QMessage {
    Local(LocalMessage),
    Remote(RemoteMessage),
}

/// States of the message loop consided as an automaton with output. There is
/// one exit state `Finished` and one transitional (also initial) state
/// `Processing` whose argument is an output queue of messages to be sent to
/// remote nodes.
#[derive(Clone, PartialEq)]
pub enum MessageLoopState {
    Processing(VecDeque<RemoteMessage>),
    Finished,
}

impl MessageLoopState {
    pub fn is_processing(&self) -> bool {
        if let MessageLoopState::Processing(_) = self {
            true
        } else {
            false
        }
    }

    /// Appends pending messages of another state.  Used to append messages
    /// emitted by the handler to the messages already queued from previous
    /// iterations of a message handling loop.
    pub fn append(&mut self, other: &mut MessageLoopState) {
        if let MessageLoopState::Processing(ref mut new_msgs) = other {
            if let MessageLoopState::Processing(ref mut msgs) = self {
                msgs.append(new_msgs);
            }
        }
    }
}

/// Abstract type of message handler callback. A callback function has two
/// arguments: the sent message and the TX handle to send replies back to the
/// message loop. A call to the function returns either a new message loop state
/// - either `Finished` or a state with outgoing messages to remote nodes - or
/// an error.
pub trait Handler<HandlerError: From<Error>>: Send + Sync {
    fn handle(&self, m: QMessage, tx: Sender<QMessage>) -> Result<MessageLoopState, HandlerError>;
}

/// The queue functionality for messages sent between algorithm instances.
pub struct MessageLoop<'a, HandlerError: 'a + From<Error>> {
    /// Algorithm message handlers. Every message handler receives a message and
    /// the TX handle of the incoming message queue for sending replies back to
    /// the message loop.
    algos: RwLock<HashMap<Algorithm, &'a Handler<HandlerError>>>,
    /// TX handle of the message queue.
    queue_tx: Sender<QMessage>,
    /// RX handle of the message queue.
    queue_rx: Receiver<QMessage>,
    /// Remote send handles. Messages are sent through channels as opposed to
    /// directly to sockets. This is done to make tests independent of socket
    /// IO.
    remote_txs: HashMap<NodeUid, Sender<Message<ProposedValue>>>,
}

impl<'a, HandlerError> MessageLoop<'a, HandlerError>
where
    HandlerError: 'a + From<Error>,
{
    pub fn new(remote_txs: HashMap<NodeUid, Sender<Message<ProposedValue>>>) -> Self {
        let (queue_tx, queue_rx) = unbounded();
        MessageLoop {
            algos: RwLock::new(HashMap::new()),
            queue_tx,
            queue_rx,
            remote_txs,
        }
    }

    pub fn queue_tx(&self) -> Sender<QMessage> {
        self.queue_tx.clone()
    }

    /// Registers a handler for messages sent to the given algorithm.
    pub fn insert_algo(&'a self, algo: Algorithm, handler: &'a Handler<HandlerError>) {
        let lock = self.algos.write();
        if let Ok(mut map) = lock {
            map.insert(algo, handler);
        } else {
            error!("Cannot insert {:?}", algo);
        }
    }

    /// Unregisters the handler for messages sent to the given algorithm.
    pub fn remove_algo(&self, algo: &Algorithm) {
        let lock = self.algos.write();
        if let Ok(mut map) = lock {
            map.remove(algo);
        } else {
            error!("Cannot remove {:?}", algo);
        }
    }

    /// The message loop.
    pub fn run(&self) -> Result<MessageLoopState, HandlerError> {
        let mut result = Ok(MessageLoopState::Processing(VecDeque::new()));

        while let Ok(mut state) = result {
            // Send any outgoing messages to remote nodes using the provided
            // function.
            (if let MessageLoopState::Processing(messages) = &state {
                self.send_remote(messages)
                    .map(|_| MessageLoopState::Processing(VecDeque::new()))
                    .map_err(HandlerError::from)
            } else {
                Ok(MessageLoopState::Finished)
            })?;

            // Receive local and remote messages.
            if let Ok(m) = self.queue_rx.recv() {
                result = match m {
                    QMessage::Local(LocalMessage { dst, message }) => {
                        // FIXME: error handling
                        if let Some(mut handler) = self.algos.write().unwrap().get_mut(&dst) {
                            let mut new_result = handler.handle(
                                QMessage::Local(LocalMessage { dst, message }),
                                self.queue_tx.clone(),
                            );
                            if let Ok(ref mut new_state) = new_result {
                                state.append(new_state);
                                Ok(state)
                            } else {
                                // Error overrides the previous state.
                                new_result
                            }
                        } else {
                            Err(Error::NoSuchAlgorithm).map_err(HandlerError::from)
                        }
                    }

                    // A message FROM a remote node.
                    QMessage::Remote(RemoteMessage { node, message }) => {
                        // Multicast the message to all algorithm instances,
                        // collecting output messages iteratively and appending them
                        // to result.
                        //
                        // FIXME: error handling
                        self.algos.write().unwrap().iter_mut().fold(
                            Ok(state),
                            |result1, (_, handler)| {
                                if let Ok(mut state1) = result1 {
                                    handler
                                        .handle(
                                            QMessage::Remote(RemoteMessage {
                                                node: node.clone(),
                                                message: message.clone(),
                                            }),
                                            self.queue_tx.clone(),
                                        )
                                        .map(|ref mut state2| {
                                            state1.append(state2);
                                            state1
                                        })
                                } else {
                                    result1
                                }
                            },
                        )
                    }
                }
            } else {
                result = Err(Error::RecvError).map_err(HandlerError::from)
            }
        } // end of while loop
        result
    }

    /// Send a message queue to remote nodes.
    fn send_remote(&self, messages: &VecDeque<RemoteMessage>) -> Result<(), Error> {
        messages.iter().fold(Ok(()), |result, m| {
            if result.is_err() {
                result
            } else {
                match m {
                    RemoteMessage {
                        node: RemoteNode::Node(uid),
                        message,
                    } => {
                        if let Some(tx) = self.remote_txs.get(&uid) {
                            tx.send(message.clone()).map_err(Error::from)
                        } else {
                            Err(Error::SendError)
                        }
                    }

                    RemoteMessage {
                        node: RemoteNode::All,
                        message,
                    } => self.remote_txs.iter().fold(result, |result1, (_, tx)| {
                        if result1.is_err() {
                            result1
                        } else {
                            tx.send(message.clone()).map_err(Error::from)
                        }
                    }),
                }
            }
        })
    }
}

/// Message destination can be either of the two:
///
/// 1) `All`: all nodes if sent to socket tasks, or all local algorithm
/// instances if received from socket tasks.
///
/// 2) `Node(i)`: node i or local algorithm instances with the node index i.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    All,
    Node(usize),
}

/// Message with a designated target.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetedMessage<T: Clone + Debug + Send + Sync> {
    pub target: Target,
    pub message: Message<T>,
}

impl<T: Clone + Debug + Send + Sync> TargetedMessage<T> {
    /// Initialises a message while checking parameter preconditions.
    pub fn new(target: Target, message: Message<T>) -> Option<Self> {
        match target {
            Target::Node(i) if i == 0 => {
                // Remote node indices start from 1.
                None
            }
            _ => Some(TargetedMessage { target, message }),
        }
    }
}

/// Message sent by a given source. The sources are consensus nodes indexed 1
/// through N where N is the total number of nodes. Sourced messages are
/// required when it is essential to know the message origin but the set of
/// recepients is unknown without further computation which is irrelevant to the
/// message delivery task.
#[derive(Clone, Debug)]
pub struct SourcedMessage<T: Clone + Debug + Send + Sync> {
    pub source: usize,
    pub message: Message<T>,
}

/// The messaging struct allows for targeted message exchange between comms
/// tasks on one side and algo tasks on the other.
pub struct Messaging<T: Clone + Debug + Send + Sync> {
    /// The total number of consensus nodes for indexing purposes.
    num_nodes: usize,

    /// Transmit sides of message channels to comms threads.
    txs_to_comms: Vec<Sender<Message<T>>>,
    /// Receive side of the routed message channel from comms threads.
    rx_from_comms: Receiver<SourcedMessage<T>>,
    /// Transmit sides of message channels to algo threads.
    txs_to_algo: Vec<Sender<SourcedMessage<T>>>,
    /// Receive side of the routed message channel from comms threads.
    rx_from_algo: Receiver<TargetedMessage<T>>,

    /// RX handles to be used by comms tasks.
    rxs_to_comms: Vec<Receiver<Message<T>>>,
    /// TX handle to be used by comms tasks.
    tx_from_comms: Sender<SourcedMessage<T>>,
    /// RX handles to be used by algo tasks.
    rxs_to_algo: Vec<Receiver<SourcedMessage<T>>>,
    /// TX handle to be used by algo tasks.
    tx_from_algo: Sender<TargetedMessage<T>>,

    /// Control channel used to stop the listening thread.
    stop_tx: Sender<()>,
    stop_rx: Receiver<()>,
}

impl<T: Clone + Debug + Send + Sync> Messaging<T> {
    /// Initialises all the required TX and RX handles for the case on a total
    /// number `num_nodes` of consensus nodes.
    pub fn new(num_nodes: usize) -> Self {
        let to_comms: Vec<_> = (0..num_nodes - 1)
            .map(|_| unbounded::<Message<T>>())
            .collect();
        let txs_to_comms = to_comms.iter().map(|&(ref tx, _)| tx.to_owned()).collect();
        let rxs_to_comms: Vec<Receiver<Message<T>>> =
            to_comms.iter().map(|&(_, ref rx)| rx.to_owned()).collect();
        let (tx_from_comms, rx_from_comms) = unbounded();
        let to_algo: Vec<_> = (0..num_nodes)
            .map(|_| unbounded::<SourcedMessage<T>>())
            .collect();
        let txs_to_algo = to_algo.iter().map(|&(ref tx, _)| tx.to_owned()).collect();
        let rxs_to_algo: Vec<Receiver<SourcedMessage<T>>> =
            to_algo.iter().map(|&(_, ref rx)| rx.to_owned()).collect();
        let (tx_from_algo, rx_from_algo) = unbounded();

        let (stop_tx, stop_rx) = bounded(1);

        Messaging {
            num_nodes,

            // internally used handles
            txs_to_comms,
            rx_from_comms,
            txs_to_algo,
            rx_from_algo,

            // externally used handles
            rxs_to_comms,
            tx_from_comms,
            rxs_to_algo,
            tx_from_algo,

            stop_tx,
            stop_rx,
        }
    }

    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    pub fn rxs_to_comms(&self) -> &Vec<Receiver<Message<T>>> {
        &self.rxs_to_comms
    }

    pub fn tx_from_comms(&self) -> &Sender<SourcedMessage<T>> {
        &self.tx_from_comms
    }

    pub fn rxs_to_algo(&self) -> &Vec<Receiver<SourcedMessage<T>>> {
        &self.rxs_to_algo
    }

    pub fn tx_from_algo(&self) -> &Sender<TargetedMessage<T>> {
        &self.tx_from_algo
    }

    /// Gives the ownership of the handle to stop the message receive loop.
    pub fn stop_tx(&self) -> Sender<()> {
        self.stop_tx.to_owned()
    }

    /// Spawns the message delivery thread in a given thread scope.
    pub fn spawn<'a>(&self, scope: &Scope<'a>) -> ScopedJoinHandle<Result<(), Error>>
    where
        T: 'a,
    {
        let txs_to_comms = self.txs_to_comms.to_owned();
        let rx_from_comms = self.rx_from_comms.to_owned();
        let txs_to_algo = self.txs_to_algo.to_owned();
        let rx_from_algo = self.rx_from_algo.to_owned();

        let stop_rx = self.stop_rx.to_owned();
        let mut stop = false;

        // TODO: `select_loop!` seems to really confuse Clippy.
        #[cfg_attr(
            feature = "cargo-clippy",
            allow(never_loop, if_let_redundant_pattern_matching, deref_addrof)
        )]
        scope.spawn(move || {
            let mut result = Ok(());
            // This loop forwards messages according to their metadata.
            while !stop && result.is_ok() {
                select_loop! {
                    recv(rx_from_algo, message) => {
                        match message {
                            TargetedMessage {
                                target: Target::All,
                                message
                            } => {
                                // Send the message to all remote nodes, stopping at
                                // the first error.
                                result = txs_to_comms.iter()
                                    .fold(Ok(()), |result, tx| {
                                        if result.is_ok() {
                                            tx.send(message.clone())
                                        }
                                        else {
                                            result
                                        }
                                    }).map_err(Error::from);
                            },
                            TargetedMessage {
                                target: Target::Node(i),
                                message
                            } => {
                                // Remote node indices start from 1.
                                assert!(i > 0);
                                // Convert node index to vector index.
                                let i = i - 1;

                                result = if i < txs_to_comms.len() {
                                    txs_to_comms[i].send(message.clone())
                                        .map_err(Error::from)
                                }
                                else {
                                    Err(Error::NoSuchTarget)
                                };
                            }
                        }
                    },
                    recv(rx_from_comms, message) => {
                        // Send the message to all algorithm instances, stopping at
                        // the first error.
                        result = txs_to_algo.iter().fold(Ok(()), |result, tx| {
                            if result.is_ok() {
                                tx.send(message.clone())
                            }
                            else {
                                result
                            }
                        }).map_err(Error::from)
                    },
                    recv(stop_rx, _) => {
                        // Flag the thread ready to exit.
                        stop = true;
                    }
                }
            } // end of select_loop!
            result
        })
    }
}

#[derive(Clone, Debug)]
pub enum Error {
    NoSuchAlgorithm,
    NoSuchRemote,
    RecvError,
    NoSuchTarget,
    SendError,
}

impl<T> From<crossbeam_channel::SendError<T>> for Error {
    fn from(_: crossbeam_channel::SendError<T>) -> Error {
        Error::SendError
    }
}
