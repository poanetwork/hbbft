//! The local message delivery system.
use std::collections::{HashSet, HashMap, VecDeque};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::RwLock;
use crossbeam::{Scope, ScopedJoinHandle};
use crossbeam_channel;
use crossbeam_channel::{bounded, unbounded, Sender, Receiver};
use proto::Message;

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

/// Type of proposed (encrypted) value for consensus.
pub type ProposedValue = Vec<u8>;

/// Kinds of messages sent between algorithm instances.
pub enum AlgoMessage {
    /// Asynchronous common subset input.
    CommonSubsetInput(ProposedValue),
    /// Asynchronous common subset output.
    CommonSubsetOutput(HashSet<ProposedValue>),
    /// Broadcast instance input or output.
    Broadcast(ProposedValue),
    /// Binary agreement instance input or output.
    Agreement(bool)
}

/// A message sent between algorithm instances.
pub struct LocalMessage {
    /// Identifier of the message destination algorithm.
    dst: Algorithm,
    /// Payload
    message: AlgoMessage
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
    Node(NodeUid)
}

/// Message to or from a remote node.
#[derive(Clone, Debug, PartialEq)]
pub struct RemoteMessage {
    pub node: RemoteNode,
    pub message: Message<ProposedValue>
}

/// The union type of local and remote messages.
pub enum QMessage {
    Local(LocalMessage),
    Remote(RemoteMessage)
}

/// States of the message loop consided as an automaton with output. There is
/// one exit state `Finished` and one transitional (also initial) state
/// `Processing` whose argument is an output queue of messages to be sent to
/// remote nodes.
#[derive(Clone, PartialEq)]
pub enum MessageLoopState {
    Processing(VecDeque<RemoteMessage>),
    Finished
}

impl MessageLoopState {
    pub fn is_processing(&self) -> bool {
        if let MessageLoopState::Processing(_) = self {
            true
        }
        else {
            false
        }
    }

    /// Appends pending messages of another state.  Used to append messages
    /// emitted by the handler to the messages already queued from previous
    /// iterations of a message handling loop.
    pub fn append(&mut self, other: &mut MessageLoopState) {
        if let MessageLoopState::Processing(ref mut new_msgs) = other
        {
            if let MessageLoopState::Processing(ref mut msgs) = self
            {
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
pub trait Handler<HandlerError: AlgoError>: Send + Sync {
    fn handle(&self, m: QMessage, tx: Sender<QMessage>) ->
        Result<MessageLoopState, HandlerError>;
}

/// The queue functionality for messages sent between algorithm instances.
pub struct MessageLoop<'a, HandlerError: 'a + AlgoError> {
    /// Algorithm message handlers. Every message handler receives a message and
    /// the TX handle of the incoming message queue for sending replies back to
    /// the message loop.
    algos: RwLock<HashMap<Algorithm, &'a Handler<HandlerError>>>,
    /// The queue of local and remote messages.
    queue: VecDeque<QMessage>,
    /// TX handle of the message queue.
    queue_tx: Sender<QMessage>,
    /// RX handle of the message queue.
    queue_rx: Receiver<QMessage>,
    /// Remote send handles. Messages are sent through channels as opposed to
    /// diretly to sockets. This is done to make tests independent of socket
    /// IO.
    remote_txs: HashMap<NodeUid, Sender<Message<ProposedValue>>>
}

impl<'a, HandlerError: AlgoError> MessageLoop<'a, HandlerError> {
    pub fn new(remote_txs: HashMap<NodeUid, Sender<Message<ProposedValue>>>) ->
        Self
    {
        let (queue_tx, queue_rx) = unbounded();
        MessageLoop {
            algos: RwLock::new(HashMap::new()),
            queue: VecDeque::new(),
            queue_tx,
            queue_rx,
            remote_txs
        }
    }

    pub fn queue_tx(&self) -> Sender<QMessage> {
        self.queue_tx.clone()
    }

    /// Registers a handler for messages sent to the given algorithm.
    pub fn insert_algo(&'a self, algo: Algorithm,
                       handler: &'a Handler<HandlerError>)
    {
        let _ = self.algos.write().unwrap().insert(algo, handler).unwrap();
    }

    /// Unregisters the handler for messages sent to the given algorithm.
    pub fn remove_algo(&self, algo: &Algorithm) {
        let _ = self.algos.write().unwrap().remove(algo).unwrap();
    }

    /// Places a message at the end of the queue for routing to the destination
    /// later.
    ///
    /// FIXME: Thread-safe interface.
    pub fn push(&mut self, message: QMessage) {
        self.queue.push_back(message);
    }

    // Removes and returns the message from the front of the queue if the queue
    // is not empty.
    // pub fn pop(&mut self) -> Option<QMessage> {
    //     self.queue.pop_front()
    // }

    /// The message loop.
    pub fn run(&mut self) -> Result<MessageLoopState, Error>
    {
        let mut result = Ok(MessageLoopState::Processing(VecDeque::new()));

        while let Ok(mut state) = result {
            // Send any outgoing messages to remote nodes using the provided
            // function.
            (if let MessageLoopState::Processing(messages) = &state {
                self.send_remote(messages)
                    .map(|_| MessageLoopState::Processing(VecDeque::new()))
                    .map_err(Error::from)
            }
            else {
                Ok(MessageLoopState::Finished)
            })?;

            // Receive local and remote messages.
            if let Ok(m) = self.queue_rx.recv() { result = match m {
                QMessage::Local(LocalMessage {
                    dst,
                    message
                }) => {
                    if let Some(handler) = self.algos.read().unwrap().get(&dst) {
                        let mut new_result =
                            handler.handle(QMessage::Local(
                                LocalMessage {
                                    dst,
                                    message
                                }), self.queue_tx.clone()
                            ).map_err(Error::from);
                        if let Ok(ref mut new_state) = new_result {
                            state.append(new_state);
                            Ok(state)
                        }
                        else {
                            // Error overrides the previous state.
                            new_result
                        }
                    }
                    else {
                        Err(Error::NoSuchAlgorithm)
                    }
                }

                QMessage::Remote(RemoteMessage {
                    node,
                    message
                }) => {
                    // Multicast the message to all algorithm instances,
                    // collecting output messages iteratively and appending them
                    // to result.
                    self.algos.read().unwrap().iter()
                        .fold(Ok(state),
                              |result1, (_, handler)| {
                                  if let Ok(mut state1) = result1 {
                                      handler.handle(
                                          QMessage::Remote(RemoteMessage {
                                              node: node.clone(),
                                              message: message.clone()
                                          }), self.queue_tx.clone()
                                          ).map(|ref mut state2| {
                                              state1.append(state2);
                                              state1
                                          }).map_err(Error::from)
                                  }
                                  else {
                                      result1
                                  }
                              }
                        )
                }
            }} else { result = Err(Error::RecvError) }} // end of while loop
        result
    }

    /// Send a message queue to remote nodes.
    fn send_remote(&mut self, messages: &VecDeque<RemoteMessage>) ->
        Result<(), Error>
    {
        messages.iter().fold(Ok(()), |result, m| {
            if result.is_err() { result } else { match m {
                RemoteMessage {
                    node: RemoteNode::Node(uid),
                    message
                } => {
                    if let Some(tx) = self.remote_txs.get(&uid) {
                        tx.send(message.clone()).map_err(Error::from)
                    }
                    else {
                        Err(Error::SendError)
                    }
                },

                RemoteMessage {
                    node: RemoteNode::All,
                    message
                } => {
                    self.remote_txs.iter().fold(result, |result1, (uid, tx)| {
                        if result1.is_err() { result1 } else {
                            if let Some(tx) = self.remote_txs.get(&uid) {
                                tx.send(message.clone()).map_err(Error::from)
                            }
                            else {
                                Err(Error::SendError)
                            }
                        }
                    })
                }
            }}
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
    Node(usize)
}

/// Message with a designated target.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetedMessage<T: Clone + Debug + Send + Sync> {
    pub target: Target,
    pub message: Message<T>
}

impl<T: Clone + Debug + Send + Sync> TargetedMessage<T>
{
    /// Initialises a message while checking parameter preconditions.
    pub fn new(target: Target, message: Message<T>) -> Option<Self> {
        match target {
            Target::Node(i) if i == 0 => {
                // Remote node indices start from 1.
                None
            },
            _ => Some(TargetedMessage{target, message})
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
    pub message: Message<T>
}

/// The messaging struct allows for targeted message exchange between comms
/// tasks on one side and algo tasks on the other.
pub struct Messaging<T: Clone + Debug + Send + Sync> {
    /// The total number of consensus nodes for indexing purposes.
    num_nodes: usize,

    /// Transmit sides of message channels to comms threads.
    to_comms_txs: Vec<Sender<Message<T>>>,
    /// Receive side of the routed message channel from comms threads.
    from_comms_rx: Receiver<SourcedMessage<T>>,
    /// Transmit sides of message channels to algo threads.
    to_algo_txs: Vec<Sender<SourcedMessage<T>>>,
    /// Receive side of the routed message channel from comms threads.
    from_algo_rx: Receiver<TargetedMessage<T>>,

    /// RX handles to be used by comms tasks.
    to_comms_rxs: Vec<Receiver<Message<T>>>,
    /// TX handle to be used by comms tasks.
    from_comms_tx: Sender<SourcedMessage<T>>,
    /// RX handles to be used by algo tasks.
    to_algo_rxs: Vec<Receiver<SourcedMessage<T>>>,
    /// TX handle to be used by algo tasks.
    from_algo_tx: Sender<TargetedMessage<T>>,

    /// Control channel used to stop the listening thread.
    stop_tx: Sender<()>,
    stop_rx: Receiver<()>,
}

impl<T: Clone + Debug + Send + Sync> Messaging<T> {
    /// Initialises all the required TX and RX handles for the case on a total
    /// number `num_nodes` of consensus nodes.
    pub fn new(num_nodes: usize) -> Self
    {
        let to_comms: Vec<(Sender<Message<T>>, Receiver<Message<T>>)>
            = (0 .. num_nodes - 1)
            .map(|_| unbounded())
            .collect();
        let to_comms_txs = to_comms.iter()
            .map(|&(ref tx, _)| tx.to_owned())
            .collect();
        let to_comms_rxs: Vec<Receiver<Message<T>>> = to_comms.iter()
            .map(|&(_, ref rx)| rx.to_owned())
            .collect();
        let (from_comms_tx, from_comms_rx) = unbounded();
        let to_algo: Vec<(Sender<SourcedMessage<T>>,
                          Receiver<SourcedMessage<T>>)>
            = (0 .. num_nodes)
            .map(|_| unbounded())
            .collect();
        let to_algo_txs = to_algo.iter()
            .map(|&(ref tx, _)| tx.to_owned())
            .collect();
        let to_algo_rxs: Vec<Receiver<SourcedMessage<T>>> = to_algo.iter()
            .map(|&(_, ref rx)| rx.to_owned())
            .collect();
        let (from_algo_tx, from_algo_rx) = unbounded();

        let (stop_tx, stop_rx) = bounded(1);

        Messaging {
            num_nodes,

            // internally used handles
            to_comms_txs,
            from_comms_rx,
            to_algo_txs,
            from_algo_rx,

            // externally used handles
            to_comms_rxs,
            from_comms_tx,
            to_algo_rxs,
            from_algo_tx,

            stop_tx,
            stop_rx,
        }
    }

    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    pub fn to_comms_rxs(&self) -> &Vec<Receiver<Message<T>>> {
        &self.to_comms_rxs
    }

    pub fn from_comms_tx(&self) -> &Sender<SourcedMessage<T>> {
        &self.from_comms_tx
    }

    pub fn to_algo_rxs(&self) -> &Vec<Receiver<SourcedMessage<T>>> {
        &self.to_algo_rxs
    }

    pub fn from_algo_tx(&self) -> &Sender<TargetedMessage<T>> {
        &self.from_algo_tx
    }

    /// Gives the ownership of the handle to stop the message receive loop.
    pub fn stop_tx(&self) -> Sender<()> {
        self.stop_tx.to_owned()
    }

    /// Spawns the message delivery thread in a given thread scope.
    pub fn spawn<'a>(&self, scope: &Scope<'a>) ->
        ScopedJoinHandle<Result<(), Error>>
    where T: 'a
    {
        let to_comms_txs = self.to_comms_txs.to_owned();
        let from_comms_rx = self.from_comms_rx.to_owned();
        let to_algo_txs = self.to_algo_txs.to_owned();
        let from_algo_rx = self.from_algo_rx.to_owned();

        let stop_rx = self.stop_rx.to_owned();
        let mut stop = false;

        scope.spawn(move || {
            let mut result = Ok(());
            // This loop forwards messages according to their metadata.
            while !stop && result.is_ok() { select_loop! {
                recv(from_algo_rx, message) => {
                    match message {
                        TargetedMessage {
                            target: Target::All,
                            message
                        } => {
                            // Send the message to all remote nodes, stopping at
                            // the first error.
                            result = to_comms_txs.iter()
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

                            result = if i < to_comms_txs.len() {
                                to_comms_txs[i].send(message.clone())
                                    .map_err(Error::from)
                            }
                            else {
                                Err(Error::NoSuchTarget)
                            };
                        }
                    }
                },
                recv(from_comms_rx, message) => {
                    // Send the message to all algorithm instances, stopping at
                    // the first error.
                    result = to_algo_txs.iter().fold(Ok(()), |result, tx| {
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
            }} // end of select_loop!
            result
        })
    }
}

/// Class of algorithm error types.
pub trait AlgoError: Send + Sync {
    fn to_str(&self) -> &'static str;
}

#[derive(Clone, Debug)]
pub enum Error {
    NoSuchAlgorithm,
    NoSuchRemote,
    RecvError,
    AlgoError(&'static str),
    NoSuchTarget,
    SendError,
}

impl<E: AlgoError> From<E> for Error {
    fn from(e: E) -> Error { Error::AlgoError(e.to_str()) }
}

impl<T> From<crossbeam_channel::SendError<T>> for Error {
    fn from(_: crossbeam_channel::SendError<T>) -> Error { Error::SendError }
}
