//! The local message delivery system.
use crossbeam::{Scope, ScopedJoinHandle};
use crossbeam_channel;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use hbbft::messaging::{SourcedMessage, Target, TargetedMessage};
use hbbft::proto::Message;
use std::fmt::Debug;

/// The queue functionality for messages sent between algorithm instances.
/// The messaging struct allows for targeted message exchange between comms
/// tasks on one side and algo tasks on the other.
pub struct Messaging<T: Clone + Debug + Send + Sync> {
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
    NoSuchTarget,
    SendError,
}

impl<T> From<crossbeam_channel::SendError<T>> for Error {
    fn from(_: crossbeam_channel::SendError<T>) -> Error {
        Error::SendError
    }
}
