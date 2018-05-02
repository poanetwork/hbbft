//! Asynchronous Common Subset algorithm.

use crossbeam_channel::{SendError, Sender};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use std::hash::Hash;
use std::fmt::{Debug, Display};

use agreement;
use agreement::Agreement;

use broadcast;
use broadcast::{Broadcast, TargetedBroadcastMessage};

use messaging;
use messaging::{AlgoMessage, Algorithm, Handler, LocalMessage, MessageLoopState,
                ProposedValue, QMessage, RemoteMessage};

use proto::{BroadcastMessage, AgreementMessage};

pub enum Input<NodeUid> {
    /// Local message to initiate broadcast of a value.
    CommonSubset(ProposedValue),
    /// Message from a remote node `uid` to the broadcast instance `uid`.
    Broadcast(NodeUid, BroadcastMessage<ProposedValue>),
    /// Message from a remote node `uid` to the agreement instance `uid`.
    Agreement(NodeUid, AgreementMessage),
}

pub enum Output<NodeUid> {
    Broadcast(TargetedBroadcastMessage<NodeUid>)
}

struct CommonSubsetState<NodeUid: Eq + Hash> {
    agreement_inputs: HashMap<NodeUid, bool>,
    agreement_true_outputs: HashSet<NodeUid>,
    agreements_without_input: HashSet<NodeUid>,
    broadcast_instances: HashMap<NodeUid, Broadcast<NodeUid>>,
    agreement_instances: HashMap<NodeUid, Agreement>,
}

pub struct CommonSubset<NodeUid: Eq + Hash> {
    uid: NodeUid,
    num_nodes: usize,
    num_faulty_nodes: usize,
    state: RwLock<CommonSubsetState<NodeUid>>,
}

impl<NodeUid: Clone + Debug + Display + Eq + Hash> CommonSubset<NodeUid> {
    pub fn new(uid: NodeUid, num_nodes: usize, node_uids: HashSet<NodeUid>) -> Self {
        let num_faulty_nodes = (num_nodes - 1) / 3;

        CommonSubset {
            uid,
            num_nodes,
            num_faulty_nodes,
             state: RwLock::new(CommonSubsetState {
                 agreement_inputs: HashMap::new(),
                 agreement_true_outputs: HashSet::new(),
                 agreements_without_input: node_uids,
                 // FIXME: instantiate broadcast instances
                 broadcast_instances: HashMap::new(),
                 // FIXME: instantiate agreement instances
                 agreement_instances: HashMap::new(),
            }),
        }
    }

    /// Common Subset input message handler. It receives a value for broadcast
    /// and redirects it to the corresponding broadcast instance.
    pub fn on_proposed_value(&self, value: ProposedValue) ->
        Result<VecDeque<Output<NodeUid>>, Error>
    {
        // Upon receiving input v_i , input v_i to RBC_i. See Figure 2.
        let state = self.state.read().unwrap();
        if let Some(instance) = state.broadcast_instances.get(&self.uid) {
            Ok(instance
                .propose_value(value)?
                .into_iter()
                .map(Output::Broadcast)
                .collect())
        } else {
            Err(Error::NoSuchBroadcastInstance)
        }
    }

    /// Upon delivery of v_j from RBC_j, if input has not yet been provided to
    /// BA_j, then provide input 1 to BA_j. See Figure 11.
    pub fn on_broadcast_output(&self, uid: NodeUid) ->
        Result<(), Error>
    {
        let mut state = self.state.write().unwrap();
        if let Some(agreement_instance) = state.agreement_instances.get_mut(&uid) {
            if agreement_instance.get_input().is_none() {
                agreement_instance.set_input(true);

                // FIXME: implement this counter indirectly by filtering the
                // list of Agreement instances
                //
                // state.agreements_without_input.remove(&uid);
            }
            Ok(())
        }
        else {
            Err(Error::NoSuchBroadcastInstance)
        }
    }

    pub fn on_input(&self, message: Input<NodeUid>) ->
        Result<VecDeque<Output<NodeUid>>, Error>
    {
        match message {
            Input::CommonSubset(value) => self.on_proposed_value(value),
            Input::Broadcast(uid, bmessage) => {
                let mut state = self.state.read().unwrap();
                if let Some(broadcast_instance) = state.broadcast_instances.get(&uid) {
                    broadcast_instance.handle_broadcast_message(&uid, &bmessage)
                        .map(|(value, queue)| {
                            if let Some(_value) = value {
                                // FIXME: use `value`
                                self.on_broadcast_output(uid);
                            }
                            queue
                                .into_iter()
                                .map(Output::Broadcast)
                                .collect()
                        })
                        .map_err(Error::from)
                }
                else {
                    Err(Error::NoSuchBroadcastInstance)
                }
            },
            Input::Agreement(_uid, _message) => {
                Err(Error::NotImplemented)
            }
        }
    }
}
    /*

                    // Upon delivery of value 1 from at least N − f instances of BA,
                    // provide input 0 to each instance of BA that has not yet been
                    // provided input.
                    AlgoMessage::AgreementOutput(uid, true) => {
                        let mut state = self.state.write().unwrap();
                        state.agreement_true_outputs.insert(uid);

                        if state.agreement_true_outputs.len()
                            >= self.num_nodes - self.num_faulty_nodes
                        {
                            // FIXME: Avoid cloning the set.
                            for uid0 in state.agreements_without_input.clone() {
                                tx.send(QMessage::Local(LocalMessage {
                                    dst: Algorithm::Agreement(uid0),
                                    message: AlgoMessage::AgreementInput(false),
                                })).map_err(Error::from)?;

                                // TODO: Possibly not required. Keeping in place to
                                // avoid resending `false`.
                                let _ = state.agreement_inputs.insert(uid0, false);
                            }
                        }

                        no_outgoing
                    }

                    // FIXME (missing clause):
                //
                // Once all instances of BA have completed, let C ⊂ [1..N] be
                // the indexes of each BA that delivered 1. Wait for the output
                // v_j for each RBC_j such that j∈C. Finally output ∪ j∈C v_j.

                // Catchall
                    _ => Err(Error::UnexpectedMessage).map_err(E::from),
                }
            }

            _ => Err(Error::UnexpectedMessage).map_err(E::from),
        }
    }
}

impl<E> Handler<E> for CommonSubset
where
    E: From<Error> + From<messaging::Error>,
{
    fn handle(&self, m: QMessage, tx: Sender<QMessage>) -> Result<MessageLoopState, E> {
        self.on_message(m, &tx)
    }
}
*/

#[derive(Clone, Debug)]
pub enum Error {
    UnexpectedMessage,
    NotImplemented,
    NoSuchBroadcastInstance,
    Send(SendError<QMessage>),
    Broadcast(broadcast::Error),
}

impl From<SendError<QMessage>> for Error {
    fn from(err: SendError<QMessage>) -> Error {
        Error::Send(err)
    }
}

impl From<broadcast::Error> for Error {
    fn from(err: broadcast::Error) -> Error {
        Error::Broadcast(err)
    }
}
