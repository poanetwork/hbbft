//! Asynchronous Common Subset algorithm.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use crossbeam_channel::{Sender, SendError};

use messaging;
use messaging::{NodeUid, QMessage, MessageLoopState, Handler, LocalMessage,
                Algorithm, AlgoMessage};

struct CommonSubsetState {
    agreement_inputs: HashMap<NodeUid, bool>,
    agreement_true_outputs: HashSet<NodeUid>
}

pub struct CommonSubset {
    uid: NodeUid,
    num_nodes: usize,
    num_faulty_nodes: usize,
    node_uids: HashSet<NodeUid>,
    state: RwLock<CommonSubsetState>
}

impl CommonSubset {
    pub fn new(uid: NodeUid, num_nodes: usize,
               node_uids: HashSet<NodeUid>) ->
        Self
    {
        let num_faulty_nodes = (num_nodes - 1) / 3;

        CommonSubset {
            uid,
            num_nodes,
            num_faulty_nodes,
            node_uids,
            state: RwLock::new(CommonSubsetState {
                agreement_inputs: HashMap::new(),
                agreement_true_outputs: HashSet::new()
            })
        }
    }

    pub fn on_message<E>(&self, m: QMessage, tx: Sender<QMessage>) ->
        Result<MessageLoopState, E>
    where E: From<Error> + From<messaging::Error>
    { match m {
        QMessage::Local(LocalMessage {
            dst: _,
            message
        }) => {
            let no_outgoing = Ok(MessageLoopState::Processing(VecDeque::new()));

            match message {
                // Upon receiving input v_i , input v_i to RBC_i. See Figure 2.
                AlgoMessage::CommonSubsetInput(value) => {
                    tx.send(QMessage::Local(LocalMessage {
                        dst: Algorithm::Broadcast(self.uid),
                        message: AlgoMessage::BroadcastInput(value)
                    })).map_err(Error::from)?;

                    no_outgoing
                }

                // Upon delivery of v_j from RBC_j, if input has not yet been
                // provided to BA_j, then provide input 1 to BA_j. See Figure
                // 11.
                AlgoMessage::BroadcastOutput(uid, value) => {
                    let mut state = self.state.write().unwrap();
                    if let None = state.agreement_inputs.get(&uid) {
                        tx.send(QMessage::Local(LocalMessage {
                            dst: Algorithm::Agreement(uid),
                            message: AlgoMessage::AgreementInput(true)
                        })).map_err(Error::from)?;

                        let _ = state.agreement_inputs.insert(uid, true);
                    }

                    no_outgoing
                }

                // Upon delivery of value 1 from at least N − f instances of BA,
                // provide input 0 to each instance of BA that has not yet been
                // provided input.
                AlgoMessage::AgreementOutput(uid, true) => {
                    self.state.write().unwrap()
                        .agreement_true_outputs.insert(uid);

                    if self.state.read().unwrap()
                        .agreement_true_outputs.len() >=
                        self.num_nodes - self.num_faulty_nodes
                    {
                        let mut with_agreement_input: HashSet<NodeUid> =
                            HashSet::new();

                        for (k, _) in self.state.read().unwrap()
                            .agreement_inputs.iter()
                        {
                            let _ = with_agreement_input.insert(*k);
                        }

                        let without_agreement_input = self.node_uids
                            .difference(&with_agreement_input);
                        for &uid0 in without_agreement_input {
                            tx.send(QMessage::Local(LocalMessage {
                                dst: Algorithm::Agreement(uid0),
                                message: AlgoMessage::AgreementInput(false)
                            })).map_err(Error::from)?;

                            // TODO: Possibly not required. Keeping in place to
                            // avoid resending `false`.
                            let _ = self.state.write().unwrap()
                                .agreement_inputs.insert(uid0, false);
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
                _ => Err(Error::UnexpectedMessage).map_err(E::from)
            }
        },

        _ => Err(Error::UnexpectedMessage).map_err(E::from)
    }}
}

impl<E> Handler<E> for CommonSubset
where E: From<Error> + From<messaging::Error> {
    fn handle(&self, m: QMessage, tx: Sender<QMessage>) ->
        Result<MessageLoopState, E>
    {
        self.on_message(m, tx)
    }
}

#[derive(Clone, Debug)]
pub enum Error {
    UnexpectedMessage,
    NotImplemented,
    Send(SendError<QMessage>),
}

impl From<SendError<QMessage>> for Error
{
    fn from(err: SendError<QMessage>) -> Error { Error::Send(err) }
}
