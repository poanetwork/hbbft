//! Asynchronous Common Subset algorithm.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::fmt::{Debug, Display};

use agreement;
use agreement::Agreement;

use broadcast;
use broadcast::{Broadcast, TargetedBroadcastMessage};

use messaging::ProposedValue;

use proto::{BroadcastMessage, AgreementMessage};

/// Input from a remote node to Common Subset.
pub enum Input<NodeUid> {
    /// Message from a remote node `uid` to the broadcast instance `uid`.
    Broadcast(NodeUid, BroadcastMessage<ProposedValue>),
    /// Message from a remote node `uid` to the agreement instance `uid`.
    Agreement(NodeUid, AgreementMessage),
}

/// Output from Common Subset to remote nodes.
pub enum Output<NodeUid> {
    Broadcast(TargetedBroadcastMessage<NodeUid>)
}

struct CommonSubsetState<NodeUid: Eq + Hash> {
    agreement_true_outputs: HashSet<NodeUid>,
    broadcast_instances: HashMap<NodeUid, Broadcast<NodeUid>>,
    agreement_instances: HashMap<NodeUid, Agreement>,
}

pub struct CommonSubset<NodeUid: Eq + Hash> {
    uid: NodeUid,
    num_nodes: usize,
    num_faulty_nodes: usize,
    agreement_true_outputs: HashSet<NodeUid>,
    broadcast_instances: HashMap<NodeUid, Broadcast<NodeUid>>,
    agreement_instances: HashMap<NodeUid, Agreement>,
}

impl<NodeUid: Clone + Debug + Display + Eq + Hash> CommonSubset<NodeUid> {
    pub fn new(uid: NodeUid, num_nodes: usize) -> Self {
        let num_faulty_nodes = (num_nodes - 1) / 3;

        CommonSubset {
            uid,
            num_nodes,
            num_faulty_nodes,
            agreement_true_outputs: HashSet::new(),
            // FIXME: instantiate broadcast instances
            broadcast_instances: HashMap::new(),
            // FIXME: instantiate agreement instances
            agreement_instances: HashMap::new(),
        }
    }

    /// Common Subset input message handler. It receives a value for broadcast
    /// and redirects it to the corresponding broadcast instance.
    pub fn send_proposed_value(&self, value: ProposedValue) ->
        Result<VecDeque<Output<NodeUid>>, Error>
    {
        // Upon receiving input v_i , input v_i to RBC_i. See Figure 2.
        if let Some(instance) = self.broadcast_instances.get(&self.uid) {
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
    pub fn on_broadcast_result(&mut self, uid: NodeUid) ->
        Result<(), Error>
    {
        if let Some(agreement_instance) = self.agreement_instances.get_mut(&uid) {
            if !agreement_instance.has_input() {
                agreement_instance.set_input(true);
            }
            Ok(())
        }
        else {
            Err(Error::NoSuchBroadcastInstance)
        }
    }

    /// Receive input from a remote node.
    pub fn on_input(&mut self, message: Input<NodeUid>) ->
        Result<VecDeque<Output<NodeUid>>, Error>
    {
        match message {
            Input::Broadcast(uid, bmessage) => {
                let mut instance_result = None;
                let input_result = {
                    if let Some(broadcast_instance) = self.broadcast_instances.get(&uid) {
                        broadcast_instance.handle_broadcast_message(&uid, &bmessage)
                            .map(|(value, queue)| {
                                if let Some(value) = value {
                                    instance_result = Some(value)
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
                };
                if instance_result.is_some() {
                    self.on_broadcast_result(uid);
                }
                input_result
            },
            Input::Agreement(_uid, _message) => {
                // FIXME: send the message to the Agreement instance and
                // conditionally call `on_agreement_output`

                Err(Error::NotImplemented)
            }
        }
    }

    /// Callback to be invoked on receipt of a returned value of the Agreement
    /// instance `uid`.
    fn on_agreement_result(&mut self, uid: NodeUid, result: bool) {
        // Upon delivery of value 1 from at least N − f instances of BA, provide
        // input 0 to each instance of BA that has not yet been provided input.
        if result {
            self.agreement_true_outputs.insert(uid);

            if self.agreement_true_outputs.len() >=
                self.num_nodes - self.num_faulty_nodes
            {
                let instances = &mut self.agreement_instances;
                for (_uid0, instance) in instances.iter_mut() {
                    if !instance.has_input() {
                        instance.set_input(false);
                    }
                }
            }
        }
    }

    // FIXME (missing clause):
    //
    // Once all instances of BA have completed, let C ⊂ [1..N] be
    // the indexes of each BA that delivered 1. Wait for the output
    // v_j for each RBC_j such that j∈C. Finally output ∪ j∈C v_j.
}

#[derive(Clone, Debug)]
pub enum Error {
    UnexpectedMessage,
    NotImplemented,
    NoSuchBroadcastInstance,
    Broadcast(broadcast::Error),
    Agreement(agreement::Error),
}

impl From<broadcast::Error> for Error {
    fn from(err: broadcast::Error) -> Error {
        Error::Broadcast(err)
    }
}

impl From<agreement::Error> for Error {
    fn from(err: agreement::Error) -> Error {
        Error::Agreement(err)
    }
}
