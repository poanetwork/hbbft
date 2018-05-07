//! Asynchronous Common Subset algorithm.

// TODO: This module is work in progress. Remove this attribute when it's not needed anymore.
#![allow(unused)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::{Debug, Display};
use std::hash::Hash;

use agreement::{self, Agreement};
use broadcast::{self, Broadcast, TargetedBroadcastMessage};
use proto::{AgreementMessage, BroadcastMessage};

// TODO: Make this a generic argument of `Broadcast`.
type ProposedValue = Vec<u8>;

/// Input from a remote node to Common Subset.
pub enum Input<NodeUid> {
    /// Message from a remote node `uid` to the broadcast instance `uid`.
    Broadcast(NodeUid, BroadcastMessage<ProposedValue>),
    /// Message from a remote node `uid` to the agreement instance `uid`.
    Agreement(NodeUid, AgreementMessage),
}

/// Output from Common Subset to remote nodes.
///
/// FIXME: We can do an interface that doesn't need this type and instead works
/// directly with the `TargetBroadcastMessage` and `AgreementMessage`.
pub enum Output<NodeUid> {
    /// A broadcast message to be sent to the destination set in the
    /// `TargetedBroadcastMessage`.
    Broadcast(TargetedBroadcastMessage<NodeUid>),
    /// An agreement message to be broadcast to all nodes. There are no
    /// one-to-one agreement messages.
    Agreement(AgreementMessage),
}

pub struct CommonSubset<NodeUid: Eq + Hash> {
    uid: NodeUid,
    num_nodes: usize,
    num_faulty_nodes: usize,
    agreement_true_outputs: HashSet<NodeUid>,
    broadcast_instances: HashMap<NodeUid, Broadcast<NodeUid>>,
    agreement_instances: HashMap<NodeUid, Agreement>,
    broadcast_results: HashMap<NodeUid, ProposedValue>,
    agreement_results: HashMap<NodeUid, bool>,
}

impl<NodeUid: Clone + Debug + Display + Eq + Hash + Ord> CommonSubset<NodeUid> {
    pub fn new(uid: NodeUid, all_uids: &HashSet<NodeUid>, num_nodes: usize) -> Result<Self, Error> {
        let num_faulty_nodes = (num_nodes - 1) / 3;

        // Create all broadcast instances.
        let mut broadcast_instances: HashMap<NodeUid, Broadcast<NodeUid>> = HashMap::new();
        for uid0 in all_uids {
            broadcast_instances.insert(
                uid0.clone(),
                Broadcast::new(uid.clone(), uid0.clone(), all_uids.clone())?,
            );
        }

        // Create all agreement instances.
        let mut agreement_instances: HashMap<NodeUid, Agreement> = HashMap::new();
        for uid0 in all_uids {
            agreement_instances.insert(uid0.clone(), Agreement::new());
        }

        Ok(CommonSubset {
            uid,
            num_nodes,
            num_faulty_nodes,
            agreement_true_outputs: HashSet::new(),
            broadcast_instances,
            agreement_instances: HashMap::new(),
            broadcast_results: HashMap::new(),
            agreement_results: HashMap::new(),
        })
    }

    /// Common Subset input message handler. It receives a value for broadcast
    /// and redirects it to the corresponding broadcast instance.
    pub fn send_proposed_value(
        &self,
        value: ProposedValue,
    ) -> Result<VecDeque<Output<NodeUid>>, Error> {
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
    pub fn on_broadcast_result(
        &mut self,
        uid: &NodeUid,
    ) -> Result<Option<AgreementMessage>, Error> {
        if let Some(agreement_instance) = self.agreement_instances.get_mut(uid) {
            if !agreement_instance.has_input() {
                Ok(Some(agreement_instance.set_input(true)))
            } else {
                Ok(None)
            }
        } else {
            Err(Error::NoSuchBroadcastInstance)
        }
    }

    /// Receive input from a remote node.
    pub fn on_input(
        &mut self,
        message: Input<NodeUid>,
    ) -> Result<VecDeque<Output<NodeUid>>, Error> {
        match message {
            Input::Broadcast(uid, bmessage) => {
                let mut instance_result = None;
                let input_result = {
                    if let Some(broadcast_instance) = self.broadcast_instances.get(&uid) {
                        broadcast_instance
                            .handle_broadcast_message(&uid, bmessage)
                            .map(|(value, queue)| {
                                instance_result = value;
                                queue.into_iter().map(Output::Broadcast).collect()
                            })
                            .map_err(Error::from)
                    } else {
                        Err(Error::NoSuchBroadcastInstance)
                    }
                };
                if instance_result.is_some() {
                    self.on_broadcast_result(&uid)?;
                }
                input_result
            }
            Input::Agreement(_uid, _message) => {
                // FIXME: send the message to the Agreement instance and
                // conditionally call `on_agreement_output`

                Err(Error::NotImplemented)
            }
        }
    }

    /// Callback to be invoked on receipt of a returned value of the Agreement
    /// instance `uid`.
    ///
    /// FIXME: It is likely that only one `AgreementMessage` is required because
    /// Figure 11 does not count the number of messages but the number of nodes
    /// that sent messages.
    fn on_agreement_result(&mut self, uid: NodeUid, result: bool) -> VecDeque<AgreementMessage> {
        let mut outgoing = VecDeque::new();
        // Upon delivery of value 1 from at least N − f instances of BA, provide
        // input 0 to each instance of BA that has not yet been provided input.
        if result {
            self.agreement_true_outputs.insert(uid);

            if self.agreement_true_outputs.len() >= self.num_nodes - self.num_faulty_nodes {
                let instances = &mut self.agreement_instances;
                for (_uid0, instance) in instances.iter_mut() {
                    if !instance.has_input() {
                        outgoing.push_back(instance.set_input(false));
                    }
                }
            }
        }
        outgoing
    }

    pub fn on_agreement_completion(&self) -> Option<HashSet<ProposedValue>> {
        // Once all instances of BA have completed, let C ⊂ [1..N] be
        // the indexes of each BA that delivered 1. Wait for the output
        // v_j for each RBC_j such that j∈C. Finally output ∪ j∈C v_j.
        let instance_uids: HashSet<NodeUid> = self.agreement_instances
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        let completed_uids: HashSet<NodeUid> = self.agreement_results
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        if instance_uids == completed_uids {
            // All instances of Agreement that delivered `true`.
            let delivered_1: HashSet<NodeUid> = self.agreement_results
                .iter()
                .filter(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .collect();
            // Results of Broadcast instances in `delivered_1`
            let broadcast_results: HashSet<ProposedValue> = self.broadcast_results
                .iter()
                .filter(|(k, _)| delivered_1.get(k).is_some())
                .map(|(_, v)| v.clone())
                .collect();

            if delivered_1.len() == broadcast_results.len() {
                Some(broadcast_results)
            } else {
                None
            }
        } else {
            None
        }
    }
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
