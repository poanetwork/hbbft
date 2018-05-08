//! Asynchronous Common Subset algorithm.

// TODO: This module is work in progress. Remove this attribute when it's not needed anymore.
#![allow(unused)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::{Debug, Display};
use std::hash::Hash;

use agreement;
use agreement::{Agreement, AgreementMessage};

use broadcast;
use broadcast::{Broadcast, BroadcastMessage, TargetedBroadcastMessage};

// TODO: Make this a generic argument of `Broadcast`.
type ProposedValue = Vec<u8>;
// Type of output from the Common Subset message handler.
type CommonSubsetOutput<NodeUid> = (Option<HashSet<ProposedValue>>, VecDeque<Output<NodeUid>>);

/// Input from a remote node to Common Subset.
pub enum Input<NodeUid> {
    /// Message from a remote node `uid` to the broadcast instance `uid`.
    Broadcast(NodeUid, BroadcastMessage<ProposedValue>),
    /// Message from a remote node `uid` to all agreement instances.
    Agreement(NodeUid, AgreementMessage),
}

/// Output from Common Subset to remote nodes.
pub enum Output<NodeUid> {
    /// A broadcast message to be sent to the destination set in the
    /// `TargetedBroadcastMessage`.
    Broadcast(TargetedBroadcastMessage<NodeUid>),
    /// An agreement message to be broadcast to all nodes. There are no
    /// one-to-one agreement messages.
    Agreement(AgreementMessage),
}

pub struct CommonSubset<NodeUid: Eq + Hash + Ord> {
    uid: NodeUid,
    num_nodes: usize,
    num_faulty_nodes: usize,
    broadcast_instances: HashMap<NodeUid, Broadcast<NodeUid>>,
    agreement_instances: HashMap<NodeUid, Agreement<NodeUid>>,
    broadcast_results: HashMap<NodeUid, ProposedValue>,
    agreement_results: HashMap<NodeUid, bool>,
}

impl<NodeUid: Clone + Debug + Display + Eq + Hash + Ord> CommonSubset<NodeUid> {
    pub fn new(uid: NodeUid, all_uids: &HashSet<NodeUid>) -> Result<Self, Error> {
        let num_nodes = all_uids.len();
        let num_faulty_nodes = (num_nodes - 1) / 3;

        // Create all broadcast instances.
        let mut broadcast_instances: HashMap<NodeUid, Broadcast<NodeUid>> = HashMap::new();
        for uid0 in all_uids {
            broadcast_instances.insert(
                uid0.clone(),
                Broadcast::new(
                    uid.clone(),
                    uid0.clone(),
                    all_uids.iter().cloned().collect(),
                )?,
            );
        }

        // Create all agreement instances.
        let mut agreement_instances: HashMap<NodeUid, Agreement<NodeUid>> = HashMap::new();
        for uid0 in all_uids {
            agreement_instances.insert(uid0.clone(), Agreement::new(uid0.clone(), num_nodes));
        }

        Ok(CommonSubset {
            uid,
            num_nodes,
            num_faulty_nodes,
            broadcast_instances,
            agreement_instances,
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
    fn on_broadcast_result(&mut self, uid: &NodeUid) -> Result<Option<AgreementMessage>, Error> {
        if let Some(agreement_instance) = self.agreement_instances.get_mut(&uid) {
            if !agreement_instance.has_input() {
                Ok(Some(agreement_instance.set_input(true)))
            } else {
                Ok(None)
            }
        } else {
            Err(Error::NoSuchBroadcastInstance)
        }
    }

    /// Receive input from a remote node. The output contains an optional result
    /// of the Common Subset algorithm - a set of proposed values - and a queue
    /// of messages to be sent to remote nodes, or an error.
    pub fn on_input(
        &mut self,
        message: Input<NodeUid>,
    ) -> Result<CommonSubsetOutput<NodeUid>, Error> {
        match message {
            Input::Broadcast(uid, bmessage) => self.on_input_broadcast(&uid, bmessage),

            Input::Agreement(uid, amessage) => self.on_input_agreement(&uid, &amessage),
        }
    }

    fn on_input_broadcast(
        &mut self,
        uid: &NodeUid,
        bmessage: BroadcastMessage<ProposedValue>,
    ) -> Result<CommonSubsetOutput<NodeUid>, Error> {
        let mut instance_result = None;
        let input_result: Result<VecDeque<Output<NodeUid>>, Error> = {
            if let Some(broadcast_instance) = self.broadcast_instances.get(&uid) {
                broadcast_instance
                    .handle_broadcast_message(&uid, bmessage)
                    .map(|(opt_value, queue)| {
                        instance_result = opt_value;
                        queue.into_iter().map(Output::Broadcast).collect()
                    })
                    .map_err(Error::from)
            } else {
                Err(Error::NoSuchBroadcastInstance)
            }
        };
        let mut opt_message: Option<AgreementMessage> = None;
        if let Some(value) = instance_result {
            self.broadcast_results.insert(uid.clone(), value);
            opt_message = self.on_broadcast_result(&uid)?;
        }
        input_result.map(|mut queue| {
            if let Some(agreement_message) = opt_message {
                // Append the message to agreement nodes to the common output queue.
                queue.push_back(Output::Agreement(agreement_message))
            }
            (None, queue)
        })
    }

    fn on_input_agreement(
        &mut self,
        uid: &NodeUid,
        amessage: &AgreementMessage,
    ) -> Result<CommonSubsetOutput<NodeUid>, Error> {
        // Send the message to all local instances of Agreement
        let on_input_result: Result<
            (HashMap<NodeUid, bool>, VecDeque<AgreementMessage>),
            Error,
        > = self.agreement_instances.iter_mut().fold(
            Ok((HashMap::new(), VecDeque::new())),
            |accum, (instance_uid, instance)| {
                match accum {
                    Err(_) => accum,
                    Ok((mut outputs, mut outgoing)) => {
                        // Optional output of agreement and outgoing
                        // agreement messages to remote nodes.
                        if instance.terminated() {
                            // This instance has terminated and does not accept input.
                            Ok((outputs, outgoing))
                        } else {
                            // Send the message to the agreement instance.
                            instance
                                .on_input(uid.clone(), &amessage)
                                .map_err(Error::from)
                                .map(|(output, mut messages)| {
                                    if let Some(b) = output {
                                        outputs.insert(instance_uid.clone(), b);
                                    }
                                    outgoing.append(&mut messages);
                                    (outputs, outgoing)
                                })
                        }
                    }
                }
            },
        );

        if let Ok((outputs, mut outgoing)) = on_input_result {
            // Process Agreement outputs.
            outputs.iter().map(|(output_uid, &output_value)| {
                outgoing.append(&mut self.on_agreement_result(output_uid.clone(), output_value));
            });

            // Check whether Agreement has completed.
            Ok((
                self.try_agreement_completion(),
                outgoing.into_iter().map(Output::Agreement).collect(),
            ))
        } else {
            // error
            on_input_result
                .map(|(_, messages)| (None, messages.into_iter().map(Output::Agreement).collect()))
        }
    }

    /// Callback to be invoked on receipt of a returned value of the Agreement
    /// instance `uid`.
    fn on_agreement_result(&mut self, uid: NodeUid, result: bool) -> VecDeque<AgreementMessage> {
        let mut outgoing = VecDeque::new();
        // Upon delivery of value 1 from at least N − f instances of BA, provide
        // input 0 to each instance of BA that has not yet been provided input.
        if result {
            self.agreement_results.insert(uid, result);
            // The number of instances of BA that output 1.
            let results1 = self.agreement_results.values().filter(|v| **v).count();

            if results1 >= self.num_nodes - self.num_faulty_nodes {
                for instance in self.agreement_instances.values_mut() {
                    if !instance.has_input() {
                        outgoing.push_back(instance.set_input(false));
                    }
                }
            }
        }
        outgoing
    }

    fn try_agreement_completion(&self) -> Option<HashSet<ProposedValue>> {
        // Once all instances of BA have completed, let C ⊂ [1..N] be
        // the indexes of each BA that delivered 1. Wait for the output
        // v_j for each RBC_j such that j∈C. Finally output ∪ j∈C v_j.
        if self.agreement_instances
            .values()
            .all(|instance| instance.terminated())
        {
            // All instances of Agreement that delivered `true` (or "1" in the paper).
            let delivered_1: HashSet<&NodeUid> = self.agreement_results
                .iter()
                .filter(|(_, v)| **v)
                .map(|(k, _)| k)
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
    NoSuchAgreementInstance,
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
