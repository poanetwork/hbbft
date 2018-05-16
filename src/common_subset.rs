//! Asynchronous Common Subset algorithm.

// TODO: This module is work in progress. Remove this attribute when it's not needed anymore.
#![allow(unused)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

use agreement;
use agreement::{Agreement, AgreementMessage};
use broadcast;
use broadcast::{Broadcast, BroadcastMessage};
use fmt::HexBytes;
use messaging::{DistAlgorithm, MessageIter, OutputIter, Target, TargetedMessage};

// TODO: Make this a generic argument of `Broadcast`.
type ProposedValue = Vec<u8>;
// Type of output from the Common Subset message handler.
type CommonSubsetOutput<NodeUid> = (
    Option<HashMap<NodeUid, ProposedValue>>,
    VecDeque<TargetedMessage<Message<NodeUid>, NodeUid>>,
);

/// Message from Common Subset to remote nodes.
#[cfg_attr(feature = "serialization-serde", derive(Serialize))]
#[derive(Clone, Debug)]
pub enum Message<NodeUid> {
    /// A message for the broadcast algorithm concerning the set element proposed by the given node.
    Broadcast(NodeUid, BroadcastMessage),
    /// A message for the agreement algorithm concerning the set element proposed by the given
    /// node.
    Agreement(NodeUid, AgreementMessage),
}

/// Asynchronous Common Subset algorithm instance
///
/// The Asynchronous Common Subset protocol assumes a network of `N` nodes that send signed
/// messages to each other, with at most `f` of them malicious, where `3 * f < N`. Handling the
/// networking and signing is the responsibility of the user: only when a message has been
/// verified to be "from node i", it can be handed to the `CommonSubset` instance.
///
/// Each participating node proposes an element for inclusion. Under the above conditions, the
/// protocol guarantees that all of the good nodes output the same set, consisting of at least
/// `N - f` of the proposed elements.
///
/// The algorithm works as follows:
///
/// * `CommonSubset` instantiates one `Broadcast` algorithm for each of the participating nodes.
/// At least `N - f` of these - the ones whose proposer is not malicious - will eventually output
/// the element proposed by that node.
/// * It also instantiates an `Agreement` instance for each participating node, to decide whether
/// that node's proposed element should be included in the common set. Whenever an element is
/// received via broadcast, we input "yes" (`true`) into the corresponding `Agreement` instance.
/// * When `N - f` `Agreement` instances have decided "yes", we input "no" (`false`) into the
/// remaining ones, where we haven't provided input yet.
/// * Once all `Agreement` instances have decided, `CommonSubset` returns the set of all proposed
/// values for which the decision was "yes".
pub struct CommonSubset<NodeUid: Eq + Hash + Ord> {
    uid: NodeUid,
    num_nodes: usize,
    num_faulty_nodes: usize,
    broadcast_instances: HashMap<NodeUid, Broadcast<NodeUid>>,
    agreement_instances: HashMap<NodeUid, Agreement<NodeUid>>,
    broadcast_results: HashMap<NodeUid, ProposedValue>,
    agreement_results: HashMap<NodeUid, bool>,
    messages: VecDeque<TargetedMessage<Message<NodeUid>, NodeUid>>,
    output: Option<HashMap<NodeUid, ProposedValue>>,
}

impl<NodeUid: Clone + Debug + Eq + Hash + Ord> DistAlgorithm for CommonSubset<NodeUid> {
    type NodeUid = NodeUid;
    type Input = ProposedValue;
    type Output = HashMap<NodeUid, ProposedValue>;
    type Message = Message<NodeUid>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        self.send_proposed_value(input)
    }

    fn handle_message(
        &mut self,
        sender_id: &Self::NodeUid,
        message: Self::Message,
    ) -> Result<(), Self::Error> {
        match message {
            Message::Broadcast(p_id, b_msg) => self.handle_broadcast(sender_id, &p_id, b_msg),
            Message::Agreement(p_id, a_msg) => self.handle_agreement(sender_id, &p_id, &a_msg),
        }
    }

    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, Self::NodeUid>> {
        self.messages.pop_front()
    }

    fn next_output(&mut self) -> Option<Self::Output> {
        self.output.take()
    }

    fn terminated(&self) -> bool {
        self.messages.is_empty() && self.agreement_instances.values().all(Agreement::terminated)
    }

    fn our_id(&self) -> &Self::NodeUid {
        &self.uid
    }
}

impl<NodeUid: Clone + Debug + Eq + Hash + Ord> CommonSubset<NodeUid> {
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
            messages: VecDeque::new(),
            output: None,
        })
    }

    /// Common Subset input message handler. It receives a value for broadcast
    /// and redirects it to the corresponding broadcast instance.
    pub fn send_proposed_value(&mut self, value: ProposedValue) -> Result<(), Error> {
        // Upon receiving input v_i , input v_i to RBC_i. See Figure 2.
        if let Some(instance) = self.broadcast_instances.get_mut(&self.uid) {
            instance.input(value)?;
            let uid = self.uid.clone();
            self.messages.extend(
                instance
                    .message_iter()
                    .map(|msg| msg.map(|b_msg| Message::Broadcast(uid.clone(), b_msg))),
            );
        } else {
            return Err(Error::NoSuchBroadcastInstance);
        }
        self.try_agreement_completion();
        Ok(())
    }

    /// Upon delivery of v_j from RBC_j, if input has not yet been provided to
    /// BA_j, then provide input 1 to BA_j. See Figure 11.
    fn on_broadcast_result(&mut self, uid: &NodeUid) -> Result<(), Error> {
        if let Some(agreement_instance) = self.agreement_instances.get_mut(&uid) {
            if agreement_instance.accepts_input() {
                agreement_instance.set_input(true)?;
                if let Some(msg) = agreement_instance.next_message() {
                    self.messages
                        .push_back(msg.map(|a_msg| Message::Agreement(uid.clone(), a_msg)));
                }
            }
        } else {
            return Err(Error::NoSuchBroadcastInstance);
        }
        self.try_agreement_completion();
        Ok(())
    }

    /// Receives a broadcast message from a remote node `sender_id` concerning a
    /// value proposed by the node `proposer_id`.
    fn handle_broadcast(
        &mut self,
        sender_id: &NodeUid,
        proposer_id: &NodeUid,
        bmessage: BroadcastMessage,
    ) -> Result<(), Error> {
        let value;
        if let Some(broadcast_instance) = self.broadcast_instances.get_mut(proposer_id) {
            broadcast_instance.handle_message(sender_id, bmessage)?;
            self.messages.extend(
                broadcast_instance
                    .message_iter()
                    .map(|msg| msg.map(|b_msg| Message::Broadcast(proposer_id.clone(), b_msg))),
            );
            value = match broadcast_instance.next_output() {
                None => return Ok(()),
                Some(result) => result,
            };
        } else {
            return Err(Error::NoSuchBroadcastInstance);
        }
        self.broadcast_results.insert(proposer_id.clone(), value);
        self.on_broadcast_result(proposer_id)
    }

    /// Receives an agreement message from a remote node `sender_id` concerning
    /// a value proposed by the node `proposer_id`.
    fn handle_agreement(
        &mut self,
        sender_id: &NodeUid,
        proposer_id: &NodeUid,
        amessage: &AgreementMessage,
    ) -> Result<(), Error> {
        let input_result;
        // Send the message to the local instance of Agreement
        if let Some(agreement_instance) = self.agreement_instances.get_mut(proposer_id) {
            // Optional output of agreement and outgoing agreement
            // messages to remote nodes.
            if agreement_instance.terminated() {
                // This instance has terminated and does not accept input.
                return Ok(());
            }
            // Send the message to the agreement instance.
            agreement_instance.handle_message(sender_id, amessage.clone())?;
            while let Some(msg) = agreement_instance.next_message() {
                self.messages
                    .push_back(msg.map(|a_msg| Message::Agreement(proposer_id.clone(), a_msg)));
            }
            input_result = agreement_instance.next_output();
        } else {
            debug!("Proposer {:?} does not exist.", proposer_id);
            return Ok(());
        }

        if let Some(output) = input_result {
            // Process Agreement outputs.
            self.on_agreement_output(proposer_id, output)?;
        }
        // Check whether Agreement has completed.
        self.try_agreement_completion();
        Ok(())
    }

    /// Callback to be invoked on receipt of the decision value of the Agreement
    /// instance `uid`.
    fn on_agreement_output(
        &mut self,
        element_proposer_id: &NodeUid,
        result: bool,
    ) -> Result<(), Error> {
        self.agreement_results
            .insert(element_proposer_id.clone(), result);
        debug!(
            "{:?} Updated Agreement results: {:?}",
            self.uid, self.agreement_results
        );
        if !result || self.count_true() < self.num_nodes - self.num_faulty_nodes {
            return Ok(());
        }

        // Upon delivery of value 1 from at least N − f instances of BA, provide
        // input 0 to each instance of BA that has not yet been provided input.
        for agreement_instance in self.agreement_instances.values_mut() {
            if agreement_instance.accepts_input() {
                agreement_instance.set_input(false)?;
                if let Some(msg) = agreement_instance.next_message() {
                    self.messages.push_back(msg.map(|a_msg| {
                        Message::Agreement(agreement_instance.our_id().clone(), a_msg)
                    }));
                }
            }
        }
        Ok(())
    }

    /// Returns the number of agreement instances that have decided "yes".
    fn count_true(&self) -> usize {
        self.agreement_results.values().filter(|v| **v).count()
    }

    fn try_agreement_completion(&mut self) {
        // Once all instances of BA have completed, let C ⊂ [1..N] be
        // the indexes of each BA that delivered 1. Wait for the output
        // v_j for each RBC_j such that j∈C. Finally output ∪ j∈C v_j.
        if self.agreement_results.len() < self.num_nodes {
            return;
        }
        debug!("{:?} All Agreement instances have terminated", self.uid);
        // All instances of Agreement that delivered `true` (or "1" in the paper).
        let delivered_1: HashSet<&NodeUid> = self.agreement_results
            .iter()
            .filter(|(_, v)| **v)
            .map(|(k, _)| k)
            .collect();
        debug!("Agreement instances that delivered 1: {:?}", delivered_1);

        // Results of Broadcast instances in `delivered_1`
        let broadcast_results: HashMap<NodeUid, ProposedValue> = self.broadcast_results
            .iter()
            .filter(|(k, _)| delivered_1.contains(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        if delivered_1.len() == broadcast_results.len() {
            debug!("{:?} Agreement instances completed:", self.uid);
            for (uid, result) in &broadcast_results {
                debug!("    {:?} → {:?}", uid, HexBytes(&result));
            }
            self.output = Some(broadcast_results)
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
