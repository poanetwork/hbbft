//! Asynchronous Common Subset algorithm.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::rc::Rc;

use agreement;
use agreement::{Agreement, AgreementMessage};
use broadcast;
use broadcast::{Broadcast, BroadcastMessage};
use fmt::HexBytes;
use messaging::{DistAlgorithm, NetworkInfo, TargetedMessage};

error_chain!{
    types {
        Error, ErrorKind, ResultExt, CommonSubsetResult;
    }

    links {
        Agreement(agreement::Error, agreement::ErrorKind);
        Broadcast(broadcast::Error, broadcast::ErrorKind);
    }

    errors {
        MultipleAgreementResults
        NoSuchAgreementInstance
        NoSuchBroadcastInstance
    }
}

// TODO: Make this a generic argument of `CommonSubset`.
type ProposedValue = Vec<u8>;

/// Message from Common Subset to remote nodes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Message<NodeUid> {
    /// A message for the broadcast algorithm concerning the set element proposed by the given node.
    Broadcast(NodeUid, BroadcastMessage),
    /// A message for the agreement algorithm concerning the set element proposed by the given
    /// node.
    Agreement(NodeUid, AgreementMessage),
}

/// The queue of outgoing messages in a `CommonSubset` instance.
#[derive(Deref, DerefMut)]
struct MessageQueue<NodeUid>(VecDeque<TargetedMessage<Message<NodeUid>, NodeUid>>);

impl<NodeUid: Clone + Debug + Ord> MessageQueue<NodeUid> {
    /// Appends to the queue the messages from `agr`, wrapped with `proposer_id`.
    fn extend_agreement(&mut self, proposer_id: &NodeUid, agr: &mut Agreement<NodeUid>) {
        let convert = |msg: TargetedMessage<AgreementMessage, NodeUid>| {
            msg.map(|a_msg| Message::Agreement(proposer_id.clone(), a_msg))
        };
        self.extend(agr.message_iter().map(convert));
    }

    /// Appends to the queue the messages from `bc`, wrapped with `proposer_id`.
    fn extend_broadcast(&mut self, proposer_id: &NodeUid, bc: &mut Broadcast<NodeUid>) {
        let convert = |msg: TargetedMessage<BroadcastMessage, NodeUid>| {
            msg.map(|b_msg| Message::Broadcast(proposer_id.clone(), b_msg))
        };
        self.extend(bc.message_iter().map(convert));
    }
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
pub struct CommonSubset<NodeUid> {
    /// Shared network information.
    netinfo: Rc<NetworkInfo<NodeUid>>,
    broadcast_instances: BTreeMap<NodeUid, Broadcast<NodeUid>>,
    agreement_instances: BTreeMap<NodeUid, Agreement<NodeUid>>,
    broadcast_results: BTreeMap<NodeUid, ProposedValue>,
    agreement_results: BTreeMap<NodeUid, bool>,
    /// Outgoing message queue.
    messages: MessageQueue<NodeUid>,
    /// The output value of the algorithm.
    output: Option<BTreeMap<NodeUid, ProposedValue>>,
    /// Whether the instance has decided on a value.
    decided: bool,
}

impl<NodeUid: Clone + Debug + Ord> DistAlgorithm for CommonSubset<NodeUid> {
    type NodeUid = NodeUid;
    type Input = ProposedValue;
    type Output = BTreeMap<NodeUid, ProposedValue>;
    type Message = Message<NodeUid>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> CommonSubsetResult<()> {
        debug!(
            "{:?} Proposing {:?}",
            self.netinfo.our_uid(),
            HexBytes(&input)
        );
        self.send_proposed_value(input)
    }

    fn handle_message(
        &mut self,
        sender_id: &Self::NodeUid,
        message: Self::Message,
    ) -> CommonSubsetResult<()> {
        match message {
            Message::Broadcast(p_id, b_msg) => self.handle_broadcast(sender_id, &p_id, b_msg),
            Message::Agreement(p_id, a_msg) => self.handle_agreement(sender_id, &p_id, a_msg),
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
        self.netinfo.our_uid()
    }
}

impl<NodeUid: Clone + Debug + Ord> CommonSubset<NodeUid> {
    pub fn new(netinfo: Rc<NetworkInfo<NodeUid>>, session_id: u64) -> CommonSubsetResult<Self> {
        // Create all broadcast instances.
        let mut broadcast_instances: BTreeMap<NodeUid, Broadcast<NodeUid>> = BTreeMap::new();
        for proposer_id in netinfo.all_uids() {
            broadcast_instances.insert(
                proposer_id.clone(),
                Broadcast::new(netinfo.clone(), proposer_id.clone())?,
            );
        }

        // Create all agreement instances.
        let mut agreement_instances: BTreeMap<NodeUid, Agreement<NodeUid>> = BTreeMap::new();
        for proposer_id in netinfo.all_uids().iter().cloned() {
            agreement_instances.insert(
                proposer_id.clone(),
                Agreement::new(netinfo.clone(), session_id, proposer_id)?,
            );
        }

        Ok(CommonSubset {
            netinfo,
            broadcast_instances,
            agreement_instances,
            broadcast_results: BTreeMap::new(),
            agreement_results: BTreeMap::new(),
            messages: MessageQueue(VecDeque::new()),
            output: None,
            decided: false,
        })
    }

    /// Common Subset input message handler. It receives a value for broadcast
    /// and redirects it to the corresponding broadcast instance.
    pub fn send_proposed_value(&mut self, value: ProposedValue) -> CommonSubsetResult<()> {
        if !self.netinfo.is_validator() {
            return Ok(());
        }
        let uid = self.netinfo.our_uid().clone();
        // Upon receiving input v_i , input v_i to RBC_i. See Figure 2.
        self.process_broadcast(&uid, |bc| bc.input(value))
    }

    /// Receives a broadcast message from a remote node `sender_id` concerning a
    /// value proposed by the node `proposer_id`.
    fn handle_broadcast(
        &mut self,
        sender_id: &NodeUid,
        proposer_id: &NodeUid,
        bmessage: BroadcastMessage,
    ) -> CommonSubsetResult<()> {
        self.process_broadcast(proposer_id, |bc| bc.handle_message(sender_id, bmessage))
    }

    /// Receives an agreement message from a remote node `sender_id` concerning
    /// a value proposed by the node `proposer_id`.
    fn handle_agreement(
        &mut self,
        sender_id: &NodeUid,
        proposer_id: &NodeUid,
        amessage: AgreementMessage,
    ) -> CommonSubsetResult<()> {
        // Send the message to the local instance of Agreement
        self.process_agreement(proposer_id, |agreement| {
            agreement.handle_message(sender_id, amessage)
        })
    }

    /// Upon delivery of v_j from RBC_j, if input has not yet been provided to
    /// BA_j, then provide input 1 to BA_j. See Figure 11.
    fn process_broadcast<F>(&mut self, proposer_id: &NodeUid, f: F) -> CommonSubsetResult<()>
    where
        F: FnOnce(&mut Broadcast<NodeUid>) -> Result<(), broadcast::Error>,
    {
        let value = {
            let broadcast = self
                .broadcast_instances
                .get_mut(proposer_id)
                .ok_or(ErrorKind::NoSuchBroadcastInstance)?;
            f(broadcast)?;
            self.messages.extend_broadcast(&proposer_id, broadcast);
            if let Some(output) = broadcast.next_output() {
                output
            } else {
                return Ok(());
            }
        };
        self.broadcast_results.insert(proposer_id.clone(), value);
        self.process_agreement(proposer_id, |agreement| {
            if agreement.accepts_input() {
                agreement.set_input(true)
            } else {
                Ok(())
            }
        })
    }

    /// Callback to be invoked on receipt of the decision value of the Agreement
    /// instance `uid`.
    fn process_agreement<F>(&mut self, proposer_id: &NodeUid, f: F) -> CommonSubsetResult<()>
    where
        F: FnOnce(&mut Agreement<NodeUid>) -> Result<(), agreement::Error>,
    {
        let value = {
            let agreement = self
                .agreement_instances
                .get_mut(proposer_id)
                .ok_or(ErrorKind::NoSuchAgreementInstance)?;
            if agreement.terminated() {
                return Ok(());
            }
            f(agreement)?;
            self.messages.extend_agreement(proposer_id, agreement);
            if let Some(output) = agreement.next_output() {
                output
            } else {
                return Ok(());
            }
        };
        if self
            .agreement_results
            .insert(proposer_id.clone(), value)
            .is_some()
        {
            return Err(ErrorKind::MultipleAgreementResults.into());
        }
        debug!(
            "{:?} Updated Agreement results: {:?}",
            self.netinfo.our_uid(),
            self.agreement_results
        );

        if value && self.count_true() == self.netinfo.num_nodes() - self.netinfo.num_faulty() {
            // Upon delivery of value 1 from at least N − f instances of BA, provide
            // input 0 to each instance of BA that has not yet been provided input.
            for (uid, agreement) in &mut self.agreement_instances {
                if agreement.accepts_input() {
                    agreement.set_input(false)?;
                    self.messages.extend_agreement(uid, agreement);
                    if let Some(output) = agreement.next_output() {
                        if self.agreement_results.insert(uid.clone(), output).is_some() {
                            return Err(ErrorKind::MultipleAgreementResults.into());
                        }
                    }
                }
            }
        }
        self.try_agreement_completion();
        Ok(())
    }

    /// Returns the number of agreement instances that have decided "yes".
    fn count_true(&self) -> usize {
        self.agreement_results.values().filter(|v| **v).count()
    }

    fn try_agreement_completion(&mut self) {
        if self.decided || self.count_true() < self.netinfo.num_nodes() - self.netinfo.num_faulty()
        {
            return;
        }
        // Once all instances of BA have completed, let C ⊂ [1..N] be
        // the indexes of each BA that delivered 1. Wait for the output
        // v_j for each RBC_j such that j∈C. Finally output ∪ j∈C v_j.
        if self.agreement_results.len() < self.netinfo.num_nodes() {
            return;
        }
        debug!(
            "{:?} All Agreement instances have terminated",
            self.netinfo.our_uid()
        );
        // All instances of Agreement that delivered `true` (or "1" in the paper).
        let delivered_1: BTreeSet<&NodeUid> = self
            .agreement_results
            .iter()
            .filter(|(_, v)| **v)
            .map(|(k, _)| k)
            .collect();
        debug!("Agreement instances that delivered 1: {:?}", delivered_1);

        // Results of Broadcast instances in `delivered_1`
        let broadcast_results: BTreeMap<NodeUid, ProposedValue> = self
            .broadcast_results
            .iter()
            .filter(|(k, _)| delivered_1.contains(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        if delivered_1.len() == broadcast_results.len() {
            debug!(
                "{:?} Agreement instances completed:",
                self.netinfo.our_uid()
            );
            for (uid, result) in &broadcast_results {
                debug!("    {:?} → {:?}", uid, HexBytes(&result));
            }
            self.decided = true;
            self.output = Some(broadcast_results)
        }
    }
}
