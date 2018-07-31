//! # Asynchronous Common Subset algorithm.
//!
//! The Asynchronous Common Subset protocol assumes a network of _N_ nodes that send signed
//! messages to each other, with at most _f_ of them malicious, where _3 f < N_. Handling the
//! networking and signing is the responsibility of the user: only when a message has been
//! verified to be "from node i" (e.g. using cryptographic signatures), it can be handed to the
//! `CommonSubset` instance.
//!
//! Each node proposes an element for inclusion. Under the above conditions, the protocol
//! guarantees that all correct nodes output the same set, consisting of at least _N - f_ of the
//! proposed elements.
//!
//! ## How it works
//!
//! * `CommonSubset` instantiates one `Broadcast` algorithm for each of the participating nodes.
//! At least _N - f_ of these - the ones whose proposer is not faulty - will eventually output
//! the element proposed by that node.
//! * It also instantiates Binary Agreement for each participating node, to decide whether
//! that node's proposed element should be included in the common set. Whenever an element is
//! received via broadcast, we input "yes" (`true`) into the corresponding `Agreement` instance.
//! * When _N - f_ `Agreement` instances have decided "yes", we input "no" (`false`) into the
//! remaining ones, where we haven't provided input yet.
//! * Once all `Agreement` instances have decided, `CommonSubset` returns the set of all proposed
//! values for which the decision was "yes".

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::result;
use std::sync::Arc;

use agreement::{self, Agreement, AgreementMessage};
use broadcast::{self, Broadcast, BroadcastMessage};
use fmt::HexBytes;
use messaging::{self, DistAlgorithm, NetworkInfo};
use rand::Rand;

/// A common subset error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "NewAgreement error: {}", _0)]
    NewAgreement(agreement::Error),
    #[fail(display = "ProcessAgreementAgreement0 error: {}", _0)]
    ProcessAgreementAgreement0(agreement::Error),
    #[fail(display = "ProcessAgreementAgreement1 error: {}", _0)]
    ProcessAgreementAgreement1(agreement::Error),
    #[fail(display = "NewBroadcast error: {}", _0)]
    NewBroadcast(broadcast::Error),
    #[fail(display = "ProcessBroadcastBroadcast error: {}", _0)]
    ProcessBroadcastBroadcast(broadcast::Error),
    #[fail(display = "Multiple agreement results")]
    MultipleAgreementResults,
    #[fail(display = "No such agreement instance")]
    NoSuchAgreementInstance,
    #[fail(display = "No such broadcast instance")]
    NoSuchBroadcastInstance,
}

/// A common subset result.
pub type Result<T> = ::std::result::Result<T, Error>;

// TODO: Make this a generic argument of `CommonSubset`.
type ProposedValue = Vec<u8>;

/// Message from Common Subset to remote nodes.
#[derive(Serialize, Deserialize, Clone, Debug, Rand)]
pub enum Message<NodeUid: Rand> {
    /// A message for the broadcast algorithm concerning the set element proposed by the given node.
    Broadcast(NodeUid, BroadcastMessage),
    /// A message for the agreement algorithm concerning the set element proposed by the given
    /// node.
    Agreement(NodeUid, AgreementMessage),
}

/// Asynchronous Common Subset algorithm instance
#[derive(Debug)]
pub struct CommonSubset<NodeUid: Rand> {
    /// Shared network information.
    netinfo: Arc<NetworkInfo<NodeUid>>,
    broadcast_instances: BTreeMap<NodeUid, Broadcast<NodeUid>>,
    agreement_instances: BTreeMap<NodeUid, Agreement<NodeUid>>,
    broadcast_results: BTreeMap<NodeUid, ProposedValue>,
    agreement_results: BTreeMap<NodeUid, bool>,
    /// Whether the instance has decided on a value.
    decided: bool,
}

pub type Step<NodeUid> = messaging::Step<CommonSubset<NodeUid>>;

impl<NodeUid: Clone + Debug + Ord + Rand> DistAlgorithm for CommonSubset<NodeUid> {
    type NodeUid = NodeUid;
    type Input = ProposedValue;
    type Output = BTreeMap<NodeUid, ProposedValue>;
    type Message = Message<NodeUid>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<Step<NodeUid>> {
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
    ) -> Result<Step<NodeUid>> {
        match message {
            Message::Broadcast(p_id, b_msg) => self.handle_broadcast(sender_id, &p_id, b_msg),
            Message::Agreement(p_id, a_msg) => self.handle_agreement(sender_id, &p_id, a_msg),
        }
    }

    fn terminated(&self) -> bool {
        self.agreement_instances.values().all(Agreement::terminated)
    }

    fn our_id(&self) -> &Self::NodeUid {
        self.netinfo.our_uid()
    }
}

impl<NodeUid: Clone + Debug + Ord + Rand> CommonSubset<NodeUid> {
    pub fn new(netinfo: Arc<NetworkInfo<NodeUid>>, session_id: u64) -> Result<Self> {
        // Create all broadcast instances.
        let mut broadcast_instances: BTreeMap<NodeUid, Broadcast<NodeUid>> = BTreeMap::new();
        for proposer_id in netinfo.all_uids() {
            broadcast_instances.insert(
                proposer_id.clone(),
                Broadcast::new(netinfo.clone(), proposer_id.clone()).map_err(Error::NewBroadcast)?,
            );
        }

        // Create all agreement instances.
        let mut agreement_instances: BTreeMap<NodeUid, Agreement<NodeUid>> = BTreeMap::new();
        for proposer_id in netinfo.all_uids() {
            agreement_instances.insert(
                proposer_id.clone(),
                Agreement::new(netinfo.clone(), session_id, proposer_id.clone())
                    .map_err(Error::NewAgreement)?,
            );
        }

        Ok(CommonSubset {
            netinfo,
            broadcast_instances,
            agreement_instances,
            broadcast_results: BTreeMap::new(),
            agreement_results: BTreeMap::new(),
            decided: false,
        })
    }

    /// Common Subset input message handler. It receives a value for broadcast
    /// and redirects it to the corresponding broadcast instance.
    pub fn send_proposed_value(&mut self, value: ProposedValue) -> Result<Step<NodeUid>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
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
    ) -> Result<Step<NodeUid>> {
        self.process_broadcast(proposer_id, |bc| bc.handle_message(sender_id, bmessage))
    }

    /// Receives an agreement message from a remote node `sender_id` concerning
    /// a value proposed by the node `proposer_id`.
    fn handle_agreement(
        &mut self,
        sender_id: &NodeUid,
        proposer_id: &NodeUid,
        amessage: AgreementMessage,
    ) -> Result<Step<NodeUid>> {
        // Send the message to the local instance of Agreement
        self.process_agreement(proposer_id, |agreement| {
            agreement.handle_message(sender_id, amessage)
        })
    }

    /// Upon delivery of v_j from RBC_j, if input has not yet been provided to
    /// BA_j, then provide input 1 to BA_j. See Figure 11.
    fn process_broadcast<F>(&mut self, proposer_id: &NodeUid, f: F) -> Result<Step<NodeUid>>
    where
        F: FnOnce(&mut Broadcast<NodeUid>)
            -> result::Result<broadcast::Step<NodeUid>, broadcast::Error>,
    {
        let mut step = Step::default();
        let value = {
            let broadcast = self
                .broadcast_instances
                .get_mut(proposer_id)
                .ok_or(Error::NoSuchBroadcastInstance)?;
            let to_msg = |b_msg| Message::Broadcast(proposer_id.clone(), b_msg);
            let output = step.extend_with(
                f(broadcast).map_err(Error::ProcessBroadcastBroadcast)?,
                to_msg,
            );
            if let Some(output) = output.into_iter().next() {
                output
            } else {
                return Ok(step);
            }
        };
        self.broadcast_results.insert(proposer_id.clone(), value);
        let set_agreement_input = |agreement: &mut Agreement<NodeUid>| {
            if agreement.accepts_input() {
                agreement.input(true)
            } else {
                Ok(agreement::Step::default())
            }
        };
        step.extend(self.process_agreement(proposer_id, set_agreement_input)?);
        Ok(step)
    }

    /// Callback to be invoked on receipt of the decision value of the Agreement
    /// instance `uid`.
    fn process_agreement<F>(&mut self, proposer_id: &NodeUid, f: F) -> Result<Step<NodeUid>>
    where
        F: FnOnce(&mut Agreement<NodeUid>)
            -> result::Result<agreement::Step<NodeUid>, agreement::Error>,
    {
        let mut step = Step::default();
        let value = {
            let agreement = self
                .agreement_instances
                .get_mut(proposer_id)
                .ok_or(Error::NoSuchAgreementInstance)?;
            if agreement.terminated() {
                return Ok(step);
            }
            let to_msg = |a_msg| Message::Agreement(proposer_id.clone(), a_msg);
            let output = step.extend_with(
                f(agreement).map_err(Error::ProcessAgreementAgreement0)?,
                to_msg,
            );
            if let Some(output) = output.into_iter().next() {
                output
            } else {
                return Ok(step);
            }
        };
        if self
            .agreement_results
            .insert(proposer_id.clone(), value)
            .is_some()
        {
            return Err(Error::MultipleAgreementResults);
        }
        debug!(
            "{:?} Updated Agreement results: {:?}",
            self.netinfo.our_uid(),
            self.agreement_results
        );

        if value && self.count_true() == self.netinfo.num_correct() {
            // Upon delivery of value 1 from at least N − f instances of BA, provide
            // input 0 to each instance of BA that has not yet been provided input.
            for (uid, agreement) in &mut self.agreement_instances {
                if agreement.accepts_input() {
                    let to_msg = |a_msg| Message::Agreement(uid.clone(), a_msg);
                    for output in step.extend_with(
                        agreement
                            .input(false)
                            .map_err(Error::ProcessAgreementAgreement1)?,
                        to_msg,
                    ) {
                        if self.agreement_results.insert(uid.clone(), output).is_some() {
                            return Err(Error::MultipleAgreementResults);
                        }
                    }
                }
            }
        }
        step.output.extend(self.try_agreement_completion());
        Ok(step)
    }

    /// Returns the number of agreement instances that have decided "yes".
    fn count_true(&self) -> usize {
        self.agreement_results.values().filter(|v| **v).count()
    }

    fn try_agreement_completion(&mut self) -> Option<BTreeMap<NodeUid, ProposedValue>> {
        if self.decided || self.count_true() < self.netinfo.num_correct() {
            return None;
        }
        // Once all instances of BA have completed, let C ⊂ [1..N] be
        // the indexes of each BA that delivered 1. Wait for the output
        // v_j for each RBC_j such that j∈C. Finally output ∪ j∈C v_j.
        if self.agreement_results.len() < self.netinfo.num_nodes() {
            return None;
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
            Some(broadcast_results)
        } else {
            None
        }
    }
}
