//! # Subset algorithm.
//!
//! The Subset protocol assumes a network of _N_ nodes that send signed
//! messages to each other, with at most _f_ of them malicious, where _3 f < N_. Handling the
//! networking and signing is the responsibility of the user: only when a message has been
//! verified to be "from node i" (e.g. using cryptographic signatures), it can be handed to the
//! `Subset` instance.
//!
//! Each node proposes an element for inclusion. Under the above conditions, the protocol
//! guarantees that all correct nodes output the same set, consisting of at least _N - f_ of the
//! proposed elements.
//!
//! ## How it works
//!
//! * `Subset` instantiates one `Broadcast` algorithm for each of the participating nodes.
//! At least _N - f_ of these - the ones whose proposer is not faulty - will eventually output
//! the element proposed by that node.
//! * It also instantiates Binary Agreement for each participating node, to decide whether
//! that node's proposed element should be included in the set. Whenever an element is
//! received via broadcast, we input "yes" (`true`) into the corresponding `BinaryAgreement` instance.
//! * When _N - f_ `BinaryAgreement` instances have decided "yes", we input "no" (`false`) into the
//! remaining ones, where we haven't provided input yet.
//! * Once all `BinaryAgreement` instances have decided, `Subset` returns the set of all proposed
//! values for which the decision was "yes".

use std::collections::{BTreeMap, BTreeSet};
use std::result;
use std::sync::Arc;

use hex_fmt::HexFmt;

use binary_agreement::{self, BinaryAgreement};
use broadcast::{self, Broadcast};
use rand::Rand;
use {DistAlgorithm, NetworkInfo, NodeIdT};

/// A subset error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "NewBinaryAgreement error: {}", _0)]
    NewBinaryAgreement(binary_agreement::Error),
    #[fail(display = "ProcessBinaryAgreement0 error: {}", _0)]
    ProcessBinaryAgreement0(binary_agreement::Error),
    #[fail(display = "ProcessBinaryAgreement1 error: {}", _0)]
    ProcessBinaryAgreement1(binary_agreement::Error),
    #[fail(display = "NewBroadcast error: {}", _0)]
    NewBroadcast(broadcast::Error),
    #[fail(display = "ProcessBroadcastBroadcast error: {}", _0)]
    ProcessBroadcastBroadcast(broadcast::Error),
    #[fail(display = "Multiple Binary Agreement results")]
    MultipleBinaryAgreementResults,
    #[fail(display = "No such Binary Agreement instance")]
    NoSuchBinaryAgreementInstance,
    #[fail(display = "No such broadcast instance")]
    NoSuchBroadcastInstance,
}

/// A subset result.
pub type Result<T> = ::std::result::Result<T, Error>;

// TODO: Make this a generic argument of `Subset`.
type ProposedValue = Vec<u8>;

/// Message from Subset to remote nodes.
#[derive(Serialize, Deserialize, Clone, Debug, Rand)]
pub enum Message<N: Rand> {
    /// A message for the broadcast algorithm concerning the set element proposed by the given node.
    Broadcast(N, broadcast::Message),
    /// A message for the Binary Agreement algorithm concerning the set element proposed by the given
    /// node.
    BinaryAgreement(N, binary_agreement::Message),
}

/// Subset algorithm instance
#[derive(Debug)]
pub struct Subset<N: Rand> {
    /// Shared network information.
    netinfo: Arc<NetworkInfo<N>>,
    broadcast_instances: BTreeMap<N, Broadcast<N>>,
    ba_instances: BTreeMap<N, BinaryAgreement<N>>,
    /// `None` means that that item has already been output.
    broadcast_results: BTreeMap<N, Option<ProposedValue>>,
    ba_results: BTreeMap<N, bool>,
    /// Whether the instance has decided on a value.
    decided: bool,
}

pub type Step<N> = ::Step<Subset<N>>;

impl<N: NodeIdT + Rand> DistAlgorithm for Subset<N> {
    type NodeId = N;
    type Input = ProposedValue;
    type Output = SubsetOutput<N>;
    type Message = Message<N>;
    type Error = Error;

    fn handle_input(&mut self, input: Self::Input) -> Result<Step<N>> {
        debug!("{:?} Proposing {:?}", self.netinfo.our_id(), HexFmt(&input));
        self.send_proposed_value(input)
    }

    fn handle_message(
        &mut self,
        sender_id: &Self::NodeId,
        message: Self::Message,
    ) -> Result<Step<N>> {
        match message {
            Message::Broadcast(p_id, b_msg) => self.handle_broadcast(sender_id, &p_id, b_msg),
            Message::BinaryAgreement(p_id, a_msg) => {
                self.handle_binary_agreement(sender_id, &p_id, a_msg)
            }
        }
    }

    fn terminated(&self) -> bool {
        self.ba_instances.values().all(BinaryAgreement::terminated)
    }

    fn our_id(&self) -> &Self::NodeId {
        self.netinfo.our_id()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubsetOutput<N> {
    Contribution(N, Vec<u8>),
    Done,
}

impl<N: NodeIdT + Rand> Subset<N> {
    pub fn new(netinfo: Arc<NetworkInfo<N>>, session_id: u64) -> Result<Self> {
        // Create all broadcast instances.
        let mut broadcast_instances: BTreeMap<N, Broadcast<N>> = BTreeMap::new();
        for proposer_id in netinfo.all_ids() {
            broadcast_instances.insert(
                proposer_id.clone(),
                Broadcast::new(netinfo.clone(), proposer_id.clone())
                    .map_err(Error::NewBroadcast)?,
            );
        }

        // Create all Binary Agreement instances.
        let mut ba_instances: BTreeMap<N, BinaryAgreement<N>> = BTreeMap::new();
        for proposer_id in netinfo.all_ids() {
            ba_instances.insert(
                proposer_id.clone(),
                BinaryAgreement::new(netinfo.clone(), session_id, proposer_id.clone())
                    .map_err(Error::NewBinaryAgreement)?,
            );
        }

        Ok(Subset {
            netinfo,
            broadcast_instances,
            ba_instances,
            broadcast_results: BTreeMap::new(),
            ba_results: BTreeMap::new(),
            decided: false,
        })
    }

    /// Subset input message handler. It receives a value for broadcast
    /// and redirects it to the corresponding broadcast instance.
    pub fn send_proposed_value(&mut self, value: ProposedValue) -> Result<Step<N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        let id = self.netinfo.our_id().clone();
        // Upon receiving input v_i , input v_i to RBC_i. See Figure 2.
        self.process_broadcast(&id, |bc| bc.handle_input(value))
    }

    /// Returns the number of validators from which we have already received a proposal.
    pub(crate) fn received_proposals(&self) -> usize {
        self.broadcast_results.len()
    }

    /// Receives a broadcast message from a remote node `sender_id` concerning a
    /// value proposed by the node `proposer_id`.
    fn handle_broadcast(
        &mut self,
        sender_id: &N,
        proposer_id: &N,
        bmessage: broadcast::Message,
    ) -> Result<Step<N>> {
        self.process_broadcast(proposer_id, |bc| bc.handle_message(sender_id, bmessage))
    }

    /// Receives a Binary Agreement message from a remote node `sender_id` concerning
    /// a value proposed by the node `proposer_id`.
    fn handle_binary_agreement(
        &mut self,
        sender_id: &N,
        proposer_id: &N,
        amessage: binary_agreement::Message,
    ) -> Result<Step<N>> {
        // Send the message to the local instance of Binary Agreement.
        self.process_binary_agreement(proposer_id, |binary_agreement| {
            binary_agreement.handle_message(sender_id, amessage)
        })
    }

    /// Upon delivery of v_j from RBC_j, if input has not yet been provided to
    /// BA_j, then provide input 1 to BA_j. See Figure 11.
    fn process_broadcast<F>(&mut self, proposer_id: &N, f: F) -> Result<Step<N>>
    where
        F: FnOnce(&mut Broadcast<N>) -> result::Result<broadcast::Step<N>, broadcast::Error>,
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

        let val_to_insert = if let Some(true) = self.ba_results.get(proposer_id) {
            debug!("    {:?} → {:?}", proposer_id, HexFmt(&value));
            step.output
                .extend(Some(SubsetOutput::Contribution(proposer_id.clone(), value)));
            None
        } else {
            Some(value)
        };

        if let Some(inval) = self
            .broadcast_results
            .insert(proposer_id.clone(), val_to_insert)
        {
            error!("Duplicate insert in broadcast_results: {:?}", inval)
        }
        let set_binary_agreement_input = |ba: &mut BinaryAgreement<N>| {
            if ba.accepts_input() {
                ba.handle_input(true)
            } else {
                Ok(binary_agreement::Step::default())
            }
        };
        step.extend(self.process_binary_agreement(proposer_id, set_binary_agreement_input)?);
        Ok(step)
    }

    /// Callback to be invoked on receipt of the decision value of the Binary Agreement
    /// instance `id`.
    fn process_binary_agreement<F>(&mut self, proposer_id: &N, f: F) -> Result<Step<N>>
    where
        F: FnOnce(&mut BinaryAgreement<N>) -> binary_agreement::Result<binary_agreement::Step<N>>,
    {
        let mut step = Step::default();
        let accepted = {
            let binary_agreement = self
                .ba_instances
                .get_mut(proposer_id)
                .ok_or(Error::NoSuchBinaryAgreementInstance)?;
            if binary_agreement.terminated() {
                return Ok(step);
            }
            let to_msg = |a_msg| Message::BinaryAgreement(proposer_id.clone(), a_msg);
            let output = step.extend_with(
                f(binary_agreement).map_err(Error::ProcessBinaryAgreement0)?,
                to_msg,
            );
            if let Some(accepted) = output.into_iter().next() {
                accepted
            } else {
                return Ok(step);
            }
        };

        // Binary agreement result accepted.
        if self
            .ba_results
            .insert(proposer_id.clone(), accepted)
            .is_some()
        {
            return Err(Error::MultipleBinaryAgreementResults);
        }

        debug!(
            "{:?} Updated Binary Agreement results: {:?}",
            self.netinfo.our_id(),
            self.ba_results
        );

        if accepted {
            if self.count_true() == self.netinfo.num_correct() {
                // Upon delivery of value 1 from at least N − f instances of BA, provide
                // input 0 to each instance of BA that has not yet been provided input.
                for (id, binary_agreement) in &mut self.ba_instances {
                    if binary_agreement.accepts_input() {
                        let to_msg = |a_msg| Message::BinaryAgreement(id.clone(), a_msg);
                        for output in step.extend_with(
                            binary_agreement
                                .handle_input(false)
                                .map_err(Error::ProcessBinaryAgreement1)?,
                            to_msg,
                        ) {
                            if self.ba_results.insert(id.clone(), output).is_some() {
                                return Err(Error::MultipleBinaryAgreementResults);
                            }
                        }
                    }
                }
            }
            if let Some(Some(value)) = self.broadcast_results.insert(proposer_id.clone(), None) {
                debug!("    {:?} → {:?}", proposer_id, HexFmt(&value));
                step.output
                    .extend(Some(SubsetOutput::Contribution(proposer_id.clone(), value)));
            }
        }

        step.output.extend(self.try_binary_agreement_completion());
        Ok(step)
    }

    /// Returns the number of Binary Agreement instances that have decided "yes".
    fn count_true(&self) -> usize {
        self.ba_results.values().filter(|v| **v).count()
    }

    fn try_binary_agreement_completion(&mut self) -> Option<SubsetOutput<N>> {
        if self.decided || self.count_true() < self.netinfo.num_correct() {
            return None;
        }
        // Once all instances of BA have completed, let C ⊂ [1..N] be
        // the indexes of each BA that delivered 1. Wait for the output
        // v_j for each RBC_j such that j∈C. Finally output ∪ j∈C v_j.
        if self.ba_results.len() < self.netinfo.num_nodes() {
            return None;
        }
        debug!(
            "{:?} All Binary Agreement instances have terminated",
            self.netinfo.our_id()
        );
        // All instances of BinaryAgreement that delivered `true` (or "1" in the paper).
        let delivered_1: BTreeSet<&N> = self
            .ba_results
            .iter()
            .filter(|(_, v)| **v)
            .map(|(k, _)| k)
            .collect();
        debug!(
            "Binary Agreement instances that delivered 1: {:?}",
            delivered_1
        );

        // Results of Broadcast instances in `delivered_1`
        let broadcast_results: BTreeSet<&N> = self
            .broadcast_results
            .iter()
            .filter(|(k, _)| delivered_1.contains(k))
            .map(|(k, _)| k)
            .collect();

        if delivered_1.len() == broadcast_results.len() {
            debug!(
                "{:?} Binary Agreement instances completed:",
                self.netinfo.our_id()
            );
            self.decided = true;
            Some(SubsetOutput::Done)
        } else {
            None
        }
    }
}
