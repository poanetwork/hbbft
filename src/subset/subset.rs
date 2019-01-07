use std::collections::BTreeMap;
use std::sync::Arc;
use std::{fmt, result};

use derivative::Derivative;
use hex_fmt::HexFmt;
use log::debug;
use serde_derive::Serialize;

use super::proposal_state::{ProposalState, Step as ProposalStep};
use super::{Error, FaultKind, Message, MessageContent, Result};
use crate::{util, DistAlgorithm, NetworkInfo, NodeIdT, SessionIdT};
use rand::Rng;

/// A `Subset` step, possibly containing several outputs.
pub type Step<N> = crate::Step<Message<N>, SubsetOutput<N>, N, FaultKind>;

/// An output with an accepted contribution or the end of the set.
#[derive(Derivative, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derivative(Debug)]
pub enum SubsetOutput<N> {
    /// A contribution was accepted into the set.
    Contribution(
        N,
        #[derivative(Debug(format_with = "util::fmt_hex"))] Vec<u8>,
    ),
    /// The set is complete.
    Done,
}

/// Subset algorithm instance
#[derive(Debug)]
pub struct Subset<N, S> {
    /// Shared network information.
    netinfo: Arc<NetworkInfo<N>>,
    /// The session identifier.
    session_id: S,
    /// A map that assigns to each validator the progress of their contribution.
    proposal_states: BTreeMap<N, ProposalState<N, S>>,
    /// Whether the instance has decided on a value.
    decided: bool,
}

impl<N: NodeIdT, S: SessionIdT> DistAlgorithm for Subset<N, S> {
    type NodeId = N;
    type Input = Vec<u8>;
    type Output = SubsetOutput<N>;
    type Message = Message<N>;
    type Error = Error;
    type FaultKind = FaultKind;

    fn handle_input<R: Rng>(&mut self, input: Self::Input, _rng: &mut R) -> Result<Step<N>> {
        self.propose(input)
    }

    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &N,
        message: Message<N>,
        _rng: &mut R,
    ) -> Result<Step<N>> {
        self.handle_message(sender_id, message)
    }

    fn terminated(&self) -> bool {
        self.decided
    }

    fn our_id(&self) -> &Self::NodeId {
        self.netinfo.our_id()
    }
}

impl<N: NodeIdT, S: SessionIdT> Subset<N, S> {
    /// Creates a new `Subset` instance with the given session identifier.
    ///
    /// If multiple `Subset`s are instantiated within a single network, they must use different
    /// session identifiers to foil replay attacks.
    pub fn new(netinfo: Arc<NetworkInfo<N>>, session_id: S) -> Result<Self> {
        let mut proposal_states = BTreeMap::new();
        for (proposer_idx, proposer_id) in netinfo.all_ids().enumerate() {
            let ba_id = BaSessionId {
                subset_id: session_id.clone(),
                proposer_idx: proposer_idx as u32,
            };
            proposal_states.insert(
                proposer_id.clone(),
                ProposalState::new(netinfo.clone(), ba_id, proposer_id.clone())?,
            );
        }

        Ok(Subset {
            netinfo,
            session_id,
            proposal_states,
            decided: false,
        })
    }

    /// Proposes a value for the subset.
    ///
    /// Returns an error if we already made a proposal.
    pub fn propose(&mut self, value: Vec<u8>) -> Result<Step<N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        debug!("{} proposing {:0.10}", self, HexFmt(&value));
        let prop_step = self
            .proposal_states
            .get_mut(self.netinfo.our_id())
            .ok_or(Error::UnknownProposer)?
            .propose(value)?;
        let step = Self::convert_step(self.netinfo.our_id(), prop_step);
        Ok(step.join(self.try_output()?))
    }

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message(&mut self, sender_id: &N, msg: Message<N>) -> Result<Step<N>> {
        let prop_step = self
            .proposal_states
            .get_mut(&msg.proposer_id)
            .ok_or(Error::UnknownProposer)?
            .handle_message(sender_id, msg.content)?;
        let step = Self::convert_step(&msg.proposer_id, prop_step);
        Ok(step.join(self.try_output()?))
    }

    /// Returns the number of validators from which we have already received a proposal.
    pub fn received_proposals(&self) -> usize {
        let received = |state: &&ProposalState<N, S>| state.received();
        self.proposal_states.values().filter(received).count()
    }

    fn convert_step(proposer_id: &N, prop_step: ProposalStep<N>) -> Step<N> {
        let from_p_msg = |p_msg: MessageContent| p_msg.with(proposer_id.clone());
        let mut step = Step::default();
        if let Some(value) = step.extend_with(prop_step, |fault| fault, from_p_msg).pop() {
            let contribution = SubsetOutput::Contribution(proposer_id.clone(), value);
            step.output.push(contribution);
        }
        step
    }

    /// Returns the number of Binary Agreement instances that have decided "yes".
    fn count_accepted(&self) -> usize {
        let accepted = |state: &&ProposalState<N, S>| state.accepted();
        self.proposal_states.values().filter(accepted).count()
    }

    /// Checks the voting and termination conditions: If enough proposals have been accepted, votes
    /// "no" for the remaining ones. If all proposals have been decided, outputs `Done`.
    fn try_output(&mut self) -> Result<Step<N>> {
        if self.decided || self.count_accepted() < self.netinfo.num_correct() {
            return Ok(Step::default());
        }
        let mut step = Step::default();
        if self.count_accepted() == self.netinfo.num_correct() {
            for (proposer_id, state) in &mut self.proposal_states {
                step.extend(Self::convert_step(proposer_id, state.vote_false()?));
            }
        }
        if self.proposal_states.values().all(ProposalState::complete) {
            self.decided = true;
            step.output.push(SubsetOutput::Done);
        }
        Ok(step)
    }
}

impl<N: NodeIdT, S: SessionIdT> fmt::Display for Subset<N, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{:?} Subset({})", self.our_id(), self.session_id)
    }
}

/// A session identifier for a `BinaryAgreement` instance run as a `Subset` sub-algorithm. It
/// consists of the `Subset` instance's own session ID, and the index of the proposer whose
/// contribution this `BinaryAgreement` is about.
#[derive(Clone, Debug, Serialize)]
pub struct BaSessionId<S> {
    subset_id: S,
    proposer_idx: u32,
}

impl<S: fmt::Display> fmt::Display for BaSessionId<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(
            f,
            "subset {}, proposer #{}",
            self.subset_id, self.proposer_idx
        )
    }
}
