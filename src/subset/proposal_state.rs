use std::mem;
use std::sync::Arc;

use super::subset::BaSessionId;
use super::{Error, FaultKind, MessageContent, Result};
use crate::binary_agreement;
use crate::broadcast::{self, Broadcast};
use crate::{NetworkInfo, NodeIdT, SessionIdT};

type BaInstance<N, S> = binary_agreement::BinaryAgreement<N, BaSessionId<S>>;
type ValueAndStep<N> = (Option<Vec<u8>>, Step<N>);
type BaResult<N> = binary_agreement::Result<binary_agreement::Step<N>>;

pub type Step<N> = crate::Step<MessageContent, Vec<u8>, N, FaultKind>;

/// The state of a proposal's broadcast and agreement process.
#[derive(Debug)]
pub enum ProposalState<N, S> {
    /// We are still awaiting the value from the `Broadcast` protocol and the decision from
    /// `BinaryAgreement`.
    Ongoing(Broadcast<N>, BaInstance<N, S>),
    /// We received the value but are still waiting for `BinaryAgreement`, whether to output.
    HasValue(Vec<u8>, BaInstance<N, S>),
    /// The values has been accepted, but we haven't received it yet.
    Accepted(Broadcast<N>),
    /// We are done: either we output (`true`) or we dropped the value (`false`).
    Complete(bool),
}

impl<N: NodeIdT, S: SessionIdT> ProposalState<N, S> {
    /// Creates a new `ProposalState::Ongoing`, with a fresh broadcast and agreement instance.
    pub fn new(netinfo: Arc<NetworkInfo<N>>, ba_id: BaSessionId<S>, prop_id: N) -> Result<Self> {
        let agreement = BaInstance::new(netinfo.clone(), ba_id).map_err(Error::NewAgreement)?;
        let broadcast = Broadcast::new(netinfo, prop_id).map_err(Error::NewBroadcast)?;
        Ok(ProposalState::Ongoing(broadcast, agreement))
    }

    /// Returns `true` if we already received the `Broadcast` result.
    pub fn received(&self) -> bool {
        match self {
            ProposalState::Ongoing(_, _) | ProposalState::Accepted(_) => false,
            ProposalState::HasValue(_, _) => true,
            ProposalState::Complete(accepted) => *accepted,
        }
    }

    /// Returns `true` if this proposal has been accepted, even if we don't have the value yet.
    pub fn accepted(&self) -> bool {
        match self {
            ProposalState::Ongoing(_, _) | ProposalState::HasValue(_, _) => false,
            ProposalState::Accepted(_) => true,
            ProposalState::Complete(accepted) => *accepted,
        }
    }

    /// Returns `true` if this proposal has been rejected, or accepted and output.
    pub fn complete(&self) -> bool {
        match self {
            ProposalState::Ongoing(_, _)
            | ProposalState::HasValue(_, _)
            | ProposalState::Accepted(_) => false,
            ProposalState::Complete(_) => true,
        }
    }

    /// Makes a proposal by broadcasting a value.
    pub fn propose(&mut self, value: Vec<u8>) -> Result<Step<N>> {
        self.transition(|state| state.handle_broadcast(|bc| bc.broadcast(value)))
    }

    /// Handles a message received from `sender_id`.
    pub fn handle_message(&mut self, sender_id: &N, msg: MessageContent) -> Result<Step<N>> {
        self.transition(|state| match msg {
            MessageContent::Agreement(ba_msg) => {
                state.handle_agreement(|ba| ba.handle_message(sender_id, ba_msg))
            }
            MessageContent::Broadcast(bc_msg) => {
                state.handle_broadcast(|bc| bc.handle_message(sender_id, bc_msg))
            }
        })
    }

    /// Votes for rejecting the proposal, if still possible.
    pub fn vote_false(&mut self) -> Result<Step<N>> {
        self.transition(|state| state.handle_agreement(|ba| ba.propose(false)))
    }

    /// Applies `f` to the `Broadcast` instance, and updates the state according to the outcome.
    fn handle_broadcast<F>(self, f: F) -> (Self, Result<Step<N>>)
    where
        F: FnOnce(&mut Broadcast<N>) -> broadcast::Result<broadcast::Step<N>>,
    {
        use self::ProposalState::*;
        match self {
            Ongoing(mut bc, ba) => match Self::convert_bc(f(&mut bc)) {
                Err(err) => (Ongoing(bc, ba), Err(err)),
                Ok((None, step)) => (Ongoing(bc, ba), Ok(step)),
                Ok((Some(value), step)) => {
                    let state = HasValue(value, ba);
                    let (state, result) = state.handle_agreement(|ba| ba.propose(true));
                    (state, result.map(|vote_step| step.join(vote_step)))
                }
            },
            Accepted(mut bc) => match Self::convert_bc(f(&mut bc)) {
                Err(err) => (Accepted(bc), Err(err)),
                Ok((None, step)) => (Accepted(bc), Ok(step)),
                Ok((Some(value), step)) => (Complete(true), Ok(step.with_output(value))),
            },
            state @ HasValue(_, _) | state @ Complete(_) => (state, Ok(Step::default())),
        }
    }

    /// Applies `f` to the `BinaryAgreement` instance, and updates the state according to the
    /// outcome.
    fn handle_agreement<F>(self, f: F) -> (Self, Result<Step<N>>)
    where
        F: FnOnce(&mut BaInstance<N, S>) -> BaResult<N>,
    {
        use self::ProposalState::*;
        match self {
            Ongoing(bc, mut ba) => match Self::convert_ba(f(&mut ba)) {
                Err(err) => (Ongoing(bc, ba), Err(err)),
                Ok((None, step)) => (Ongoing(bc, ba), Ok(step)),
                Ok((Some(false), step)) => (Complete(false), Ok(step)),
                Ok((Some(true), step)) => (Accepted(bc), Ok(step)),
            },
            HasValue(value, mut ba) => match Self::convert_ba(f(&mut ba)) {
                Err(err) => (HasValue(value, ba), Err(err)),
                Ok((None, step)) => (HasValue(value, ba), Ok(step)),
                Ok((Some(false), step)) => (Complete(false), Ok(step)),
                Ok((Some(true), step)) => (Complete(true), Ok(step.with_output(value))),
            },
            state @ Accepted(_) | state @ Complete(_) => (state, Ok(Step::default())),
        }
    }

    /// Converts a `Broadcast` result and returns the output, if there was one.
    fn convert_bc(result: broadcast::Result<broadcast::Step<N>>) -> Result<ValueAndStep<N>> {
        let bc_step = result.map_err(Error::HandleBroadcast)?;
        let mut step = Step::default();
        let opt_value = step
            .extend_with(
                bc_step,
                FaultKind::BroadcastFault,
                MessageContent::Broadcast,
            )
            .pop();
        Ok((opt_value, step))
    }

    /// Converts a `BinaryAgreement` step and returns the output, if there was one.
    fn convert_ba(result: BaResult<N>) -> Result<(Option<bool>, Step<N>)> {
        let ba_step = result.map_err(Error::HandleAgreement)?;
        let mut step = Step::default();
        let opt_decision = step
            .extend_with(ba_step, FaultKind::BaFault, MessageContent::Agreement)
            .pop();
        Ok((opt_decision, step))
    }

    /// Applies the given transition to `self`.
    fn transition<F>(&mut self, f: F) -> Result<Step<N>>
    where
        F: FnOnce(Self) -> (Self, Result<Step<N>>),
    {
        // Temporary value: We need to take ownership of the state to make it transition.
        let (new_state, result) = f(mem::replace(self, ProposalState::Complete(false)));
        *self = new_state;
        result
    }
}
