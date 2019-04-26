//! Test network errors

use std::fmt::{self, Debug, Display};
use std::time;

use failure;
use threshold_crypto as crypto;

use hbbft::ConsensusProtocol;

use super::NetMessage;

/// Network crank error.
///
/// Errors resulting from processing a single message ("cranking").
pub enum CrankError<D>
where
    D: ConsensusProtocol,
{
    /// The algorithm run by the node produced a `ConsensusProtocol::Error` while processing input.
    HandleInput(D::Error),
    /// The algorithm run by the node produced a `ConsensusProtocol::Error` while processing input to
    /// all nodes.
    HandleInputAll(D::Error),
    /// The algorithm run by the node produced a `ConsensusProtocol::Error` while processing a message.
    HandleMessage {
        /// Network message that triggered the error.
        msg: NetMessage<D>,
        err: D::Error,
    },
    /// As spotted during cranking, a node unexpectly disappeared from the list of nodes. Note that
    /// this is likely a bug in the network framework code.
    NodeDisappearedInCrank(D::NodeId),
    /// As spotted during message dispatch, a node unexpectly disappeared from the list of
    /// nodes. Note that this is likely a bug in the network framework code.
    NodeDisappearedInDispatch(D::NodeId),
    /// The configured maximum number of cranks has been reached or exceeded.
    CrankLimitExceeded(usize),
    /// The configured maximum number of messages has been reached or exceeded.
    MessageLimitExceeded(usize),
    /// The execution time limit has been reached or exceeded.
    TimeLimitHit(time::Duration),
    /// A `Fault` was reported by a correct node in a step of a `ConsensusProtocol`.
    Fault {
        /// The ID of the node that reported the fault.
        reported_by: D::NodeId,
        /// The ID of the faulty node.
        faulty_id: D::NodeId,
        /// The reported fault.
        fault_kind: D::FaultKind,
    },
    /// An error occurred while generating initial keys for threshold cryptography.
    InitialKeyGeneration(crypto::error::Error),
}

// Note: Deriving [Debug](std::fmt::Debug), [Fail](failure::Fail) and through that,
//       [Debug](std::fmt::Debug) automatically does not work due to the wrongly required trait
//       bound of `D: ConsensusProtocol` implementing the respective Trait. For this reason, these
//       three traits are implemented manually.
//
//       More details at
//
//       * <https://github.com/rust-lang/rust/issues/26925>
//       * <https://github.com/rust-lang/rust/issues/26925#issuecomment-405189266>
impl<D> Display for CrankError<D>
where
    D: ConsensusProtocol,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrankError::HandleInput(err) => {
                write!(f, "The algorithm could not process input: {:?}", err)
            }
            CrankError::HandleInputAll(err) => write!(
                f,
                "The algorithm could not process input to all nodes: {:?}",
                err
            ),
            CrankError::HandleMessage { msg, err } => write!(
                f,
                "The algorithm could not process network message {:?}. Error: {:?}",
                msg, err
            ),
            CrankError::NodeDisappearedInCrank(id) => write!(
                f,
                "Node {:?} disappeared or never existed, while it was cranked.",
                id
            ),
            CrankError::NodeDisappearedInDispatch(id) => write!(
                f,
                "Node {:?} disappeared or never existed, while it still had incoming messages.",
                id
            ),
            CrankError::CrankLimitExceeded(max) => {
                write!(f, "Maximum number of cranks exceeded: {}", max)
            }
            CrankError::MessageLimitExceeded(max) => {
                write!(f, "Maximum number of messages exceeded: {}", max)
            }
            CrankError::TimeLimitHit(lim) => {
                write!(f, "Time limit of {} seconds exceeded.", lim.as_secs())
            }
            CrankError::Fault {
                reported_by,
                faulty_id,
                fault_kind,
            } => write!(
                f,
                "Correct node {:?} reported node {:?} as faulty: {:?}.",
                reported_by, faulty_id, fault_kind
            ),
            CrankError::InitialKeyGeneration(err) => write!(
                f,
                "An error occurred while generating initial keys for threshold cryptography: {:?}.",
                err
            ),
        }
    }
}

impl<D> Debug for CrankError<D>
where
    D: ConsensusProtocol,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrankError::HandleInput(err) => {
                f.debug_struct("HandleInput").field("err", err).finish()
            }
            CrankError::HandleInputAll(err) => {
                f.debug_struct("HandleInputAll").field("err", err).finish()
            }
            CrankError::HandleMessage { msg, err } => f
                .debug_struct("HandleMessage")
                .field("msg", msg)
                .field("err", err)
                .finish(),
            CrankError::NodeDisappearedInCrank(id) => {
                f.debug_tuple("NodeDisappearedInCrank").field(id).finish()
            }
            CrankError::NodeDisappearedInDispatch(id) => f
                .debug_tuple("NodeDisappearedInDispatch")
                .field(id)
                .finish(),
            CrankError::CrankLimitExceeded(max) => {
                f.debug_tuple("CrankLimitExceeded").field(max).finish()
            }
            CrankError::MessageLimitExceeded(max) => {
                f.debug_tuple("MessageLimitExceeded").field(max).finish()
            }
            CrankError::TimeLimitHit(lim) => f.debug_tuple("TimeLimitHit").field(lim).finish(),
            CrankError::Fault {
                reported_by,
                faulty_id,
                fault_kind,
            } => f
                .debug_struct("Fault")
                .field("reported_by", reported_by)
                .field("faulty_id", faulty_id)
                .field("fault_kind", fault_kind)
                .finish(),
            CrankError::InitialKeyGeneration(err) => {
                f.debug_tuple("InitialKeyGeneration").field(err).finish()
            }
        }
    }
}

impl<D> failure::Fail for CrankError<D>
where
    D: ConsensusProtocol + 'static,
{
    fn cause(&self) -> Option<&dyn failure::Fail> {
        match self {
            CrankError::HandleInput(err) | CrankError::HandleInputAll(err) => Some(err),
            CrankError::HandleMessage { err, .. } => Some(err),
            CrankError::InitialKeyGeneration(err) => Some(err),
            _ => None,
        }
    }
}
