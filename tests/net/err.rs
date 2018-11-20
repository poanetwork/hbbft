//! Test network errors

use std::fmt::{self, Debug, Display};
use std::time;

use failure;
use threshold_crypto as crypto;

use hbbft::{DistAlgorithm, Fault};

use super::NetMessage;

/// Network crank error.
///
/// Errors resulting from processing a single message ("cranking").
pub enum CrankError<D>
where
    D: DistAlgorithm,
{
    /// The algorithm run by the node produced a `DistAlgorithm::Error`.
    Algorithm(D::Error),
    /// The algorithm run by the node produced a `DistAlgorithm::Error` while processing a message.
    HandleMessage {
        /// Network message that triggered the error.
        msg: NetMessage<D>,
        err: D::Error,
    },
    /// A node unexpectly disappeared from the list of nodes. Note that this is likely a bug in
    /// the network framework code.
    NodeDisappeared(D::NodeId),
    /// The configured maximum number of cranks has been reached or exceeded.
    CrankLimitExceeded(usize),
    /// The configured maximum number of messages has been reached or exceeded.
    MessageLimitExceeded(usize),
    /// The execution time limit has been reached or exceeded.
    TimeLimitHit(time::Duration),
    /// Fault encountered.
    Fault(Fault<D::NodeId>),
    /// Threshold cryptography error.
    Crypto(crypto::error::Error),
}

// Note: Deriving [Debug](std::fmt::Debug), [Fail](failure::Fail) and through that,
//       [Debug](std::fmt::Debug) automatically does not work due to the wrongly required trait
//       bound of `D: DistAlgorithm` implementing the respective Trait. For this reason, these
//       three traits are implemented manually.
//
//       More details at
//
//       * <https://github.com/rust-lang/rust/issues/26925>
//       * <https://github.com/rust-lang/rust/issues/26925#issuecomment-405189266>
impl<D> Display for CrankError<D>
where
    D: DistAlgorithm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CrankError::Algorithm(err) => {
                write!(f, "The algorithm encountered an error: {:?}", err)
            }
            CrankError::HandleMessage { msg, err } => write!(
                f,
                "The algorithm could not process network message {:?}. Error: {:?}",
                msg, err
            ),
            CrankError::NodeDisappeared(id) => write!(
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
            CrankError::Fault(fault) => {
                write!(f, "Node {:?} is faulty: {:?}.", fault.node_id, fault.kind)
            }
            CrankError::Crypto(err) => write!(f, "Threshold cryptography error {:?}.", err),
        }
    }
}

impl<D> Debug for CrankError<D>
where
    D: DistAlgorithm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CrankError::Algorithm(err) => f.debug_struct("Algorithm").field("err", err).finish(),
            CrankError::HandleMessage { msg, err } => f
                .debug_struct("HandleMessage")
                .field("msg", msg)
                .field("err", err)
                .finish(),
            CrankError::NodeDisappeared(id) => f.debug_tuple("NodeDisappeared").field(id).finish(),
            CrankError::CrankLimitExceeded(max) => {
                f.debug_tuple("CrankLimitExceeded").field(max).finish()
            }
            CrankError::MessageLimitExceeded(max) => {
                f.debug_tuple("MessageLimitExceeded").field(max).finish()
            }
            CrankError::TimeLimitHit(lim) => f.debug_tuple("TimeLimitHit").field(lim).finish(),
            CrankError::Fault(fault) => f.debug_tuple("Fault").field(fault).finish(),
            CrankError::Crypto(err) => f.debug_tuple("Crypto").field(err).finish(),
        }
    }
}

impl<D> failure::Fail for CrankError<D>
where
    D: DistAlgorithm + 'static,
{
    fn cause(&self) -> Option<&failure::Fail> {
        match self {
            CrankError::Algorithm(err) => Some(err),
            CrankError::HandleMessage { err, .. } => Some(err),
            CrankError::Crypto(err) => Some(err),
            _ => None,
        }
    }
}
