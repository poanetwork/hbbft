//! Test network errors

use std::{fmt, time};

use failure;
use hbbft::messaging::DistAlgorithm;

use super::NetMessage;

/// Network crank error.
///
/// Errors resulting from processing a single message ("cranking").
pub enum CrankError<D>
where
    D: DistAlgorithm,
{
    /// The algorithm run by the node produced a `DistAlgorithm::Error` while processing input.
    AlgorithmError {
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
impl<D> fmt::Display for CrankError<D>
where
    D: DistAlgorithm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CrankError::AlgorithmError { msg, err } => write!(
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
        }
    }
}

impl<D> fmt::Debug for CrankError<D>
where
    D: DistAlgorithm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CrankError::AlgorithmError { msg, err } => f
                .debug_struct("AlgorithmError")
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
        }
    }
}

impl<D> failure::Fail for CrankError<D>
where
    D: DistAlgorithm + 'static,
{
    fn cause(&self) -> Option<&failure::Fail> {
        match self {
            CrankError::AlgorithmError { err, .. } => Some(err),
            _ => None,
        }
    }
}
