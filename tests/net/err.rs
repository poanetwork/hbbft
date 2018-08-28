//! Test network errors

use std::fmt;

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
        // Note: Currently, neither [Error](std::error::Error) nor [Fail](failure::Fail) are
        //       implemented for [`D::Error`].
        //       Either would be preferable, and would enable a [`failure::Fail::cause`]
        //       implementation.
        /// Error produced by `D`.
        err: D::Error,
    },
    /// A node unexpectly disappeared from the list of notes. Note that this is likely a bug in
    /// the network framework code.
    NodeDisappeared(D::NodeUid),
    /// The configured maximum number of cranks has been reached or exceeded.
    CrankLimitExceeded(usize),
    /// The configured maximum number of messages has been reached or exceeded.
    MessageLimitExceeded(usize),
}

// Note: Deriving [Debug](std::fmt::Debug), [Fail](failure::Fail) and through that,
//       [Debug](std::fmt::Debug) automatically does not work due to the trait bound of
//       `D: DistAlgorithm`. For this reason, these three traits are implemented manually.
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
                "The Underyling algorithm could not process network message {:?}. Error: {:?}",
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
        }
    }
}

impl<D> failure::Fail for CrankError<D>
where
    D: DistAlgorithm + 'static,
{
    fn cause(&self) -> Option<&failure::Fail> {
        match self {
            CrankError::AlgorithmError { .. } => {
                // As soon as the necessary Trait bounds are on `DistAlgorithm`, this implementation
                // can be commented in:
                // Some(err)
                None
            }
            _ => None,
        }
    }
}
