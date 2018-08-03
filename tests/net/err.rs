//! Test network errors
//!
//! The error implementation for the test networking code is slightly involved and has been factored
//! into its own module for this reason.
//!
//! The most commonly used error type is [CrankError<D>], which wraps errors from the algorithms,
//! as well as rarely triggered violations of invariants. See the type description for more details.

use std::fmt;

use failure;
use hbbft::messaging::DistAlgorithm;

use super::NetMessage;

/// Single crank error
///
/// Errors of the test network, resulting from processing a single message ("cranking").
pub enum CrankError<D>
where
    D: DistAlgorithm,
{
    CorrectNodeErr {
        msg: NetMessage<D>,
        // Note: Currently, neither [Error](std::error::Error) nor [Fail](failure::Fail) are
        //       implemented for [`D::Error`].
        //       Either would be preferable, and would enable a [`failure::Fail::cause`]
        //       implementation.
        err: D::Error,
    },
    FaultyNodeButNoAdversary(D::NodeUid),
    NodeDisappeared(D::NodeUid),
}

impl<D> fmt::Display for CrankError<D>
where
    D: DistAlgorithm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CrankError::CorrectNodeErr { msg, err } => write!(
                f,
                "Node error'd processing network message {:?}. Error: {:?}",
                msg, err
            ),
            CrankError::FaultyNodeButNoAdversary(id) => write!(
                f,
                "The node with ID {:?} is faulty, but no adversary is set.",
                id
            ),
            CrankError::NodeDisappeared(id) => write!(
                f,
                "Node {:?} disappeared or never existed, while it still had incoming messages.",
                id
            ),
        }
    }
}

impl<D> fmt::Debug for CrankError<D>
where
    D: DistAlgorithm,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CrankError::CorrectNodeErr { msg, err } => f.debug_struct("CorrectNodeErr")
                .field("msg", msg)
                .field("err", err)
                .finish(),
            CrankError::FaultyNodeButNoAdversary(id) => {
                f.debug_tuple("FaultyNodeButNoAdversary").field(id).finish()
            }
            CrankError::NodeDisappeared(id) => f.debug_tuple("NodeDisappeared").field(id).finish(),
        }
    }
}

impl<D> failure::Fail for CrankError<D>
where
    D: DistAlgorithm + 'static,
{
    fn cause(&self) -> Option<&failure::Fail> {
        match self {
            CrankError::CorrectNodeErr { err: _, .. } => {
                // As soon as the necessary Trait bounds are on DistAlgorithm, this implementation
                // can be commented in:
                // Some(err)
                None
            }
            _ => None,
        }
    }
}
