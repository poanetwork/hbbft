use failure::Fail;

use std::result;

use crate::binary_agreement;
use crate::broadcast;

/// A subset error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    /// Error creating `BinaryAgreement`.
    #[fail(display = "Error creating BinaryAgreement: {}", _0)]
    NewAgreement(binary_agreement::Error),
    /// Error creating `Broadcast`.
    #[fail(display = "Error creating Broadcast: {}", _0)]
    NewBroadcast(broadcast::Error),
    /// Error handling a `Broadcast` input or message.
    #[fail(display = "Error handling Broadcast input/message: {}", _0)]
    HandleBroadcast(broadcast::Error),
    /// Error handling a `BinaryAgreement` input or message.
    #[fail(display = "Error handling BinaryAgreement input/message: {}", _0)]
    HandleAgreement(binary_agreement::Error),
    /// Unknown proposer.
    #[fail(display = "Unknown proposer ID")]
    UnknownProposer,
}

/// A subset result.
pub type Result<T> = result::Result<T, Error>;

/// Faults that can be detected in Subset.
#[derive(Clone, Debug, Fail, PartialEq)]
pub enum FaultKind {
    /// `Subset` received a faulty Broadcast message.
    #[fail(display = "`Subset` received a faulty Broadcast message.")]
    BroadcastFault(broadcast::FaultKind),
    /// `Subset` received a faulty Binary Agreement message.
    #[fail(display = "`Subset` received a faulty Binary Agreement message.")]
    BaFault(binary_agreement::FaultKind),
}
