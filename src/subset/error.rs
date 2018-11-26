use failure::Fail;

use std::result;

use binary_agreement;
use broadcast;

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
    #[fail(
        display = "Error handling BinaryAgreement input/message: {}",
        _0
    )]
    HandleAgreement(binary_agreement::Error),
    /// Unknown proposer.
    #[fail(display = "Unknown proposer ID")]
    UnknownProposer,
}

/// A subset result.
pub type Result<T> = result::Result<T, Error>;
