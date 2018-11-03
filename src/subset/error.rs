use failure::Fail;

use std::result;

use binary_agreement;
use broadcast;

/// A subset error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "Error creating BinaryAgreement: {}", _0)]
    NewAgreement(binary_agreement::Error),
    #[fail(display = "Error creating Broadcast: {}", _0)]
    NewBroadcast(broadcast::Error),
    #[fail(display = "Error handling Broadcast input/message: {}", _0)]
    HandleBroadcast(broadcast::Error),
    #[fail(
        display = "Error handling BinaryAgreement input/message: {}",
        _0
    )]
    HandleAgreement(binary_agreement::Error),
    #[fail(display = "Unknown proposer ID")]
    UnknownProposer,
}

/// A subset result.
pub type Result<T> = result::Result<T, Error>;
