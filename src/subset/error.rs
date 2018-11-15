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

/// Subset does not actually have any messages defined, so there's no real FaultKind to define here
#[derive(Debug, Fail, PartialEq)]
pub enum FaultKind {
    #[fail(display = "`Subset` received a faulty Broadcast message.")]
    BroadcastFault(broadcast::FaultKind),
    #[fail(display = "`Subset` received a faulty Binary Agreement message.")]
    BaFault(binary_agreement::FaultKind),
}
