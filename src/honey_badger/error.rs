use bincode;
use failure::Fail;

use crate::subset;
use crate::threshold_decrypt;

/// Honey badger error variants.
#[derive(Debug, Fail)]
pub enum Error {
    /// Failed to serialize contribution.
    #[fail(display = "Error serializing contribution: {}", _0)]
    ProposeBincode(bincode::ErrorKind),
    /// Failed to instantiate `Subset`.
    #[fail(display = "Failed to instantiate Subset: {}", _0)]
    CreateSubset(subset::Error),
    /// Failed to input contribution to `Subset`.
    #[fail(display = "Failed to input contribution to Subset: {}", _0)]
    InputSubset(subset::Error),
    /// Failed to handle `Subset` message.
    #[fail(display = "Failed to handle Subset message: {}", _0)]
    HandleSubsetMessage(subset::Error),
    /// Failed to decrypt a contribution.
    #[fail(display = "Threshold decryption error: {}", _0)]
    ThresholdDecrypt(threshold_decrypt::Error),
    /// Unknown sender
    #[fail(display = "Unknown sender")]
    UnknownSender,
}

/// The result of `HoneyBadger` handling an input or a message.
pub type Result<T> = ::std::result::Result<T, Error>;
