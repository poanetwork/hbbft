use bincode;
use failure::Fail;

use fault_log;
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

/// Faults detectable from receiving honey badger messages
#[derive(Debug, Fail, PartialEq)]
pub enum FaultKind {
    #[fail(display = "`HoneyBadger` received a decryption share for an unaccepted proposer.")]
    UnexpectedDecryptionShare,
    #[fail(display = "`HoneyBadger` was unable to deserialize a proposer's ciphertext.")]
    DeserializeCiphertext,
    #[fail(display = "`HoneyBadger` received an invalid ciphertext from the proposer.")]
    InvalidCiphertext,
    #[fail(display = "`HoneyBadger` received a message with an invalid epoch.")]
    UnexpectedHbMessageEpoch,
    #[fail(
        display = "`HoneyBadger` could not deserialize bytes (i.e. a serialized Batch) from a
                    given proposer into a vector of transactions."
    )]
    BatchDeserializationFailed,
    #[fail(display = "`HoneyBadger` received a fault from `Subset`.")]
    SubsetFault(subset::FaultKind),
    #[fail(display = "`HoneyBadger` received a fault from `ThresholdDecrypt`.")]
    DecryptionFault(threshold_decrypt::FaultKind),
    #[fail(display = "`HoneyBadger` received a fault from `ThresholdSign`.")]
    SigningFault(threshold_sign::FaultKind),
}

pub type FaultLog<N> = fault_log::FaultLog<N, FaultKind>;
