use bincode;
use thiserror::Error as ThisError;

use crate::fault_log;
use crate::subset;
use crate::threshold_decrypt;

/// Honey badger error variants.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Failed to serialize contribution.
    #[error("Error serializing contribution: {0}")]
    ProposeBincode(bincode::ErrorKind),
    /// Failed to instantiate `Subset`.
    #[error("Failed to instantiate Subset: {0}")]
    CreateSubset(subset::Error),
    /// Failed to input contribution to `Subset`.
    #[error("Failed to input contribution to Subset: {0}")]
    InputSubset(subset::Error),
    /// Failed to handle `Subset` message.
    #[error("Failed to handle Subset message: {0}")]
    HandleSubsetMessage(subset::Error),
    /// Failed to decrypt a contribution.
    #[error("Threshold decryption error: {0}")]
    ThresholdDecrypt(threshold_decrypt::Error),
    /// Unknown sender
    #[error("Unknown sender")]
    UnknownSender,
}

/// The result of `HoneyBadger` handling an input or a message.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Faults detectable from receiving honey badger messages
#[derive(Clone, Debug, ThisError, PartialEq)]
pub enum FaultKind {
    /// `HoneyBadger` received a decryption share for an unaccepted proposer.
    #[error("`HoneyBadger` received a decryption share for an unaccepted proposer.")]
    UnexpectedDecryptionShare,
    /// `HoneyBadger` was unable to deserialize a proposer's ciphertext.
    #[error("`HoneyBadger` was unable to deserialize a proposer's ciphertext.")]
    DeserializeCiphertext,
    /// `HoneyBadger` received an invalid ciphertext from the proposer.
    #[error("`HoneyBadger` received an invalid ciphertext from the proposer.")]
    InvalidCiphertext,
    /// `HoneyBadger` received a message with an invalid epoch.
    #[error("`HoneyBadger` received a message with an invalid epoch.")]
    UnexpectedHbMessageEpoch,
    /// `HoneyBadger` could not deserialize bytes (i.e. a serialized Batch) from a given proposer
    /// into a vector of transactions.
    #[error(
        "`HoneyBadger` could not deserialize bytes (i.e. a serialized Batch) from a
                    given proposer into a vector of transactions."
    )]
    BatchDeserializationFailed,
    /// `HoneyBadger` received a fault from `Subset`.
    #[error("`HoneyBadger` received a fault from `Subset`.")]
    SubsetFault(subset::FaultKind),
    /// `HoneyBadger` received a fault from `ThresholdDecrypt`.
    #[error("`HoneyBadger` received a fault from `ThresholdDecrypt`.")]
    DecryptionFault(threshold_decrypt::FaultKind),
}

/// The type of fault log whose entries are `HoneyBadger` faults.
pub type FaultLog<N> = fault_log::FaultLog<N, FaultKind>;
