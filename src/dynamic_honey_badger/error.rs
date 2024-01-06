use bincode;
use thiserror::Error as ThisError;

use crate::honey_badger;
use crate::sync_key_gen;

/// Dynamic honey badger error variants.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Failed to serialize a key generation message for signing.
    #[error("Error serializing a key gen message: {0}")]
    SerializeKeyGen(bincode::ErrorKind),
    /// Failed to serialize a vote for signing.
    #[error("Error serializing a vote: {0}")]
    SerializeVote(bincode::ErrorKind),
    /// Failed to propose a contribution in `HoneyBadger`.
    #[error("Error proposing a contribution in HoneyBadger: {0}")]
    ProposeHoneyBadger(honey_badger::Error),
    /// Failed to handle a `HoneyBadger` message.
    #[error("Error handling a HoneyBadger message: {0}")]
    HandleHoneyBadgerMessage(honey_badger::Error),
    /// Failed to handle a `SyncKeyGen` message.
    #[error("Error handling SyncKeyGen message: {0}")]
    SyncKeyGen(sync_key_gen::Error),
    /// The join plan contains contradictory information.
    #[error("Invalid Join Plan")]
    InvalidJoinPlan,
    /// Unknown sender
    #[error("Unknown sender")]
    UnknownSender,
}

/// The result of `DynamicHoneyBadger` handling an input or message.
pub type Result<T> = ::std::result::Result<T, Error>;
/// Represents each way an an incoming message can be considered faulty.
#[derive(Clone, Debug, ThisError, PartialEq)]
pub enum FaultKind {
    /// `DynamicHoneyBadger` received a key generation message with an invalid signature.
    #[error("`DynamicHoneyBadger` received a key generation message with an invalid signature.")]
    InvalidKeyGenMessageSignature,
    /// `DynamicHoneyBadger` received a key generation message with an invalid era.
    #[error("`DynamicHoneyBadger` received a key generation message with an invalid era.")]
    InvalidKeyGenMessageEra,
    /// `DynamicHoneyBadger` received a key generation message when there was no key generation in
    /// progress.
    #[error(
        "`DynamicHoneyBadger` received a key generation message when there was no key
                    generation in progress."
    )]
    UnexpectedKeyGenMessage,
    /// `DynamicHoneyBadger` received a signed `Ack` when no key generation in progress.
    #[error("`DynamicHoneyBadger` received a signed `Ack` when no key generation in progress.")]
    UnexpectedKeyGenAck,
    /// `DynamicHoneyBadger` received a signed `Part` when no key generation in progress.
    #[error("`DynamicHoneyBadger` received a signed `Part` when no key generation in progress.")]
    UnexpectedKeyGenPart,
    /// `DynamicHoneyBadger` received more key generation messages from the peer than expected.
    #[error(
        "`DynamicHoneyBadger` received more key generation messages from the peer than
                    expected."
    )]
    TooManyKeyGenMessages,
    /// `DynamicHoneyBadger` received a message (Accept, Propose, or Change with an invalid
    /// signature.
    #[error(
        "`DynamicHoneyBadger` received a message (Accept, Propose, or Change
                       with an invalid signature."
    )]
    IncorrectPayloadSignature,
    /// `DynamicHoneyBadger`/`SyncKeyGen` received an invalid `Ack` message.
    #[error("`DynamicHoneyBadger`/`SyncKeyGen` received an invalid `Ack` message.")]
    SyncKeyGenAck(sync_key_gen::AckFault),
    /// `DynamicHoneyBadger`/`SyncKeyGen` received an invalid `Part` message.
    #[error("`DynamicHoneyBadger`/`SyncKeyGen` received an invalid `Part` message.")]
    SyncKeyGenPart(sync_key_gen::PartFault),
    /// `DynamicHoneyBadger` received a change vote with an invalid signature.
    #[error("`DynamicHoneyBadger` received a change vote with an invalid signature.")]
    InvalidVoteSignature,
    /// A validator committed an invalid vote in `DynamicHoneyBadger`.
    #[error("A validator committed an invalid vote in `DynamicHoneyBadger`.")]
    InvalidCommittedVote,
    /// `DynamicHoneyBadger` received a message with an invalid era.
    #[error("`DynamicHoneyBadger` received a message with an invalid era.")]
    UnexpectedDhbMessageEra,
    /// `DynamicHoneyBadger` received a fault from `HoneyBadger`.
    #[error("`DynamicHoneyBadger` received a fault from `HoneyBadger`.")]
    HbFault(honey_badger::FaultKind),
}
