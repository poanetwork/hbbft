use bincode;
use failure::Fail;

use crate::honey_badger;
use crate::sync_key_gen;

/// Dynamic honey badger error variants.
#[derive(Debug, Fail)]
pub enum Error {
    /// Failed to serialize a key generation message for signing.
    #[fail(display = "Error serializing a key gen message: {}", _0)]
    SerializeKeyGen(bincode::ErrorKind),
    /// Failed to serialize a vote for signing.
    #[fail(display = "Error serializing a vote: {}", _0)]
    SerializeVote(bincode::ErrorKind),
    /// Failed to propose a contribution in `HoneyBadger`.
    #[fail(display = "Error proposing a contribution in HoneyBadger: {}", _0)]
    ProposeHoneyBadger(honey_badger::Error),
    /// Failed to handle a `HoneyBadger` message.
    #[fail(display = "Error handling a HoneyBadger message: {}", _0)]
    HandleHoneyBadgerMessage(honey_badger::Error),
    /// Failed to handle a `SyncKeyGen` message.
    #[fail(display = "Error handling SyncKeyGen message: {}", _0)]
    SyncKeyGen(sync_key_gen::Error),
    /// Unknown sender
    #[fail(display = "Unknown sender")]
    UnknownSender,
}

/// The result of `DynamicHoneyBadger` handling an input or message.
pub type Result<T> = ::std::result::Result<T, Error>;
/// Represents each way an an incoming message can be considered faulty.
#[derive(Debug, Fail, PartialEq)]
pub enum FaultKind {
    #[fail(
        display = "`DynamicHoneyBadger` received a key generation message with an invalid signature."
    )]
    InvalidKeyGenMessageSignature,
    #[fail(
        display = "`DynamicHoneyBadger` received a key generation message with an invalid era."
    )]
    InvalidKeyGenMessageEra,
    #[fail(
        display = "`DynamicHoneyBadger` received a key generation message when there was no key
                    generation in progress."
    )]
    UnexpectedKeyGenMessage,
    #[fail(
        display = "`DynamicHoneyBadger` received a signed `Ack` when no key generation in progress."
    )]
    UnexpectedKeyGenAck,
    #[fail(
        display = "`DynamicHoneyBadger` received a signed `Part` when no key generation in progress."
    )]
    UnexpectedKeyGenPart,
    #[fail(
        display = "`DynamicHoneyBadger` received more key generation messages from the peer than
                    expected."
    )]
    TooManyKeyGenMessages,
    #[fail(
        display = "`DynamicHoneyBadger` received a message (Accept, Propose, or Change
                       with an invalid signature."
    )]
    IncorrectPayloadSignature,
    #[fail(display = "`DynamicHoneyBadger`/`SyncKeyGen` received an invalid `Ack` message.")]
    SyncKeyGenAck(sync_key_gen::AckFault),
    #[fail(display = "`DynamicHoneyBadger`/`SyncKeyGen` received an invalid `Part` message.")]
    SyncKeyGenPart(sync_key_gen::PartFault),
    #[fail(display = "`DynamicHoneyBadger` received a change vote with an invalid signature.")]
    InvalidVoteSignature,
    #[fail(display = "A validator committed an invalid vote in `DynamicHoneyBadger`.")]
    InvalidCommittedVote,
    #[fail(display = "`DynamicHoneyBadger` received a message with an invalid era.")]
    UnexpectedDhbMessageEra,
    #[fail(display = "`DynamicHoneyBadger` received a fault from `HoneyBadger`.")]
    HbFault(honey_badger::FaultKind),
}
