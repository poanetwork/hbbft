use std::fmt::{self, Display};

use bincode;
use crypto;
use failure::{Backtrace, Context, Fail};

use honey_badger;
use sync_key_gen;

/// Dynamic honey badger error variants.
#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "SendTransactionBincode error: {}", _0)]
    SendTransactionBincode(bincode::ErrorKind),
    #[fail(display = "VerifySignatureBincode error: {}", _0)]
    VerifySignatureBincode(bincode::ErrorKind),
    #[fail(display = "SignVoteForBincode error: {}", _0)]
    SignVoteForBincode(bincode::ErrorKind),
    #[fail(display = "ValidateBincode error: {}", _0)]
    ValidateBincode(bincode::ErrorKind),
    #[fail(display = "Crypto error: {}", _0)]
    Crypto(crypto::error::Error),
    #[fail(display = "ProposeHoneyBadger error: {}", _0)]
    ProposeHoneyBadger(honey_badger::Error),
    #[fail(
        display = "HandleHoneyBadgerMessageHoneyBadger error: {}",
        _0
    )]
    HandleHoneyBadgerMessageHoneyBadger(honey_badger::Error),
    #[fail(display = "SyncKeyGen error: {}", _0)]
    SyncKeyGen(sync_key_gen::Error),
    #[fail(display = "Unknown sender")]
    UnknownSender,
}

/// A dynamic honey badger error.
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

impl From<crypto::error::Error> for Error {
    fn from(e: crypto::error::Error) -> Error {
        Error {
            inner: Context::new(ErrorKind::Crypto(e)),
        }
    }
}

impl From<sync_key_gen::Error> for Error {
    fn from(e: sync_key_gen::Error) -> Error {
        Error {
            inner: Context::new(ErrorKind::SyncKeyGen(e)),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

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
