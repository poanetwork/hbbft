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
    #[fail(display = "DynamicEpochStarted error: {}", _0)]
    DynamicEpochStarted(honey_badger::Error),
    #[fail(display = "Obsolete `DynamicEpochStarted`")]
    ObsoleteDynamicEpochStarted,
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
