use std::fmt::{self, Display, Formatter};

use bincode;
use failure::{Backtrace, Context, Fail};

use subset;
use threshold_decryption;

/// Honey badger error variants.
#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "ProposeBincode error: {}", _0)]
    ProposeBincode(bincode::ErrorKind),
    #[fail(display = "Failed to instantiate Subset: {}", _0)]
    CreateSubset(subset::Error),
    #[fail(display = "Failed to input contribution to Subset: {}", _0)]
    InputSubset(subset::Error),
    #[fail(display = "Failed to handle Subset message: {}", _0)]
    HandleSubsetMessage(subset::Error),
    #[fail(display = "Threshold decryption error: {}", _0)]
    ThresholdDecryption(threshold_decryption::Error),
    #[fail(display = "HoneyBadger message sender is not a validator")]
    SenderNotValidator,
}

/// A honey badger error.
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

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;
