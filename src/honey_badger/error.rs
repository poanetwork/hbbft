use std::fmt::{self, Display, Formatter};

use bincode;
use failure::{Backtrace, Context, Fail};

use common_subset;

/// Honey badger error variants.
#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "ProposeBincode error: {}", _0)]
    ProposeBincode(bincode::ErrorKind),
    #[fail(display = "ProposeCommonSubset0 error: {}", _0)]
    ProposeCommonSubset0(common_subset::Error),
    #[fail(display = "ProposeCommonSubset1 error: {}", _0)]
    ProposeCommonSubset1(common_subset::Error),
    #[fail(display = "HandleCommonMessageCommonSubset0 error: {}", _0)]
    HandleCommonMessageCommonSubset0(common_subset::Error),
    #[fail(display = "HandleCommonMessageCommonSubset1 error: {}", _0)]
    HandleCommonMessageCommonSubset1(common_subset::Error),
    #[fail(display = "Unknown sender")]
    UnknownSender,
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
