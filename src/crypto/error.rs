//! Crypto errors.

/// A crypto error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "Not enough signature shares")]
    NotEnoughShares,
    #[fail(display = "Signature shares contain a duplicated index")]
    DuplicateEntry,
}

/// A crypto result.
pub type Result<T> = ::std::result::Result<T, Error>;
