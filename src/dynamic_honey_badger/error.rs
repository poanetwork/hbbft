use bincode;
use failure::Fail;

use honey_badger;
use sync_key_gen;

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
    #[fail(
        display = "Error proposing a contribution in HoneyBadger: {}",
        _0
    )]
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
