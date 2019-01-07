//! # Honey Badger
//!
//! Honey Badger allows a network of _N_ nodes with at most _f_ faulty ones,
//! where _3 f < N_, to input "contributions" - any kind of data -, and to agree on a sequence of
//! _batches_ of contributions. The protocol proceeds in _epochs_, starting at number 0, and outputs
//! one batch in each epoch. It never terminates: It handles a continuous stream of incoming
//! contributions and keeps producing new batches from them. All correct nodes will output the same
//! batch for each epoch. Each validator proposes one contribution per epoch, and every batch will
//! contain the contributions of at least _N - f_ validators.
//!
//! ## How it works
//!
//! In every epoch, every validator encrypts their contribution and proposes it to the others.
//! A `Subset` instance determines which proposals are accepted and will be part of the new
//! batch. Using threshold encryption, the nodes collaboratively decrypt all accepted
//! contributions. Invalid contributions (that e.g. cannot be deserialized) are discarded - their
//! proposers must be faulty -, and the remaining ones are output as the new batch. The next epoch
//! begins as soon as the validators propose new contributions again.
//!
//! So it is essentially an endlessly repeating `Subset`, but with the proposed values
//! encrypted. The encryption makes it harder for an attacker to try and censor a particular value
//! by influencing the set of proposals that make it into the subset, because they don't
//! know the decrypted values before the subset is determined.

mod batch;
mod builder;
mod epoch_state;
mod error;
mod honey_badger;
mod message;
mod params;

pub use self::batch::Batch;
pub use self::builder::HoneyBadgerBuilder;
pub use self::epoch_state::SubsetHandlingStrategy;
pub use self::error::{Error, FaultKind, FaultLog, Result};
pub use self::honey_badger::{EncryptionSchedule, HoneyBadger, Step};
pub use self::message::{Message, MessageContent};
pub use self::params::Params;
