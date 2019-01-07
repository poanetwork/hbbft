//! # Subset algorithm.
//!
//! The Subset protocol assumes a network of _N_ nodes that send signed
//! messages to each other, with at most _f_ of them malicious, where _3 f < N_. Handling the
//! networking and signing is the responsibility of the user: only when a message has been
//! verified to be "from node i" (e.g. using cryptographic signatures), it can be handed to the
//! `Subset` instance.
//!
//! Each node proposes an element for inclusion. Under the above conditions, the protocol
//! guarantees that all correct nodes output the same set, consisting of at least _N - f_ of the
//! proposed elements.
//!
//! ## How it works
//!
//! * `Subset` instantiates one `Broadcast` algorithm for each of the participating nodes.
//! At least _N - f_ of these - the ones whose proposer is not faulty - will eventually output
//! the element proposed by that node.
//! * It also instantiates Binary Agreement for each participating node, to decide whether
//! that node's proposed element should be included in the set. Whenever an element is
//! received via broadcast, we input "yes" (`true`) into the corresponding `BinaryAgreement` instance.
//! * When _N - f_ `BinaryAgreement` instances have decided "yes", we input "no" (`false`) into the
//! remaining ones, where we haven't provided input yet.
//! * Once all `BinaryAgreement` instances have decided, `Subset` returns the set of all proposed
//! values for which the decision was "yes".

mod error;
mod message;
mod proposal_state;
mod subset;

pub use self::error::{Error, FaultKind, Result};
pub use self::message::{Message, MessageContent};
pub use self::subset::{Step, Subset, SubsetOutput};
