//! # Honey Badger BFT
//!
//! An implementation of [The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf),
//! an asynchronous, Byzantine fault tolerant consensus algorithm.
//!
//!
//! ## Consensus
//!
//! Consensus algorithms are fundamental to resilient, distributed systems such as decentralized
//! databases and blockchains. Byzantine fault tolerant systems can reach consensus with a number
//! of faulty nodes _f_ (including complete takeover by an attacker), as long as the total number
//! _N_ of nodes is greater than _3 f_.
//!
//! The Honey Badger consensus algorithm is both Byzantine fault tolerant and asynchronous. It does
//! not make timing assumptions about message delivery. An adversary can control network scheduling
//! and delay messages without impacting consensus, and progress can be made in adverse networking
//! conditions.
//!
//!
//! ## Crate Implementation
//!
//! This protocol does not function in a standalone context, it must be instantiated in an
//! application that handles networking.
//!
//! * The network must contain a number of nodes that are known to each other by some unique
//! identifiers (IDs) and are able to exchange authenticated (cryptographically signed) messages.
//!
//! * The user must define a type of _input_ - the _transactions_ - to the system and nodes must
//! handle system networking.
//!
//! * Messages received from other nodes must be passed into the instance, and messages produced by
//! the instance sent to corresponding nodes.
//!
//! The algorithm outputs _batches_ of transactions. The order and content of these batches is
//! guaranteed to be the same for all correct nodes, assuming enough nodes (_N > 3 f_) are
//! functional and correct.
//!
//!
//! ## Algorithms
//!
//! Honey Badger is modular, and composed of several algorithms that can also be used independently.
//!
//! [**Honey Badger**](honey_badger/index.html)
//!
//! The nodes repeatedly input _contributions_ (any user-defined type) and output a sequence of
//! _batches_. The batches have sequential numbers (_epochs_) and contain one contribution
//! from at least _N - f_ nodes. The sequence and contents of the batches will be the same in all
//! nodes.
//!
//! [**Dynamic Honey Badger**](dynamic_honey_badger/index.html)
//!
//! A modified Honey Badger where validators can dynamically add and remove others to/from the
//! network. In addition to the transactions, they can input `Add` and `Remove` requests. The
//! output batches contain information about validator changes.
//!
//! [**Queueing Honey Badger**](queueing_honey_badger/index.html)
//!
//! A modified Dynamic Honey Badger that has a built-in transaction queue. The nodes input any
//! number of _transactions_, and output a sequence of batches. Each batch contains a set of
//! transactions that were input by the nodes, and usually multiple transactions from each node.
//!
//! [**Common Subset**](common_subset/index.html)
//!
//! Each node inputs one item. The output is a set of at least _N - f_ nodes' IDs, together with
//! their items, and will be the same in every correct node.
//!
//! This is the main building block of Honey Badger: In each epoch, every node proposes a number of
//! transactions. Using the Common Subset protocol, they agree on at least _N - f_ of those
//! proposals. The batch contains the union of these sets of transactions.
//!
//! [**Reliable Broadcast**](broadcast/index.html)
//!
//! One node, the _proposer_, inputs an item, and every node receives that item as an output. Even
//! if the proposer is faulty it is guaranteed that either none of the correct nodes output
//! anything, or all of them have the same output.
//!
//! This is used in Common Subset to send each node's proposal to the other nodes.
//!
//! [**Binary Agreement**](agreement/index.html)
//!
//! Each node inputs a binary value: `true` or `false`. As output, either all correct nodes receive
//! `true` or all correct nodes receive `false`. The output is guaranteed to be a value that was
//! input by at least one _correct_ node.
//!
//! This is used in Subset to decide whether each node's proposal should be included in the subset
//! or not.
//!
//! [**Common Coin**](common_coin/index.html)
//!
//! Each node inputs `()` to initiate a coin flip. Once _f + 1_ nodes have input, either all nodes
//! receive `true` or all nodes receive `false`. The outcome cannot be known by the adversary
//! before at least one correct node has provided input, and is uniformly distributed and
//! pseudorandom.
//!
//! ## Serialization
//!
//! `hbbft` supports [serde](https://serde.rs/): All message types implement the `Serialize` and
//! `Deserialize` traits so they can be easily serialized or included as part of other serializable
//! types.

// TODO: Remove this once https://github.com/rust-lang-nursery/error-chain/issues/245 is resolved.
#![allow(renamed_and_removed_lints)]
// We put algorithm structs in `src/algorithm/algorithm.rs`.
#![cfg_attr(feature = "cargo-clippy", allow(module_inception))]

extern crate bincode;
extern crate byteorder;
#[macro_use]
extern crate failure;
extern crate init_with;
#[macro_use]
extern crate log;
extern crate itertools;
extern crate pairing;
extern crate rand;
#[macro_use]
extern crate rand_derive;
extern crate reed_solomon_erasure;
extern crate serde;
#[macro_use]
extern crate serde_derive;
pub extern crate threshold_crypto as crypto;
extern crate tiny_keccak;

pub mod agreement;
pub mod broadcast;
pub mod common_coin;
pub mod common_subset;
pub mod dynamic_honey_badger;
pub mod fault_log;
mod fmt;
pub mod honey_badger;
pub mod messaging;
pub mod queueing_honey_badger;
pub mod sync_key_gen;
pub mod threshold_decryption;
pub mod transaction_queue;

/// Common supertraits.
pub mod traits {
    use std::fmt::Debug;
    use std::hash::Hash;

    /// A transaction, user message, etc.
    pub trait Contribution: Eq + Debug + Hash + Send + Sync {}
    impl<C> Contribution for C where C: Eq + Debug + Hash + Send + Sync {}

    /// A peer node's unique identifier.
    pub trait NodeUidT: Eq + Ord + Clone + Debug + Hash + Send + Sync {}
    impl<N> NodeUidT for N where N: Eq + Ord + Clone + Debug + Hash + Send + Sync {}

    /// Messages.
    pub trait Message: Debug + Send + Sync {}
    impl<M> Message for M where M: Debug + Send + Sync {}
}
