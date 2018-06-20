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
//! of failed nodes `f` (including complete takeover by an attacker), as long as the total number
//! `N` of nodes is greater than `3 * f`.
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
//! guaranteed to be the same for all correct nodes, assuming enough nodes (`N > 3 * f`) are
//! functional and correct.
//!
//!
//! ## Algorithms
//!
//! Honey Badger is modular, and composed of several algorithms that can also be used independently.
//!
//! [**Honey Badger BFT**](honey_badger/index.html)
//!
//! The nodes input any number of _transactions_ (any user-defined type) and output a sequence of
//! _batches_. The batches have sequential numbers (_epochs_) and contain a set of transactions
//! that were input by the nodes. The sequence and contents of the batches will be the same in all
//! nodes.
//!
//! [**Common Subset**](common_subset/index.html)
//!
//! Each node inputs one item. The output is a set of at least `N - f` nodes' IDs, together with
//! their items, and will be the same in every correct node.
//!
//! This is the main building block of Honey Badger: In each epoch, every node proposes a number of
//! transactions. Using the Common Subset protocol, they agree on at least `N - f` of those
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
//! **Common Coin** (TBD)
//!
//! Each node inputs `()` to initiate a coin flip. Once `f + 1` nodes have input, either all nodes
//! receive `true` or all nodes receive `false`. The outcome cannot be known by the adversary
//! before at least one correct node has provided input, and is uniformly distributed and
//! pseudorandom.
//!
//! ## Serialization
//!
//! `hbbft` supports [serde](https://serde.rs/): All message types implement the `Serialize` and
//! `Deserialize` traits so they can be easily serialized or included as part of other serializable
//! types.
//!
//! If `serialization-protobuf` is enabled, the message types support serialization with [Google
//! protocol buffers](https://developers.google.com/protocol-buffers/docs/overview).

#![feature(optin_builtin_traits)]
// TODO: Remove this once https://github.com/rust-lang-nursery/error-chain/issues/245 is resolved.
#![allow(renamed_and_removed_lints)]

extern crate bincode;
extern crate byteorder;
extern crate clear_on_drop;
#[macro_use(Deref, DerefMut)]
extern crate derive_deref;
#[macro_use]
extern crate error_chain;
extern crate init_with;
#[macro_use]
extern crate log;
extern crate itertools;
extern crate merkle;
extern crate pairing;
#[cfg(feature = "serialization-protobuf")]
extern crate protobuf;
extern crate rand;
extern crate reed_solomon_erasure;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;

pub mod agreement;
pub mod broadcast;
pub mod common_coin;
pub mod common_subset;
pub mod crypto;
mod fmt;
pub mod honey_badger;
pub mod messaging;
#[cfg(feature = "serialization-protobuf")]
pub mod proto;
#[cfg(feature = "serialization-protobuf")]
pub mod proto_io;
