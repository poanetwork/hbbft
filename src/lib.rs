//! # Honey Badger BFT
//!
//! An implementation of [The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf),
//! an asynchronous, Byzantine fault tolerant consensus algorithm.
//!
//! This crate only implements the protocol itself and is meant to be instantiated in a number of
//! nodes known to each other by some unique identifiers (IDs), that are able to exchange
//! authenticated (e.g. cryptographically signed) messages. The nodes provide a user-defined type
//! of _input_ - _transactions_ - to the instance, and handle networking:
//! Messages received from other nodes must be passed into the instance, and messages produced by
//! the instance need to be sent to the corresponding nodes.
//! The algorithm's output are _batches_ of transactions. The order and content of these
//! batches is guaranteed to be the same in all the nodes, as long as enough nodes are honest and
//! functioning.
//!
//! * It is _Byzantine fault tolerant_: It works correctly even if an adversary controls a number
//! `f` of the nodes, as long as the total number `N` of nodes is greater than `3 * f`. The
//! adversary is assumed to be unable to break cryptography, but otherwise can send any kind of
//! message through their nodes.
//! * It is also _asynchronous_: It does not make timing assumptions about message delivery. The
//! adversary can even be allowed to fully control the network scheduling, i.e. arbitrarily delay
//! messages, even those sent from an honest node to another honest node, as long as every message
//! eventually arrives. In particular, the algorithm is independent of time scales: it works via
//! fiber optics and via smoke signals, with the same code and the same parameters.
//!
//! Consensus algorithms are a fundamental building block of resilient systems that are distributed
//! across a number `N > 3 * f` of machines, and that can tolerate any kind of failure (including
//! complete takeover by an attacker) in up to `f` machines. Use-cases include distributed
//! databases and blockchains.
//!
//! Honey Badger is modular, and composed of several other algorithms that can also be used
//! independently. All of them are Byzantine fault tolerant and asynchronous.
//!
//! ## Algorithms
//!
//! [**Honey Badger BFT**](honey_badger/index.html)
//!
//! The nodes input any number of _transactions_ (any user-defined type) and outputs a sequence of
//! _batches_. The batches have sequential numbers (_epochs_) and contain a set of transactions
//! that were input by the nodes. The sequence and contents of the batches will be the same in all
//! nodes.
//!
//! [**Common Subset**](common_subset/index.html)
//!
//! Each node inputs one item. The output is a set of at least `N - f` nodes' items and will be the
//! same in every node.
//!
//! This is the main building block of Honey Badger: In each epoch, every node proposes a number of
//! transactions. Using the Common Subset protocol, they agree on at least `N - f` of those
//! proposals. The batch contains the union of these sets of transactions.
//!
//! [**Reliable Broadcast**](broadcast/index.html)
//!
//! One node, the _proposer_, inputs an item, and every node receives that item as an output. Even
//! if the proposer is faulty it is guaranteed that either all nodes output the same item or none
//! at all.
//!
//! This is used in Common Subset to send each node's proposal to the other nodes.
//!
//! [**Binary Agreement**](agreement/index.html)
//!
//! Each node inputs a binary value: `true` or `false`. As output, either all nodes receive `true`
//! or all nodes receive `false`. The output is guaranteed to be a value that was input by at least
//! one _honest_ node.
//!
//! This is used in Common Subset to decide for each node's proposal whether it should be included
//! in the subset or not.
//!
//! **Common Coin** (TBD)
//!
//! Each node inputs `()` to initiate a coin flip. Once `f + 1` nodes have input, either all nodes
//! receive `true` or all nodes receive `false`. The outcome cannot be known by the adversary
//! before at least one honest node has provided input, and is uniformly distributed and
//! pseudorandom.
//!
//! ## Serialization
//!
//! If the `serialization-serde` feature is enabled in the `Cargo.toml`, `hbbft` is compiled with
//! [serde](https://serde.rs/) support: All message types implement the `Serialize` and
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
#[cfg(feature = "serialization-serde")]
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
