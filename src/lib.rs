//! # Honey Badger BFT
//!
//! An implementation of [The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf),
//! an asynchronous, Byzantine fault tolerant consensus algorithm.
//!
//!
//! ## Consensus
//!
//! A consensus algorithm is a protocol that helps a number of nodes agree on some data value.
//! Byzantine fault tolerant systems can tolerate a number of faulty nodes _f_ (broken, or even
//! controlled by an attacker), as long as the total number of nodes _N_ is greater than _3 f_.
//! Asynchronous protocols do not make assumptions about timing: Even if an adversary controls
//! network scheduling and can delay message delivery, consensus will still be reached as long as
//! all messages are _eventually_ delivered.
//!
//! The Honey Badger consensus algorithm is both Byzantine fault tolerant and asynchronous. It is
//! also modular, and the subalgorithms it is composed of are exposed in this crate as well, and
//! usable separately.
//!
//! Consensus algorithms are fundamental to resilient, distributed systems such as decentralized
//! databases and blockchains.
//!
//!
//! ## Usage
//!
//! `hbbft` is meant to solve the consensus problem in a distributed application. Participating
//! nodes provide input to the algorithm and are guaranteed to eventually produce the same output,
//! after passing several messages back and forth.
//!
//! The crate only implements the abstract protocols, it is the application's responsibility to
//! serialize, sign and send the messages. The application is required to call `handle_message` for
//! every correctly signed message from a peer. Methods return a [Step](struct.Step.html) data
//! structure, which contain messages that need to be sent, fault logs indicating misbehaving
//! peers, and outputs.
//!
//! The network must contain a number of nodes that are known to each other by some unique
//! identifiers (IDs), which is a generic type argument to the algorithms. Where applicable, the
//! type of the input and output is also generic.
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
//! [**Subset**](subset/index.html)
//!
//! Each node inputs one item. The output is a set of at least _N - f_ nodes' IDs, together with
//! their items, and will be the same in every correct node.
//!
//! This is the main building block of Honey Badger: In each epoch, every node proposes a number of
//! transactions. Using the Subset protocol, they agree on at least _N - f_ of those
//! proposals. The batch contains the union of these sets of transactions.
//!
//! [**Broadcast**](broadcast/index.html)
//!
//! One node, the _proposer_, inputs an item, and every node receives that item as an output. Even
//! if the proposer is faulty it is guaranteed that either none of the correct nodes output
//! anything, or all of them have the same output.
//!
//! This is used in Subset to send each node's proposal to the other nodes.
//!
//! [**Binary Agreement**](binary_agreement/index.html)
//!
//! Each node inputs a binary value: `true` or `false`. As output, either all correct nodes receive
//! `true` or all correct nodes receive `false`. The output is guaranteed to be a value that was
//! input by at least one _correct_ node.
//!
//! This is used in Subset to decide whether each node's proposal should be included in the subset
//! or not.
//!
//! [**Threshold Sign**](threshold_sign/index.html)
//!
//! Each node inputs `()` to broadcast signature shares. Once _f + 1_ nodes have input, all nodes
//! receive a valid signature. The outcome cannot be known by the adversary before at least one
//! correct node has provided input, and can be used as a source of pseudorandomness.
//!
//! [**Threshold Decrypt**](threshold_decrypt/index.html)
//!
//! Each node inputs the same ciphertext, encrypted to the public master key. Once _f + 1_
//! validators have received input, all nodes output the decrypted data.
//!
//! [**Synchronous Key Generation**](sync_key_gen/index.html)
//!
//! The participating nodes collaboratively generate a key set for threshold cryptography, such
//! that each node learns its own secret key share, as well as everyone's public key share and the
//! public master key. No single trusted dealer is involved and no node ever learns the secret
//! master key or another node's secret key share.
//!
//! Unlike the other algorithms, this one is _not_ asynchronous: All nodes must handle the same
//! messages, in the same order.
//!
//! ## Serialization
//!
//! `hbbft` supports [serde](https://serde.rs/): All message types implement the `Serialize` and
//! `Deserialize` traits so they can be easily serialized or included as part of other serializable
//! types.

// We put algorithm structs in `src/algorithm/algorithm.rs`.
// Some of our constructors return results.
#![allow(clippy::module_inception, clippy::new_ret_no_self)]
#![warn(missing_docs)]

pub extern crate threshold_crypto as crypto;

mod fault_log;
mod messaging;
mod network_info;
mod traits;

pub mod binary_agreement;
pub mod broadcast;
pub mod dynamic_honey_badger;
pub mod honey_badger;
pub mod queueing_honey_badger;
pub mod sender_queue;
pub mod subset;
pub mod sync_key_gen;
pub mod threshold_decrypt;
pub mod threshold_sign;
pub mod transaction_queue;
pub mod util;

pub use crate::crypto::pairing;
pub use crate::fault_log::{Fault, FaultLog};
pub use crate::messaging::{SourcedMessage, Target, TargetedMessage};
pub use crate::network_info::NetworkInfo;
pub use crate::traits::{
    Contribution, DaStep, DistAlgorithm, Epoched, Message, NodeIdT, SessionIdT, Step,
};
