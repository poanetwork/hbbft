//! # Broadcast
//!
//! The Broadcast Protocol assumes a network of _N_ validators that send signed messages to
//! each other, with at most _f_ of them faulty, where _3 f < N_. It allows one validator, the
//! "proposer", to send a value to the other validators, and guarantees that:
//! * If the proposer is correct, all correct validators will receive the value.
//! * If the proposer is faulty, either all correct validators will receive the same value, or none
//! of them receives any value at all.
//!
//! Handling the networking and signing is the responsibility of this crate's user:
//! * The proposer needs to be determined beforehand. In all nodes, `Broadcast::new` must be called
//! with the same proposer's ID.
//! * Only in the proposer, `Broadcast::broadcast` is called, with the value they want to send.
//! * All messages contained in `Step`s returned by any of the methods must be securely sent to the
//! other nodes, e.g. by signing, (possibly encrypting) and sending them over the network.
//! * All incoming, verified messages must be passed into `Broadcast::handle_message`. It is the
//! user's responsibility to validate the sender, e.g. by checking the signature.
//! * Eventually, a `Step` will contain the value as its output. At that point, the algorithm has
//! terminated and the instance can be dropped. (The messages in the last step still need to be
//! sent out, though, to allow the other nodes to terminate, too.)
//!
//!
//! ## How it works
//!
//! The proposer uses a Reed-Solomon code to split the value into _N_ chunks, _N - 2 f_ of which
//! suffice to reconstruct the value. These chunks `s[0]`, `s[1]`, ..., `s[N - 1]` are used as the
//! leaves of a Merkle tree, a data structure which allows creating small proofs that the chunks
//! belong together: The tree has a root hash `h`, and for each chunk `s[i]`, there is a branch
//! `b[i]` connecting that chunk to the root hash. Together, these values are the proof
//! `p[i] = (h, b[i], s[i])`, with which a third party can verify that `s[i]` is the `i`-th leaf of
//! the Merkle tree with root hash `h`.
//!
//! The algorithm proceeds as follows:
//! * The proposer sends `Value(p[i])` to each validator number `i`.
//! * When validator `i` receives `Value(p[i])` from the proposer, it sends it on to everyone else
//! as `Echo(p[i])`.
//! * A validator that has received _N - f_ `Echo`s **or** _f + 1_ `Ready`s with root hash `h`,
//! sends `Ready(h)` to everyone.
//! * A node that has received _2 f + 1_ `Ready`s **and** _N - 2 f_ `Echo`s with root hash `h`
//! decodes and outputs the value, and then terminates.
//!
//! Only the first valid `Value` from the proposer, and the first valid `Echo` message from every
//! validator, is handled as above. Invalid messages (where the proof isn't correct), `Values`
//! received from other nodes, and any further `Value`s and `Echo`s are ignored, and the sender is
//! reported as faulty.
//!
//! In the `Valid(p[i])` messages, the proposer distributes the chunks of the value equally among
//! all validators, along with a proof to verify that all chunks are leaves of the same Merkle tree
//! with root hash `h`.
//!
//! An `Echo(p[i])` indicates that validator `i` has received its chunk of the value from
//! the proposer. Since `Echo`s contain the chunk, they are also used later on to reconstruct the
//! value when the algorithm completes: Every node that receives at least _N - 2 f_ valid `Echo`s
//! with root hash `h` can decode the value.
//!
//! A validator sends `Ready(h)` as soon as it knows that everyone will eventually be able to
//! decode the value with root hash `h`. Either of the two conditions in the third point above is
//! sufficient for that:
//! * If it has received _N - f_ `Echo`s with `h`, it knows that at least _N - 2 f_ **correct**
//! validators have multicast an `Echo` with `h`, and therefore everyone will
//! eventually receive at least _N - 2 f_ valid ones. So it knows that everyone will be able to
//! decode, and can send `Ready(h)`.
//! Moreover, since every correct validator only sends one kind of `Echo` message, there is no
//! danger of receiving _N - f_ `Echo`s with two different root hashes, so every correct validator
//! will only send one `Ready` message.
//! * Even without enough `Echo`s, if a validator receives _f + 1_ `Ready(h)` messages, it knows
//! that at least one **correct** validator has sent `Ready(h)`. It therefore also knows that
//! everyone will be able to decode eventually, and multicasts `Ready(h)` itself.
//!
//! Finally, if a node has received _2 f + 1_ `Ready(h)` messages, it knows that at least _f + 1_
//! **correct** validators have sent it. Thus, every remaining correct validator will eventually
//! receive _f + 1_, and multicast `Ready(h)` itself. Hence every node will receive
//! _N - f ≥ 2 f + 1_ `Ready(h)` messages.<br>
//! In addition, we know at this point that every node will eventually be able to decode, i.e.
//! receive _N - 2 f_ valid `Echo`s (since we know that at least one correct validator has sent
//! `Ready(h)`).<br>
//! In short: Once we satisfy the termination condition in the fourth point (we've received
//! _2 f + 1_ `Ready`s **and** _N - 2 f_ `Echo`s with root hash `h`), we know that
//! everyone else will eventually satisfy it, too. So at that point, we can output and terminate.
//!
//!
//! ## Example
//!
//! In this example, we manually pass messages between instantiated nodes to simulate a network. The
//! network is composed of 7 nodes, and node 3 is the proposer. We use `u64` as network IDs, and
//! start by creating a common network info. Then we input a randomly generated payload into the
//! proposer and process all the resulting messages in a loop. For the purpose of simulation we
//! annotate each message with the node that produced it. For each output, we perform correctness
//! checks to verify that every node has output the same payload as we provided to the proposer
//! node, and that it did so exactly once.
//!
//! ```
//! use hbbft::broadcast::{Broadcast, Error, Step};
//! use hbbft::{NetworkInfo, SourcedMessage, Target, TargetedMessage};
//! use rand::{OsRng, Rng, RngCore};
//! use std::collections::{BTreeMap, BTreeSet, VecDeque};
//! use std::iter::once;
//! use std::sync::Arc;
//!
//! fn main() -> Result<(), Error> {
//!     // Our simulated network has seven nodes in total, node 3 is the proposer.
//!     const NUM_NODES: u64 = 7;
//!     const PROPOSER_ID: u64 = 3;
//!
//!     let mut rng = OsRng::new().expect("Could not initialize OS random number generator.");
//!
//!     // Create a random set of keys for testing.
//!     let netinfos = NetworkInfo::generate_map(0..NUM_NODES, &mut rng)
//!         .expect("Failed to create `NetworkInfo` map");
//!
//!     // Create initial nodes by instantiating a `Broadcast` for each.
//!     let mut nodes = BTreeMap::new();
//!     for (i, netinfo) in netinfos {
//!         let bc = Broadcast::new(Arc::new(netinfo), PROPOSER_ID)?;
//!         nodes.insert(i, bc);
//!     }
//!
//!     // First we generate a random payload.
//!     let mut payload: Vec<_> = vec![0; 128];
//!     rng.fill_bytes(&mut payload[..]);
//!
//!     // Define a function for handling one step of a `Broadcast` instance. This function appends
//!     // new messages onto the message queue and checks whether each node outputs at most once
//!     // and the output is correct.
//!     let on_step = |id: u64,
//!                    step: Step<u64>,
//!                    messages: &mut VecDeque<SourcedMessage<TargetedMessage<_, _>, _>>,
//!                    finished_nodes: &mut BTreeSet<u64>| {
//!         // Annotate messages with the sender ID.
//!         messages.extend(step.messages.into_iter().map(|msg| SourcedMessage {
//!             source: id,
//!             message: msg,
//!         }));
//!         if !step.output.is_empty() {
//!             // The output should be the same as the input we gave to the proposer.
//!             assert!(step.output.iter().eq(once(&payload)));
//!             // Every node should output exactly once. Here we check the first half of this
//!             // statement, namely that every node outputs at most once.
//!             assert!(finished_nodes.insert(id));
//!         }
//!     };
//!
//!     let mut messages = VecDeque::new();
//!     let mut finished_nodes = BTreeSet::new();
//!
//!     // Now we can start the algorithm, its input is the payload.
//!     let initial_step = {
//!         let proposer = nodes.get_mut(&PROPOSER_ID).unwrap();
//!         proposer.broadcast(payload.clone()).unwrap()
//!     };
//!     on_step(
//!         PROPOSER_ID,
//!         initial_step,
//!         &mut messages,
//!         &mut finished_nodes,
//!     );
//!
//!     // The message loop: The network is simulated by passing messages around from node to node.
//!     while let Some(SourcedMessage {
//!         source,
//!         message: TargetedMessage { target, message },
//!     }) = messages.pop_front()
//!     {
//!         match target {
//!             Target::All => {
//!                 for (id, node) in &mut nodes {
//!                     let step = node.handle_message(&source, message.clone())?;
//!                     on_step(*id, step, &mut messages, &mut finished_nodes);
//!                 }
//!             }
//!             Target::Node(id) => {
//!                 let step = {
//!                     let node = nodes.get_mut(&id).unwrap();
//!                     node.handle_message(&source, message)?
//!                 };
//!                 on_step(id, step, &mut messages, &mut finished_nodes);
//!             }
//!         };
//!     }
//!     // Every node should output exactly once. Here we check the second half of this statement,
//!     // namely that every node outputs.
//!     assert_eq!(finished_nodes, nodes.keys().cloned().collect());
//!     Ok(())
//! }
//! ```

mod broadcast;
mod error;
pub(crate) mod merkle;
mod message;

pub use self::broadcast::{Broadcast, Step};
pub use self::error::{Error, FaultKind, Result};
pub use self::message::Message;
