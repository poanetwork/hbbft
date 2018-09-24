//! # Dynamic Honey Badger
//!
//! Like Honey Badger, this protocol allows a network of _N_ nodes with at most _f_ faulty ones,
//! where _3 f < N_, to input "contributions" - any kind of data -, and to agree on a sequence of
//! _batches_ of contributions. The protocol proceeds in _epochs_, starting at number 0, and outputs
//! one batch in each epoch. It never terminates: It handles a continuous stream of incoming
//! contributions and keeps producing new batches from them. All correct nodes will output the same
//! batch for each epoch. Each validator proposes one contribution per epoch, and every batch will
//! contain the contributions of at least _N - f_ validators.
//!
//! Unlike Honey Badger, this algorithm allows dynamically adding and removing validators.
//! As a signal to initiate converting observers to validators or vice versa, it defines a special
//! `Change` input variant, which contains either a vote `Add(node_id, public_key)`, to add an
//! existing observer to the set of validators, or `Remove(node_id)` to remove it. Each
//! validator can have at most one active vote, and casting another vote revokes the previous one.
//! Once _f + 1_ validators have the same active vote, a reconfiguration process begins: They
//! create new cryptographic key shares for the new group of validators.
//!
//! The state of that process after each epoch is communicated via the `change` field in `Batch`.
//! When this contains an `InProgress(..)` value, key generation begins. The joining validator (in
//! the case of an `Add` change) must be an observer starting in the following epoch or earlier.
//! When `change` is `Complete(..)`, the following epochs will be produced by the new set of
//! validators.
//!
//! New observers can only join the network after an epoch where `change` was not `None`. These
//! epochs' batches contain a `JoinPlan`, which can be sent as an invitation to the new node: The
//! `DynamicHoneyBadger` instance created from a `JoinPlan` will start as an observer in the
//! following epoch. All `Target::All` messages from that and later epochs must be sent to the new
//! node.
//!
//! Observer nodes can leave the network at any time.
//!
//! These mechanisms create a dynamic network where you can:
//!
//! * introduce new nodes as observers,
//! * promote observer nodes to validators,
//! * demote validator nodes to observers, and
//! * remove observer nodes,
//!
//! without interrupting the consensus process.
//!
//! ## How it works
//!
//! Dynamic Honey Badger runs a regular Honey Badger instance internally, which in addition to the
//! user's contributions contains special transactions for the change votes and the key generation
//! messages: Running votes and key generation "on-chain" greatly simplifies these processes, since
//! it is guaranteed that every node will see the same sequence of votes and messages.
//!
//! Every time Honey Badger outputs a new batch, Dynamic Honey Badger outputs the user
//! contributions in its own batch. The other transactions are processed: votes are counted and key
//! generation messages are passed into a `SyncKeyGen` instance.
//!
//! Whenever a change receives _f + 1_ votes, the votes are reset and key generation for that
//! change begins. If key generation completes successfully, the Honey Badger instance is dropped,
//! and replaced by a new one with the new set of participants. If a different change wins a
//! vote before that happens, key generation resets again, and is attempted for the new change.

mod batch;
mod builder;
mod change;
mod dynamic_honey_badger;
mod error;
mod votes;

use std::collections::BTreeMap;

use crypto::{PublicKey, PublicKeySet, Signature};
use rand::Rand;

use self::votes::{SignedVote, VoteCounter};
use honey_badger::Message as HbMessage;
use sync_key_gen::{Ack, Part, SyncKeyGen};
use traits::NodeIdT;

pub use self::batch::Batch;
pub use self::builder::DynamicHoneyBadgerBuilder;
pub use self::change::{Change, ChangeState};
pub use self::dynamic_honey_badger::{DynamicHoneyBadger, Step};
pub use self::error::{Error, ErrorKind, Result};

/// The user input for `DynamicHoneyBadger`.
#[derive(Clone, Debug)]
pub enum Input<C, N> {
    /// A user-defined contribution for the next epoch.
    User(C),
    /// A vote to change the set of validators.
    Change(Change<N>),
}

/// An internal message containing a vote for adding or removing a validator, or a message for key
/// generation. It gets committed via Honey Badger and is only handled after it has been output in
/// a batch, so that all nodes see these messages in the same order.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Hash, Clone)]
pub enum KeyGenMessage {
    /// A `SyncKeyGen::Part` message for key generation.
    Part(Part),
    /// A `SyncKeyGen::Ack` message for key generation.
    Ack(Ack),
}

/// The content of a `DynamicHoneyBadger` message.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MessageContent<N: Rand> {
    /// A message belonging to the `HoneyBadger` algorithm started in the given epoch.
    HoneyBadger(u64, HbMessage<N>),
    /// A transaction to be committed, signed by a node.
    KeyGen(u64, KeyGenMessage, Box<Signature>),
    /// A vote to be committed, signed by a validator.
    SignedVote(SignedVote<N>),
}

impl<N: Rand> MessageContent<N> {
    fn start_epoch(&self) -> u64 {
        match *self {
            MessageContent::HoneyBadger(start_epoch, ..) => start_epoch,
            MessageContent::KeyGen(start_epoch, ..) => start_epoch,
            MessageContent::SignedVote(ref signed_vote) => signed_vote.era(),
        }
    }

    pub fn dynamic_epoch(&self) -> DynamicEpoch {
        match *self {
            MessageContent::HoneyBadger(start_epoch, ref msg) => {
                DynamicEpoch::new(start_epoch, msg.epoch())
            }
            MessageContent::KeyGen(start_epoch, ..) => DynamicEpoch::new(start_epoch, 0),
            MessageContent::SignedVote(ref signed_vote) => DynamicEpoch::new(signed_vote.era(), 0),
        }
    }

    /// Tests whether the message has only Dynamic Honey Badger content.
    pub fn is_dynamic(&self) -> bool {
        if let MessageContent::HoneyBadger(..) = *self {
            false
        } else {
            true
        }
    }

    /// Computes the overall epoch from the `DynamicEpoch`.
    pub fn epoch(&self) -> u64 {
        self.dynamic_epoch().epoch()
    }
}

/// The detailed epoch of `DynamicHoneyBadger` consisting of the epoch after the last restart of the
/// `HoneyBadger` instance and the current epoch of that instance.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DynamicEpoch {
    pub start_epoch: u64,
    pub hb_epoch: u64,
}

impl DynamicEpoch {
    pub fn new(start_epoch: u64, hb_epoch: u64) -> Self {
        DynamicEpoch {
            start_epoch,
            hb_epoch,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.start_epoch + self.hb_epoch
    }
}

/// A message sent to or received from another node's Dynamic Honey Badger instance.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message<N: Rand> {
    /// A message belonging to the `DynamicHoneyBadger` algorithm.
    DynamicHoneyBadger(MessageContent<N>),
    /// A Dynamic Honey Badger participant uses this message to announce its transition to the given
    /// epoch. This message informs the recipients that this participant now accepts messages for
    /// this epoch only and drops any incoming messages from earlier or later epochs.
    DynamicEpochStarted(DynamicEpoch),
}

impl<N: Rand> Message<N> {
    pub fn dynamic_epoch(&self) -> DynamicEpoch {
        match *self {
            Message::DynamicHoneyBadger(ref content) => content.dynamic_epoch(),
            Message::DynamicEpochStarted(epoch) => epoch,
        }
    }

    /// Tests whether the message has only Dynamic Honey Badger content.
    pub fn is_dynamic(&self) -> bool {
        if let Message::DynamicHoneyBadger(MessageContent::HoneyBadger(..)) = *self {
            false
        } else {
            true
        }
    }
}

/// The information a new node requires to join the network as an observer. It contains the state
/// of voting and key generation after a specific epoch, so that the new node will be in sync if it
/// joins in the next one.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinPlan<N: Ord> {
    /// The first epoch the new node will observe.
    epoch: u64,
    /// The current change. If `InProgress`, key generation for it is beginning at `epoch`.
    change: ChangeState<N>,
    /// The current public key set for threshold cryptography.
    pub_key_set: PublicKeySet,
    /// The public keys of the nodes taking part in key generation.
    pub_keys: BTreeMap<N, PublicKey>,
}

/// The ongoing key generation, together with information about the validator change.
#[derive(Debug)]
struct KeyGenState<N> {
    /// The key generation instance.
    key_gen: SyncKeyGen<N>,
    /// The change for which key generation is performed.
    change: Change<N>,
    /// The number of key generation messages received from the candidate. At most _N² + 1_ are
    /// accepted.
    candidate_msg_count: usize,
}

impl<N: NodeIdT> KeyGenState<N> {
    fn new(key_gen: SyncKeyGen<N>, change: Change<N>) -> Self {
        KeyGenState {
            key_gen,
            change,
            candidate_msg_count: 0,
        }
    }

    /// Returns `true` if the candidate's, if any, as well as enough validators' key generation
    /// parts have been completed.
    fn is_ready(&self) -> bool {
        let candidate_ready = |id: &N| self.key_gen.is_node_ready(id);
        self.key_gen.is_ready() && self.change.candidate().map_or(true, candidate_ready)
    }

    /// If the node `node_id` is the currently joining candidate, returns its public key.
    fn candidate_key(&self, node_id: &N) -> Option<&PublicKey> {
        match self.change {
            Change::Add(ref id, ref pk) if id == node_id => Some(pk),
            Change::Add(_, _) | Change::Remove(_) => None,
        }
    }
}

/// The contribution for the internal `HoneyBadger` instance: this includes a user-defined
/// application-level contribution as well as internal signed messages.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Hash)]
struct InternalContrib<C, N> {
    /// A user-defined contribution.
    contrib: C,
    /// Key generation messages that get committed via Honey Badger to communicate synchronously.
    key_gen_messages: Vec<SignedKeyGenMsg<N>>,
    /// Signed votes for validator set changes.
    votes: Vec<SignedVote<N>>,
}

/// A signed internal message.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Hash, Clone)]
struct SignedKeyGenMsg<N>(u64, N, KeyGenMessage, Signature);
