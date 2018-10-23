//! # Binary Agreement
//!
//! The Binary Agreement protocol allows each node to input one binary (`bool`) value, and will
//! output a binary value. The output is guaranteed to have been input by at least one correct
//! node, and all correct nodes will have the same output.
//!
//! ## How it works
//!
//! The algorithm proceeds in _epochs_, and the number of epochs it takes until it terminates is
//! unbounded in theory but has a finite expected value. Each node keeps track of an _estimate_
//! value `e`, which is initialized to the node's own input. Let's call a value `v`
//! that has been input by at least one correct node and such that `!v` hasn't been _output_ by any
//! correct node yet, a _viable output_. The estimate will always be a viable output.
//!
//! All messages are annotated with the epoch they belong to, but we omit that here for brevity.
//!
//! * At the beginning of each epoch, we multicast `BVal(e)`. It translates to: "I know that `e` is
//!   a viable output."
//!
//! * Once we receive `BVal(v)` with the same value from _f + 1_ different validators, we know that
//!   at least one of them must be correct. So we know that `v` is a viable output. If we haven't
//!   done so already we multicast `BVal(v)`. (Even if we already multicast `BVal(!v)`).
//!
//! * Let's say a node _believes in `v`_ if it received `BVal(v)` from _2 f + 1_ validators.
//!   For the _first_ value `v` we believe in, we multicast `Aux(v)`. It translates to:
//!   "I know that all correct nodes will eventually know that `v` is a viable output.
//!   I'm not sure about `!v` yet."
//!
//!   * Since every node will receive at least _2 f + 1_ `BVal` messages from correct validators,
//!     there is at least one value `v`, such that every node receives _f + 1_ `BVal(v)` messages.
//!     As a consequence, every correct validator will multicast `BVal(v)` itself. Hence we are
//!     guaranteed to receive _2 f + 1_ `BVal(v)` messages.
//!     In short: If _any_ correct node believes in `v`, _every_ correct node will.
//!
//!   * Every correct node will eventually send exactly one `Aux`, so we will receive at least
//!     _N - f_ `Aux` messages with values we believe in. At that point, we define the set `vals`
//!     of _candidate values_: the set of values we believe in _and_ have received in an `Aux`.
//!
//! * Once we have the set of candidate values, we obtain a _coin value_ `s` (see below).
//!
//!   * If there is only a single candidate value `b`, we set our estimate `e = b`. If `s == b`,
//!     we _output_ and send a `Term(b)` message which is interpreted as `BVal(b)` and `Aux(b)` for
//!     all future epochs. If `s != b`, we just proceed to the next epoch.
//!
//!   * If both values are candidates, we set `e = s` and proceed to the next epoch.
//!
//! In epochs that are 0 modulo 3, the value `s` is `true`. In 1 modulo 3, it is `false`. In the
//! case 2 modulo 3, we flip a coin to determine a pseudorandom `s`.
//!
//! An adversary that knows each coin value, controls a few validators and controls network
//! scheduling can delay the delivery of `Aux` and `BVal` messages to influence which candidate
//! values the nodes will end up with. In some circumstances that allows them to stall the network.
//! This is even true if the coin is flipped too early: the adversary must not learn about the coin
//! value early enough to delay enough `Aux` messages. That's why in the third case, the value `s`
//! is determined as follows:
//!
//! * We multicast a `Conf` message containing our candidate values.
//!
//! * Since every good node believes in all values it puts into its `Conf` message, we will
//! eventually receive _N - f_ `Conf` messages containing only values we believe in. Then we
//! trigger the coin.
//!
//! * After _f + 1_ nodes have sent us their coin shares, we receive the coin output and assign it
//! to `s`.

mod binary_agreement;
mod bool_multimap;
pub mod bool_set;
mod sbv_broadcast;

use rand;

use self::bool_set::BoolSet;
use threshold_sign;

pub use self::binary_agreement::BinaryAgreement;

/// An Binary Agreement error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "Error handling threshold sign message: {}", _0)]
    HandleThresholdSign(threshold_sign::Error),
    #[fail(display = "Error invoking the common coin: {}", _0)]
    InvokeCoin(threshold_sign::Error),
    #[fail(display = "Unknown proposer")]
    UnknownProposer,
}

/// An Binary Agreement result.
pub type Result<T> = ::std::result::Result<T, Error>;

pub type Step<N> = ::Step<BinaryAgreement<N>>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MessageContent {
    /// Synchronized Binary Value Broadcast message.
    SbvBroadcast(sbv_broadcast::Message),
    /// `Conf` message.
    Conf(BoolSet),
    /// `Term` message.
    Term(bool),
    /// `ThresholdSign` message used for the common coin,
    Coin(Box<threshold_sign::Message>),
}

impl MessageContent {
    /// Creates an message with a given epoch number.
    pub fn with_epoch(self, epoch: u32) -> Message {
        Message {
            epoch,
            content: self,
        }
    }

    /// Returns `true` if this message can be ignored if its epoch has already passed.
    pub fn can_expire(&self) -> bool {
        match *self {
            MessageContent::Term(_) => false,
            _ => true,
        }
    }
}

/// Messages sent during the Binary Agreement stage.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Rand)]
pub struct Message {
    pub epoch: u32,
    pub content: MessageContent,
}

// NOTE: Extending rand_derive to correctly generate random values from boxes would make this
// implementation obsolete; however at the time of this writing, `rand::Rand` is already deprecated
// with no replacement in sight.
impl rand::Rand for MessageContent {
    fn rand<R: rand::Rng>(rng: &mut R) -> Self {
        let message_type = *rng.choose(&["sbvb", "conf", "term", "coin"]).unwrap();

        match message_type {
            "sbvb" => MessageContent::SbvBroadcast(rng.gen()),
            "conf" => MessageContent::Conf(rng.gen()),
            "term" => MessageContent::Term(rng.gen()),
            "coin" => MessageContent::Coin(Box::new(rng.gen())),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
struct Nonce(Vec<u8>);

impl Nonce {
    pub fn new(
        invocation_id: &[u8],
        session_id: u64,
        proposer_id: usize,
        binary_agreement_epoch: u32,
    ) -> Self {
        Nonce(Vec::from(format!(
            "Nonce for Honey Badger {:?}@{}:{}:{}",
            invocation_id, session_id, binary_agreement_epoch, proposer_id
        )))
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
