//! # Binary Byzantine agreement protocol
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
//! case 2 modulo 3, we flip a common coin to determine a pseudorandom `s`.
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
//! trigger the common coin.
//!
//! * After _f + 1_ nodes have sent us their coin shares, we receive the coin output and assign it
//! to `s`.

pub mod bin_values;

use rand;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::sync::Arc;

use itertools::Itertools;

use agreement::bin_values::BinValues;
use common_coin::{self, CommonCoin, CommonCoinMessage};
use messaging::{self, DistAlgorithm, NetworkInfo, Target};

error_chain!{
    links {
        CommonCoin(common_coin::Error, common_coin::ErrorKind);
    }

    errors {
        UnknownProposer {
            description("unknown proposer")
        }
        InputNotAccepted {
            description("input not accepted")
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AgreementContent {
    /// `BVal` message.
    BVal(bool),
    /// `Aux` message.
    Aux(bool),
    /// `Conf` message.
    Conf(BinValues),
    /// `Term` message.
    Term(bool),
    /// Common Coin message,
    Coin(Box<CommonCoinMessage>),
}

impl AgreementContent {
    /// Creates an message with a given epoch number.
    pub fn with_epoch(self, epoch: u32) -> AgreementMessage {
        AgreementMessage {
            epoch,
            content: self,
        }
    }

    /// Returns `true` if this message can be ignored if its epoch has already passed.
    pub fn can_expire(&self) -> bool {
        match *self {
            AgreementContent::Term(_) => false,
            _ => true,
        }
    }
}

/// Messages sent during the binary Byzantine agreement stage.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Rand)]
pub struct AgreementMessage {
    pub epoch: u32,
    pub content: AgreementContent,
}

// NOTE: Extending rand_derive to correctly generate random values from boxes would make this
// implementation obsolete; however at the time of this writing, `rand::Rand` is already deprecated
// with no replacement in sight.
impl rand::Rand for AgreementContent {
    fn rand<R: rand::Rng>(rng: &mut R) -> Self {
        let message_type = *rng
            .choose(&["bval", "aux", "conf", "term", "coin"])
            .unwrap();

        match message_type {
            "bval" => AgreementContent::BVal(rand::random()),
            "aux" => AgreementContent::Aux(rand::random()),
            "conf" => AgreementContent::Conf(rand::random()),
            "term" => AgreementContent::Term(rand::random()),
            "coin" => AgreementContent::Coin(Box::new(rand::random())),
            _ => unreachable!(),
        }
    }
}

/// The state of the current epoch's common coin. In some epochs this is fixed, in others it starts
/// with in `InProgress`.
#[derive(Debug)]
enum CoinState<NodeUid> {
    /// The value was fixed in the current epoch, or the coin has already terminated.
    Decided(bool),
    /// The coin value is not known yet.
    InProgress(CommonCoin<NodeUid, Nonce>),
}

impl<NodeUid> CoinState<NodeUid> {
    /// Returns the value, if this coin has already decided.
    fn value(&self) -> Option<bool> {
        match self {
            CoinState::Decided(value) => Some(*value),
            CoinState::InProgress(_) => None,
        }
    }
}

impl<NodeUid> From<bool> for CoinState<NodeUid> {
    fn from(value: bool) -> Self {
        CoinState::Decided(value)
    }
}

/// Binary Agreement instance
#[derive(Debug)]
pub struct Agreement<NodeUid> {
    /// Shared network information.
    netinfo: Arc<NetworkInfo<NodeUid>>,
    /// Session ID, e.g, the Honey Badger algorithm epoch.
    session_id: u64,
    /// The ID of the proposer of the value for this agreement instance.
    proposer_id: NodeUid,
    /// Agreement algorithm epoch.
    epoch: u32,
    /// Bin values. Reset on every epoch update.
    bin_values: BinValues,
    /// Values received in `BVal` messages. Reset on every epoch update.
    received_bval: BTreeMap<bool, BTreeSet<NodeUid>>,
    /// Sent `BVal` values. Reset on every epoch update.
    sent_bval: BTreeSet<bool>,
    /// Values received in `Aux` messages. Reset on every epoch update.
    received_aux: BTreeMap<bool, BTreeSet<NodeUid>>,
    /// Received `Conf` messages. Reset on every epoch update.
    received_conf: BTreeMap<NodeUid, BinValues>,
    /// Received `Term` messages. Kept throughout epoch updates. These count as `BVal`, `Aux` and
    /// `Conf` messages for all future epochs.
    received_term: BTreeMap<bool, BTreeSet<NodeUid>>,
    /// The estimate of the decision value in the current epoch.
    estimated: Option<bool>,
    /// A permanent, latching copy of the output value. This copy is required because `output` can
    /// be consumed using `DistAlgorithm::next_output` immediately after the instance finishing to
    /// handle a message, in which case it would otherwise be unknown whether the output value was
    /// ever there at all. While the output value will still be required in a later epoch to decide
    /// the termination state.
    decision: Option<bool>,
    /// A cache for messages for future epochs that cannot be handled yet.
    // TODO: Find a better solution for this; defend against spam.
    incoming_queue: BTreeMap<u32, Vec<(NodeUid, AgreementContent)>>,
    /// The values we found in the first _N - f_ `Aux` messages that were in `bin_values`.
    conf_values: Option<BinValues>,
    /// The state of this epoch's common coin.
    coin_state: CoinState<NodeUid>,
}

pub type Step<NodeUid> = messaging::Step<Agreement<NodeUid>>;

impl<NodeUid: Clone + Debug + Ord> DistAlgorithm for Agreement<NodeUid> {
    type NodeUid = NodeUid;
    type Input = bool;
    type Output = bool;
    type Message = AgreementMessage;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<Step<NodeUid>> {
        self.set_input(input)
    }

    /// Receive input from a remote node.
    fn handle_message(
        &mut self,
        sender_id: &Self::NodeUid,
        AgreementMessage { epoch, content }: Self::Message,
    ) -> Result<Step<NodeUid>> {
        if self.decision.is_some() || (epoch < self.epoch && content.can_expire()) {
            // Message is obsolete: We are already in a later epoch or terminated.
            Ok(Step::default())
        } else if epoch > self.epoch {
            // Message is for a later epoch. We can't handle that yet.
            let queue = self.incoming_queue.entry(epoch).or_insert_with(Vec::new);
            queue.push((sender_id.clone(), content));
            Ok(Step::default())
        } else {
            self.handle_message_content(sender_id, content)
        }
    }

    /// Whether the algorithm has terminated.
    fn terminated(&self) -> bool {
        self.decision.is_some()
    }

    fn our_id(&self) -> &Self::NodeUid {
        self.netinfo.our_uid()
    }
}

impl<NodeUid: Clone + Debug + Ord> Agreement<NodeUid> {
    pub fn new(
        netinfo: Arc<NetworkInfo<NodeUid>>,
        session_id: u64,
        proposer_id: NodeUid,
    ) -> Result<Self> {
        if !netinfo.is_node_validator(&proposer_id) {
            return Err(ErrorKind::UnknownProposer.into());
        }
        Ok(Agreement {
            netinfo,
            session_id,
            proposer_id,
            epoch: 0,
            bin_values: BinValues::new(),
            received_bval: BTreeMap::new(),
            sent_bval: BTreeSet::new(),
            received_aux: BTreeMap::new(),
            received_conf: BTreeMap::new(),
            received_term: BTreeMap::new(),
            estimated: None,
            decision: None,
            incoming_queue: BTreeMap::new(),
            conf_values: None,
            coin_state: CoinState::Decided(true),
        })
    }

    /// Sets the input value for agreement.
    fn set_input(&mut self, input: bool) -> Result<Step<NodeUid>> {
        if self.epoch != 0 || self.estimated.is_some() {
            return Err(ErrorKind::InputNotAccepted.into());
        }
        // Set the initial estimated value to the input value.
        self.estimated = Some(input);
        debug!("{:?}/{:?} Input {}", self.our_id(), self.proposer_id, input);
        // Record the input value as sent.
        self.send_bval(input)
    }

    /// Acceptance check to be performed before setting the input value.
    pub fn accepts_input(&self) -> bool {
        self.epoch == 0 && self.estimated.is_none()
    }

    /// Dispatches the message content to the corresponding handling method.
    fn handle_message_content(
        &mut self,
        sender_id: &NodeUid,
        content: AgreementContent,
    ) -> Result<Step<NodeUid>> {
        match content {
            AgreementContent::BVal(b) => self.handle_bval(sender_id, b),
            AgreementContent::Aux(b) => self.handle_aux(sender_id, b),
            AgreementContent::Conf(v) => self.handle_conf(sender_id, v),
            AgreementContent::Term(v) => self.handle_term(sender_id, v),
            AgreementContent::Coin(msg) => self.handle_coin(sender_id, *msg),
        }
    }

    /// Handles a `BVal(b)` message.
    ///
    /// Upon receiving _f + 1_ `BVal(b)`, multicast `BVal(b)`. Upon receiving _2 f + 1_ `BVal(b)`,
    /// update `bin_values`. When `bin_values` gets its first entry, multicast `Aux(b)`. If the
    /// condition is met, starts the `Conf` round or decides. (See `on_bval_or_aux`.)
    fn handle_bval(&mut self, sender_id: &NodeUid, b: bool) -> Result<Step<NodeUid>> {
        let count_bval = {
            let entry = self.received_bval.entry(b).or_insert_with(BTreeSet::new);
            if !entry.insert(sender_id.clone()) {
                return Ok(Step::default()); // TODO: Fault?
            }
            entry.len()
        };

        let mut step = Step::default();

        if count_bval == 2 * self.netinfo.num_faulty() + 1 {
            self.bin_values.insert(b);

            if self.bin_values != BinValues::Both {
                step.extend(self.send(AgreementContent::Aux(b))?) // First entry: send `Aux(b)`.
            } else {
                step.extend(self.on_bval_or_aux()?); // Otherwise just check for `Conf` condition.
            }
        }

        if count_bval == self.netinfo.num_faulty() + 1 {
            step.extend(self.send_bval(b)?);
        }

        Ok(step)
    }

    /// Handles an `Aux` message.
    ///
    /// If the condition is met, starts the `Conf` round or decides. (See `on_bval_or_aux`.)
    fn handle_aux(&mut self, sender_id: &NodeUid, b: bool) -> Result<Step<NodeUid>> {
        // Perform the `Aux` message round only if a `Conf` round hasn't started yet.
        if self.conf_values.is_some() {
            return Ok(Step::default());
        }
        // TODO: Detect duplicate `Aux` messages and report faults.
        self.received_aux
            .entry(b)
            .or_insert_with(BTreeSet::new)
            .insert(sender_id.clone());
        self.on_bval_or_aux()
    }

    /// Handles a `Conf` message. When _N - f_ `Conf` messages with values in `bin_values` have
    /// been received, updates the epoch or decides.
    fn handle_conf(&mut self, sender_id: &NodeUid, v: BinValues) -> Result<Step<NodeUid>> {
        self.received_conf.insert(sender_id.clone(), v);
        self.try_finish_conf_round()
    }

    /// Handles a `Term(v)` message. If we haven't yet decided on a value and there are more than
    /// _f_ such messages with the same value from different nodes, performs expedite termination:
    /// decides on `v`, broadcasts `Term(v)` and terminates the instance.
    fn handle_term(&mut self, sender_id: &NodeUid, b: bool) -> Result<Step<NodeUid>> {
        self.received_term
            .entry(b)
            .or_insert_with(BTreeSet::new)
            .insert(sender_id.clone());
        // Check for the expedite termination condition.
        if self.decision.is_some() {
            Ok(Step::default())
        } else if self.received_term[&b].len() > self.netinfo.num_faulty() {
            Ok(self.decide(b))
        } else {
            // Otherwise handle the `Term` as a `BVal`, `Aux` and `Conf`.
            let mut step = self.handle_bval(sender_id, b)?;
            step.extend(self.handle_aux(sender_id, b)?);
            step.extend(self.handle_conf(sender_id, BinValues::from_bool(b))?);
            Ok(step)
        }
    }

    /// Handles a Common Coin message. If there is output from Common Coin, starts the next
    /// epoch. The function may output a decision value.
    fn handle_coin(
        &mut self,
        sender_id: &NodeUid,
        msg: CommonCoinMessage,
    ) -> Result<Step<NodeUid>> {
        let coin_step = match self.coin_state {
            CoinState::Decided(_) => return Ok(Step::default()), // Coin value is already decided.
            CoinState::InProgress(ref mut common_coin) => {
                common_coin.handle_message(sender_id, msg)?
            }
        };
        self.on_coin_step(coin_step)
    }

    /// Checks whether there are _N - f_ `Aux` messages with values in `bin_values`. If so, starts
    /// the `Conf` round or decides.
    fn on_bval_or_aux(&mut self) -> Result<Step<NodeUid>> {
        if self.bin_values == BinValues::None || self.conf_values.is_some() {
            return Ok(Step::default());
        }
        let (aux_count, aux_vals) = self.count_aux();
        if aux_count < self.netinfo.num_correct() {
            return Ok(Step::default());
        }
        // Execute the Common Coin schedule `false, true, get_coin(), false, true, get_coin(), ...`
        match self.coin_state {
            CoinState::Decided(_) => {
                self.conf_values = Some(aux_vals);
                self.try_update_epoch()
            }
            CoinState::InProgress(_) => self.send_conf(aux_vals), // Start the `Conf` message round.
        }
    }

    /// Multicasts a `BVal(b)` message, and handles it.
    fn send_bval(&mut self, b: bool) -> Result<Step<NodeUid>> {
        // Record the value `b` as sent. If it was already there, don't send it again.
        if !self.sent_bval.insert(b) {
            return Ok(Step::default());
        }
        self.send(AgreementContent::BVal(b))
    }

    /// Multicasts a `Conf(values)` message, and handles it.
    fn send_conf(&mut self, values: BinValues) -> Result<Step<NodeUid>> {
        if self.conf_values.is_some() {
            // Only one `Conf` message is allowed in an epoch.
            return Ok(Step::default());
        }

        // Trigger the start of the `Conf` round.
        self.conf_values = Some(values);

        if !self.netinfo.is_validator() {
            return Ok(self.try_finish_conf_round()?);
        }

        self.send(AgreementContent::Conf(values))
    }

    /// Multicasts and handles a message. Does nothing if we are only an observer.
    fn send(&mut self, content: AgreementContent) -> Result<Step<NodeUid>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        let mut step: Step<_> = Target::All
            .message(content.clone().with_epoch(self.epoch))
            .into();
        let our_uid = &self.netinfo.our_uid().clone();
        step.extend(self.handle_message_content(our_uid, content)?);
        Ok(step)
    }

    /// Handles a step returned from the `CommonCoin`.
    fn on_coin_step(
        &mut self,
        coin_step: common_coin::Step<NodeUid, Nonce>,
    ) -> Result<Step<NodeUid>> {
        let mut step = Step::default();
        let epoch = self.epoch;
        let to_msg = |c_msg| AgreementContent::Coin(Box::new(c_msg)).with_epoch(epoch);
        let coin_output = step.extend_with(coin_step, to_msg);
        if let Some(coin) = coin_output.into_iter().next() {
            self.coin_state = coin.into();
            step.extend(self.try_update_epoch()?);
        }
        Ok(step)
    }

    /// If this epoch's coin value or conf values are not known yet, does nothing, otherwise
    /// updates the epoch or decides.
    ///
    /// With two conf values, the next epoch's estimate is the coin value. If there is only one conf
    /// value and that disagrees with the coin, the conf value is the next epoch's estimate. If
    /// the unique conf value agrees with the coin, terminates and decides on that value.
    fn try_update_epoch(&mut self) -> Result<Step<NodeUid>> {
        if self.decision.is_some() {
            // Avoid an infinite regression without making an Agreement step.
            return Ok(Step::default());
        }
        let coin = match self.coin_state.value() {
            None => return Ok(Step::default()), // Still waiting for coin value.
            Some(coin) => coin,
        };
        let def_bin_value = match self.conf_values {
            None => return Ok(Step::default()), // Still waiting for conf value.
            Some(ref values) => values.definite(),
        };

        if Some(coin) == def_bin_value {
            Ok(self.decide(coin))
        } else {
            self.update_epoch(def_bin_value.unwrap_or(coin))
        }
    }

    /// Creates the initial coin state for the current epoch, i.e. sets it to the predetermined
    /// value, or initializes a `CommonCoin` instance.
    fn coin_state(&self) -> CoinState<NodeUid> {
        match self.epoch % 3 {
            0 => CoinState::Decided(true),
            1 => CoinState::Decided(false),
            _ => {
                let nonce = Nonce::new(
                    self.netinfo.invocation_id().as_ref(),
                    self.session_id,
                    self.netinfo.node_index(&self.proposer_id).unwrap(),
                    self.epoch,
                );
                CoinState::InProgress(CommonCoin::new(self.netinfo.clone(), nonce))
            }
        }
    }

    /// Decides on a value and broadcasts a `Term` message with that value.
    fn decide(&mut self, b: bool) -> Step<NodeUid> {
        if self.decision.is_some() {
            return Step::default();
        }
        // Output the agreement value.
        let mut step = Step::default();
        step.output.push_back(b);
        // Latch the decided state.
        self.decision = Some(b);
        debug!(
            "{:?}/{:?} (is_validator: {}) decision: {}",
            self.netinfo.our_uid(),
            self.proposer_id,
            self.netinfo.is_validator(),
            b
        );
        if self.netinfo.is_validator() {
            let msg = AgreementContent::Term(b).with_epoch(self.epoch + 1);
            step.messages.push_back(Target::All.message(msg));
        }
        step
    }

    /// Checks whether the _N - f_ `Conf` messages have arrived, and if so, activates the coin.
    fn try_finish_conf_round(&mut self) -> Result<Step<NodeUid>> {
        if self.conf_values.is_none() || self.count_conf() < self.netinfo.num_correct() {
            return Ok(Step::default());
        }

        // Invoke the common coin.
        let coin_step = match self.coin_state {
            CoinState::Decided(_) => return Ok(Step::default()), // TODO: Error!
            CoinState::InProgress(ref mut common_coin) => common_coin.input(())?,
        };
        let mut step = self.on_coin_step(coin_step)?;
        step.extend(self.try_update_epoch()?);
        Ok(step)
    }

    /// Counts the number of received `Conf` messages with values in `bin_values`.
    fn count_conf(&self) -> usize {
        let is_bin_val = |conf: &&BinValues| conf.is_subset(self.bin_values);
        self.received_conf.values().filter(is_bin_val).count()
    }

    /// The count of `Aux` messages such that the set of values carried by those messages is a
    /// subset of `bin_values`.
    ///
    /// In general, we can't expect every good node to send the same `Aux` value, so waiting for
    /// _N - f_ agreeing messages would not always terminate. We can, however, expect every good
    /// node to send an `Aux` value that will eventually end up in our `bin_values`.
    fn count_aux(&self) -> (usize, BinValues) {
        let mut values = BinValues::None;
        let mut count = 0;
        for b in self.bin_values {
            let b_count = self.received_aux.get(&b).map_or(0, BTreeSet::len);
            if b_count > 0 {
                values.insert(b);
                count += b_count;
            }
        }
        (count, values)
    }

    /// Increments the epoch, sets the new estimate and handles queued messages.
    fn update_epoch(&mut self, b: bool) -> Result<Step<NodeUid>> {
        self.bin_values.clear();
        self.received_bval = self.received_term.clone();
        self.sent_bval.clear();
        self.received_aux = self.received_term.clone();
        self.received_conf.clear();
        for (v, ids) in &self.received_term {
            for id in ids {
                self.received_conf
                    .insert(id.clone(), BinValues::from_bool(*v));
            }
        }
        self.conf_values = None;
        self.epoch += 1;
        self.coin_state = self.coin_state();
        debug!(
            "{:?} Agreement instance {:?} started epoch {}, {} terminated",
            self.netinfo.our_uid(),
            self.proposer_id,
            self.epoch,
            self.received_conf.len(),
        );

        self.estimated = Some(b);
        let mut step = self.send_bval(b)?;
        let queued_msgs = Itertools::flatten(self.incoming_queue.remove(&self.epoch).into_iter());
        for (sender_id, content) in queued_msgs {
            step.extend(self.handle_message_content(&sender_id, content)?);
            if self.decision.is_some() {
                break;
            }
        }
        Ok(step)
    }
}

#[derive(Clone, Debug)]
struct Nonce(Vec<u8>);

impl Nonce {
    pub fn new(
        invocation_id: &[u8],
        session_id: u64,
        proposer_id: usize,
        agreement_epoch: u32,
    ) -> Self {
        Nonce(Vec::from(format!(
            "Nonce for Honey Badger {:?}@{}:{}:{}",
            invocation_id, session_id, agreement_epoch, proposer_id
        )))
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
