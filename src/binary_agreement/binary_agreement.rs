use std::collections::BTreeMap;
use std::sync::Arc;

use super::bool_multimap::BoolMultimap;
use super::bool_set::BoolSet;
use super::sbv_broadcast::{self, SbvBroadcast};
use super::{Error, Message, MessageContent, Nonce, Result, Step};
use coin::{self, Coin, CoinMessage};
use messaging::{DistAlgorithm, NetworkInfo, Target};
use traits::NodeIdT;

/// The state of the current epoch's coin. In some epochs this is fixed, in others it starts
/// with in `InProgress`.
#[derive(Debug)]
enum CoinState<N> {
    /// The value was fixed in the current epoch, or the coin has already terminated.
    Decided(bool),
    /// The coin value is not known yet.
    InProgress(Coin<N, Nonce>),
}

impl<N> CoinState<N> {
    /// Returns the value, if this coin has already decided.
    fn value(&self) -> Option<bool> {
        match self {
            CoinState::Decided(value) => Some(*value),
            CoinState::InProgress(_) => None,
        }
    }
}

impl<N> From<bool> for CoinState<N> {
    fn from(value: bool) -> Self {
        CoinState::Decided(value)
    }
}

/// Binary Agreement instance
#[derive(Debug)]
pub struct BinaryAgreement<N> {
    /// Shared network information.
    netinfo: Arc<NetworkInfo<N>>,
    /// Session ID, e.g, the Honey Badger algorithm epoch.
    session_id: u64,
    /// The ID of the proposer of the value for this Binary Agreement instance.
    proposer_id: N,
    /// Binary Agreement algorithm epoch.
    epoch: u32,
    /// This epoch's Synchronized Binary Value Broadcast instance.
    sbv_broadcast: SbvBroadcast<N>,
    /// Received `Conf` messages. Reset on every epoch update.
    received_conf: BTreeMap<N, BoolSet>,
    /// Received `Term` messages. Kept throughout epoch updates. These count as `BVal`, `Aux` and
    /// `Conf` messages for all future epochs.
    received_term: BoolMultimap<N>,
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
    incoming_queue: BTreeMap<u32, Vec<(N, MessageContent)>>,
    /// The values we found in the first _N - f_ `Aux` messages that were in `bin_values`.
    conf_values: Option<BoolSet>,
    /// The state of this epoch's coin.
    coin_state: CoinState<N>,
}

impl<N: NodeIdT> DistAlgorithm for BinaryAgreement<N> {
    type NodeId = N;
    type Input = bool;
    type Output = bool;
    type Message = Message;
    type Error = Error;

    fn handle_input(&mut self, input: Self::Input) -> Result<Step<N>> {
        self.handle_input(input)
    }

    /// Receive input from a remote node.
    fn handle_message(&mut self, sender_id: &Self::NodeId, msg: Message) -> Result<Step<N>> {
        let Message { epoch, content } = msg;
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

    fn our_id(&self) -> &Self::NodeId {
        self.netinfo.our_id()
    }
}

impl<N: NodeIdT> BinaryAgreement<N> {
    pub fn new(netinfo: Arc<NetworkInfo<N>>, session_id: u64, proposer_id: N) -> Result<Self> {
        if !netinfo.is_node_validator(&proposer_id) {
            return Err(Error::UnknownProposer);
        }
        Ok(BinaryAgreement {
            netinfo: netinfo.clone(),
            session_id,
            proposer_id,
            epoch: 0,
            sbv_broadcast: SbvBroadcast::new(netinfo),
            received_conf: BTreeMap::new(),
            received_term: BoolMultimap::default(),
            estimated: None,
            decision: None,
            incoming_queue: BTreeMap::new(),
            conf_values: None,
            coin_state: CoinState::Decided(true),
        })
    }

    /// Sets the input value for Binary Agreement.
    fn handle_input(&mut self, input: bool) -> Result<Step<N>> {
        if self.epoch != 0 || self.estimated.is_some() {
            return Err(Error::InputNotAccepted);
        }
        // Set the initial estimated value to the input value.
        self.estimated = Some(input);
        debug!("{:?}/{:?} Input {}", self.our_id(), self.proposer_id, input);
        let sbvb_step = self.sbv_broadcast.handle_input(input)?;
        self.handle_sbvb_step(sbvb_step)
    }

    /// Acceptance check to be performed before setting the input value.
    pub fn accepts_input(&self) -> bool {
        self.epoch == 0 && self.estimated.is_none()
    }

    /// Dispatches the message content to the corresponding handling method.
    fn handle_message_content(
        &mut self,
        sender_id: &N,
        content: MessageContent,
    ) -> Result<Step<N>> {
        match content {
            MessageContent::SbvBroadcast(msg) => self.handle_sbv_broadcast(sender_id, msg),
            MessageContent::Conf(v) => self.handle_conf(sender_id, v),
            MessageContent::Term(v) => self.handle_term(sender_id, v),
            MessageContent::Coin(msg) => self.handle_coin(sender_id, *msg),
        }
    }

    /// Handles a Synchroniced Binary Value Broadcast message.
    fn handle_sbv_broadcast(
        &mut self,
        sender_id: &N,
        msg: sbv_broadcast::Message,
    ) -> Result<Step<N>> {
        let sbvb_step = self.sbv_broadcast.handle_message(sender_id, msg)?;
        self.handle_sbvb_step(sbvb_step)
    }

    /// Handles a Synchronized Binary Value Broadcast step. On output, starts the `Conf` round or
    /// decides.
    fn handle_sbvb_step(&mut self, sbvb_step: sbv_broadcast::Step<N>) -> Result<Step<N>> {
        let mut step = Step::default();
        let output = step.extend_with(sbvb_step, |msg| {
            MessageContent::SbvBroadcast(msg).with_epoch(self.epoch)
        });
        if self.conf_values.is_some() {
            return Ok(step); // The `Conf` round has already started.
        }
        if let Some(aux_vals) = output.into_iter().next() {
            // Execute the Coin schedule `false, true, get_coin(), false, true, get_coin(), ...`
            match self.coin_state {
                CoinState::Decided(_) => {
                    self.conf_values = Some(aux_vals);
                    step.extend(self.try_update_epoch()?)
                }
                CoinState::InProgress(_) => {
                    // Start the `Conf` message round.
                    step.extend(self.send_conf(aux_vals)?)
                }
            }
        }
        Ok(step)
    }

    /// Handles a `Conf` message. When _N - f_ `Conf` messages with values in `bin_values` have
    /// been received, updates the epoch or decides.
    fn handle_conf(&mut self, sender_id: &N, v: BoolSet) -> Result<Step<N>> {
        self.received_conf.insert(sender_id.clone(), v);
        self.try_finish_conf_round()
    }

    /// Handles a `Term(v)` message. If we haven't yet decided on a value and there are more than
    /// _f_ such messages with the same value from different nodes, performs expedite termination:
    /// decides on `v`, broadcasts `Term(v)` and terminates the instance.
    fn handle_term(&mut self, sender_id: &N, b: bool) -> Result<Step<N>> {
        self.received_term[b].insert(sender_id.clone());
        // Check for the expedite termination condition.
        if self.decision.is_some() {
            Ok(Step::default())
        } else if self.received_term[b].len() > self.netinfo.num_faulty() {
            Ok(self.decide(b))
        } else {
            // Otherwise handle the `Term` as a `BVal`, `Aux` and `Conf`.
            let mut sbvb_step = self.sbv_broadcast.handle_bval(sender_id, b)?;
            sbvb_step.extend(self.sbv_broadcast.handle_aux(sender_id, b)?);
            let mut step = self.handle_sbvb_step(sbvb_step)?;
            step.extend(self.handle_conf(sender_id, BoolSet::from(b))?);
            Ok(step)
        }
    }

    /// Handles a Coin message. If there is output from Coin, starts the next
    /// epoch. The function may output a decision value.
    fn handle_coin(&mut self, sender_id: &N, msg: CoinMessage) -> Result<Step<N>> {
        let coin_step = match self.coin_state {
            CoinState::Decided(_) => return Ok(Step::default()), // Coin value is already decided.
            CoinState::InProgress(ref mut coin) => coin
                .handle_message(sender_id, msg)
                .map_err(Error::HandleCoin)?,
        };
        self.on_coin_step(coin_step)
    }

    /// Multicasts a `Conf(values)` message, and handles it.
    fn send_conf(&mut self, values: BoolSet) -> Result<Step<N>> {
        if self.conf_values.is_some() {
            // Only one `Conf` message is allowed in an epoch.
            return Ok(Step::default());
        }

        // Trigger the start of the `Conf` round.
        self.conf_values = Some(values);

        if !self.netinfo.is_validator() {
            return Ok(self.try_finish_conf_round()?);
        }

        self.send(MessageContent::Conf(values))
    }

    /// Multicasts and handles a message. Does nothing if we are only an observer.
    fn send(&mut self, content: MessageContent) -> Result<Step<N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        let mut step: Step<_> = Target::All
            .message(content.clone().with_epoch(self.epoch))
            .into();
        let our_id = &self.netinfo.our_id().clone();
        step.extend(self.handle_message_content(our_id, content)?);
        Ok(step)
    }

    /// Handles a step returned from the `Coin`.
    fn on_coin_step(&mut self, coin_step: coin::Step<N, Nonce>) -> Result<Step<N>> {
        let mut step = Step::default();
        let epoch = self.epoch;
        let to_msg = |c_msg| MessageContent::Coin(Box::new(c_msg)).with_epoch(epoch);
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
    fn try_update_epoch(&mut self) -> Result<Step<N>> {
        if self.decision.is_some() {
            // Avoid an infinite regression without making a Binary Agreement step.
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
    /// value, or initializes a `Coin` instance.
    fn coin_state(&self) -> CoinState<N> {
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
                CoinState::InProgress(Coin::new(self.netinfo.clone(), nonce))
            }
        }
    }

    /// Decides on a value and broadcasts a `Term` message with that value.
    fn decide(&mut self, b: bool) -> Step<N> {
        if self.decision.is_some() {
            return Step::default();
        }
        // Output the Binary Agreement value.
        let mut step = Step::default();
        step.output.push_back(b);
        // Latch the decided state.
        self.decision = Some(b);
        debug!(
            "{:?}/{:?} (is_validator: {}) decision: {}",
            self.netinfo.our_id(),
            self.proposer_id,
            self.netinfo.is_validator(),
            b
        );
        if self.netinfo.is_validator() {
            let msg = MessageContent::Term(b).with_epoch(self.epoch + 1);
            step.messages.push_back(Target::All.message(msg));
        }
        step
    }

    /// Checks whether the _N - f_ `Conf` messages have arrived, and if so, activates the coin.
    fn try_finish_conf_round(&mut self) -> Result<Step<N>> {
        if self.conf_values.is_none() || self.count_conf() < self.netinfo.num_correct() {
            return Ok(Step::default());
        }

        // Invoke the coin.
        let coin_step = match self.coin_state {
            CoinState::Decided(_) => return Ok(Step::default()), // Coin has already decided.
            CoinState::InProgress(ref mut coin) => coin
                .handle_input(())
                .map_err(Error::TryFinishConfRoundCoin)?,
        };
        let mut step = self.on_coin_step(coin_step)?;
        step.extend(self.try_update_epoch()?);
        Ok(step)
    }

    /// Counts the number of received `Conf` messages with values in `bin_values`.
    fn count_conf(&self) -> usize {
        let is_bin_val = |conf: &&BoolSet| conf.is_subset(self.sbv_broadcast.bin_values());
        self.received_conf.values().filter(is_bin_val).count()
    }

    /// Increments the epoch, sets the new estimate and handles queued messages.
    fn update_epoch(&mut self, b: bool) -> Result<Step<N>> {
        self.sbv_broadcast.clear(&self.received_term);
        self.received_conf.clear();
        for (v, id) in &self.received_term {
            self.received_conf.insert(id.clone(), BoolSet::from(v));
        }
        self.conf_values = None;
        self.epoch += 1;
        self.coin_state = self.coin_state();
        debug!(
            "{:?} BinaryAgreement instance {:?} started epoch {}, {} terminated",
            self.netinfo.our_id(),
            self.proposer_id,
            self.epoch,
            self.received_conf.len(),
        );

        self.estimated = Some(b);
        let sbvb_step = self.sbv_broadcast.handle_input(b)?;
        let mut step = self.handle_sbvb_step(sbvb_step)?;
        let queued_msgs = self
            .incoming_queue
            .remove(&self.epoch)
            .into_iter()
            .flatten();
        for (sender_id, content) in queued_msgs {
            step.extend(self.handle_message_content(&sender_id, content)?);
            if self.decision.is_some() {
                break;
            }
        }
        Ok(step)
    }
}
