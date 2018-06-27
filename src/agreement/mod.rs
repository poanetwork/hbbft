//! Binary Byzantine agreement protocol from a common coin protocol.

pub mod bin_values;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::mem::replace;
use std::rc::Rc;

use itertools::Itertools;

use agreement::bin_values::BinValues;
use common_coin;
use common_coin::{CommonCoin, CommonCoinMessage};
use messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};

error_chain!{
    links {
        CommonCoin(common_coin::Error, common_coin::ErrorKind);
    }

    types {
        Error, ErrorKind, ResultExt, AgreementResult;
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
}

/// Messages sent during the binary Byzantine agreement stage.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AgreementMessage {
    pub epoch: u32,
    pub content: AgreementContent,
}

/// Possible values of the common coin schedule defining the method to derive the common coin in a
/// given epoch: as a constant value or a distributed computation.
enum CoinSchedule {
    False,
    True,
    Random,
}

/// Binary Agreement instance
pub struct Agreement<NodeUid> {
    /// Shared network information.
    netinfo: Rc<NetworkInfo<NodeUid>>,
    /// Session ID, e.g, the Honey Badger algorithm epoch.
    session_id: u64,
    /// The ID of the proposer of the value for this agreement instance.
    proposer_id: NodeUid,
    /// Agreement algorithm epoch.
    epoch: u32,
    /// Bin values. Reset on every epoch update.
    bin_values: BinValues,
    /// Values received in `BVal` messages. Reset on every epoch update.
    received_bval: BTreeMap<NodeUid, BTreeSet<bool>>,
    /// Sent `BVal` values. Reset on every epoch update.
    sent_bval: BTreeSet<bool>,
    /// Values received in `Aux` messages. Reset on every epoch update.
    received_aux: BTreeMap<NodeUid, bool>,
    /// Received `Conf` messages. Reset on every epoch update.
    received_conf: BTreeMap<NodeUid, BinValues>,
    /// Received `Term` messages. Kept throughout epoch updates.
    received_term: BTreeMap<NodeUid, bool>,
    /// The estimate of the decision value in the current epoch.
    estimated: Option<bool>,
    /// The value output by the agreement instance. It is set once to `Some(b)`
    /// and then never changed. That is, no instance of Binary Agreement can
    /// decide on two different values of output.
    output: Option<bool>,
    /// A permanent, latching copy of the output value. This copy is required because `output` can
    /// be consumed using `DistAlgorithm::next_output` immediately after the instance finishing to
    /// handle a message, in which case it would otherwise be unknown whether the output value was
    /// ever there at all. While the output value will still be required in a later epoch to decide
    /// the termination state.
    decision: Option<bool>,
    /// A cache for messages for future epochs that cannot be handled yet.
    // TODO: Find a better solution for this; defend against spam.
    incoming_queue: Vec<(NodeUid, AgreementMessage)>,
    /// Termination flag. The Agreement instance doesn't terminate immediately
    /// upon deciding on the agreed value. This is done in order to help other
    /// nodes decide despite asynchrony of communication. Once the instance
    /// determines that all the remote nodes have reached agreement, it sets the
    /// `terminated` flag and accepts no more incoming messages.
    terminated: bool,
    /// The outgoing message queue.
    messages: VecDeque<AgreementMessage>,
    /// Whether the `Conf` message round has started in the current epoch.
    conf_round: bool,
    /// A common coin instance. It is reset on epoch update.
    common_coin: CommonCoin<NodeUid, Nonce>,
    /// Common coin schedule computed at the start of each epoch.
    coin_schedule: CoinSchedule,
}

impl<NodeUid: Clone + Debug + Ord> DistAlgorithm for Agreement<NodeUid> {
    type NodeUid = NodeUid;
    type Input = bool;
    type Output = bool;
    type Message = AgreementMessage;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> AgreementResult<()> {
        self.set_input(input)
    }

    /// Receive input from a remote node.
    fn handle_message(
        &mut self,
        sender_id: &Self::NodeUid,
        message: Self::Message,
    ) -> AgreementResult<()> {
        if self.terminated || message.epoch < self.epoch {
            return Ok(()); // Message is obsolete: We are already in a later epoch or terminated.
        }
        if message.epoch > self.epoch {
            // Message is for a later epoch. We can't handle that yet.
            self.incoming_queue.push((sender_id.clone(), message));
            return Ok(());
        }
        match message.content {
            AgreementContent::BVal(b) => self.handle_bval(sender_id, b),
            AgreementContent::Aux(b) => self.handle_aux(sender_id, b),
            AgreementContent::Conf(v) => self.handle_conf(sender_id, v),
            AgreementContent::Term(v) => self.handle_term(sender_id, v),
            AgreementContent::Coin(msg) => self.handle_coin(sender_id, *msg),
        }
    }

    /// Take the next Agreement message for multicast to all other nodes.
    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, Self::NodeUid>> {
        self.messages
            .pop_front()
            .map(|msg| Target::All.message(msg))
    }

    /// Consume the output. Once consumed, the output stays `None` forever.
    fn next_output(&mut self) -> Option<Self::Output> {
        self.output.take()
    }

    /// Whether the algorithm has terminated.
    fn terminated(&self) -> bool {
        self.terminated
    }

    fn our_id(&self) -> &Self::NodeUid {
        self.netinfo.our_uid()
    }
}

impl<NodeUid: Clone + Debug + Ord> Agreement<NodeUid> {
    pub fn new(
        netinfo: Rc<NetworkInfo<NodeUid>>,
        session_id: u64,
        proposer_id: NodeUid,
    ) -> AgreementResult<Self> {
        let invocation_id = netinfo.invocation_id();
        if let Some(&proposer_i) = netinfo.node_index(&proposer_id) {
            Ok(Agreement {
                netinfo: netinfo.clone(),
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
                output: None,
                decision: None,
                incoming_queue: Vec::new(),
                terminated: false,
                messages: VecDeque::new(),
                conf_round: false,
                common_coin: CommonCoin::new(
                    netinfo,
                    Nonce::new(invocation_id.as_ref(), session_id, proposer_i, 0),
                ),
                coin_schedule: CoinSchedule::True,
            })
        } else {
            Err(ErrorKind::UnknownProposer.into())
        }
    }

    /// Sets the input value for agreement.
    pub fn set_input(&mut self, input: bool) -> AgreementResult<()> {
        if self.epoch != 0 || self.estimated.is_some() {
            return Err(ErrorKind::InputNotAccepted.into());
        }
        if self.netinfo.num_nodes() == 1 {
            self.decision = Some(input);
            self.output = Some(input);
            self.terminated = true;
            self.send_bval(input)?;
            self.send_aux(input)
        } else {
            // Set the initial estimated value to the input value.
            self.estimated = Some(input);
            // Record the input value as sent.
            self.send_bval(input)
        }
    }

    /// Acceptance check to be performed before setting the input value.
    pub fn accepts_input(&self) -> bool {
        self.epoch == 0 && self.estimated.is_none()
    }

    fn handle_bval(&mut self, sender_id: &NodeUid, b: bool) -> AgreementResult<()> {
        self.received_bval
            .entry(sender_id.clone())
            .or_insert_with(BTreeSet::new)
            .insert(b);
        let count_bval = self
            .received_bval
            .values()
            .filter(|values| values.contains(&b))
            .count();

        // upon receiving `BVal(b)` messages from 2f + 1 nodes,
        // bin_values := bin_values ∪ {b}
        if count_bval == 2 * self.netinfo.num_faulty() + 1 {
            let previous_bin_values = self.bin_values;
            let bin_values_changed = self.bin_values.insert(b);

            // wait until bin_values != 0, then multicast `Aux(w)`
            // where w ∈ bin_values
            if previous_bin_values == BinValues::None {
                // Send an `Aux` message at most once per epoch.
                self.send_aux(b)
            } else if bin_values_changed {
                self.on_bin_values_changed()
            } else {
                Ok(())
            }
        } else if count_bval == self.netinfo.num_faulty() + 1 && !self.sent_bval.contains(&b) {
            // upon receiving `BVal(b)` messages from f + 1 nodes, if
            // `BVal(b)` has not been sent, multicast `BVal(b)`
            self.send_bval(b)
        } else {
            Ok(())
        }
    }

    /// Called when `bin_values` changes as a result of receiving a `BVal` message. Tries to update
    /// the epoch.
    fn on_bin_values_changed(&mut self) -> AgreementResult<()> {
        match self.coin_schedule {
            CoinSchedule::False => {
                let (aux_count, aux_vals) = self.count_aux();
                if aux_count >= self.netinfo.num_nodes() - self.netinfo.num_faulty() {
                    self.on_coin(false, aux_vals.definite())
                } else {
                    Ok(())
                }
            }
            CoinSchedule::True => {
                let (aux_count, aux_vals) = self.count_aux();
                if aux_count >= self.netinfo.num_nodes() - self.netinfo.num_faulty() {
                    self.on_coin(true, aux_vals.definite())
                } else {
                    Ok(())
                }
            }
            CoinSchedule::Random => {
                // If the `Conf` round has already started, a change in `bin_values` can lead to its
                // end. Try if it has indeed finished.
                self.try_finish_conf_round()
            }
        }
    }

    fn send_bval(&mut self, b: bool) -> AgreementResult<()> {
        if !self.netinfo.is_peer() {
            return Ok(());
        }
        // Record the value `b` as sent.
        self.sent_bval.insert(b);
        // Multicast `BVal`.
        self.messages
            .push_back(AgreementContent::BVal(b).with_epoch(self.epoch));
        // Receive the `BVal` message locally.
        let our_uid = &self.netinfo.our_uid().clone();
        self.handle_bval(our_uid, b)
    }

    fn send_conf(&mut self) -> AgreementResult<()> {
        if self.conf_round {
            // Only one `Conf` message is allowed in an epoch.
            return Ok(());
        }

        // Trigger the start of the `Conf` round.
        self.conf_round = true;

        if !self.netinfo.is_peer() {
            return Ok(());
        }

        let v = self.bin_values;
        // Multicast `Conf`.
        self.messages
            .push_back(AgreementContent::Conf(v).with_epoch(self.epoch));
        // Receive the `Conf` message locally.
        let our_uid = &self.netinfo.our_uid().clone();
        self.handle_conf(our_uid, v)
    }

    /// Waits until at least (N − f) `Aux` messages have been received, such that
    /// the set of values carried by these messages, vals, are a subset of
    /// bin_values (note that bin_values_r may continue to change as `BVal`
    /// messages are received, thus this condition may be triggered upon arrival
    /// of either an `Aux` or a `BVal` message).
    fn handle_aux(&mut self, sender_id: &NodeUid, b: bool) -> AgreementResult<()> {
        // Perform the `Aux` message round only if a `Conf` round hasn't started yet.
        if self.conf_round {
            return Ok(());
        }
        self.received_aux.insert(sender_id.clone(), b);
        if self.bin_values == BinValues::None {
            return Ok(());
        }
        let (aux_count, aux_vals) = self.count_aux();
        if aux_count < self.netinfo.num_nodes() - self.netinfo.num_faulty() {
            // Continue waiting for the (N - f) `Aux` messages.
            return Ok(());
        }

        // Execute the Common Coin schedule `false, true, get_coin(), false, true, get_coin(), ...`
        match self.coin_schedule {
            CoinSchedule::False => self.on_coin(false, aux_vals.definite()),
            CoinSchedule::True => self.on_coin(true, aux_vals.definite()),
            CoinSchedule::Random => {
                // Start the `Conf` message round.
                self.send_conf()
            }
        }
    }

    fn handle_conf(&mut self, sender_id: &NodeUid, v: BinValues) -> AgreementResult<()> {
        self.received_conf.insert(sender_id.clone(), v);
        self.try_finish_conf_round()
    }

    /// Receives a `Term(v)` message. If we haven't yet decided on a value and there are more than
    /// `num_faulty` such messages with the same value from different nodes, performs expedite
    /// termination: decides on `v`, broadcasts `Term(v)` and terminates the instance.
    fn handle_term(&mut self, sender_id: &NodeUid, b: bool) -> AgreementResult<()> {
        self.received_term.insert(sender_id.clone(), b);
        // Check for the expedite termination condition.
        if self.decision.is_none()
            && self.received_term.iter().filter(|(_, &c)| b == c).count()
                > self.netinfo.num_faulty()
        {
            self.decide(b);
        }
        Ok(())
    }

    /// Handles a Common Coin message. If there is output from Common Coin, starts the next
    /// epoch. The function may output a decision value.
    fn handle_coin(&mut self, sender_id: &NodeUid, msg: CommonCoinMessage) -> AgreementResult<()> {
        self.common_coin.handle_message(sender_id, msg)?;
        self.extend_common_coin();

        if let Some(coin) = self.common_coin.next_output() {
            let def_bin_value = self.count_conf().1.definite();
            self.on_coin(coin, def_bin_value)?;
        }

        Ok(())
    }

    /// When the common coin has been computed, tries to decide on an output value, updates the
    /// `Agreement` epoch and handles queued messages for the new epoch.
    fn on_coin(&mut self, coin: bool, def_bin_value: Option<bool>) -> AgreementResult<()> {
        let b = if let Some(b) = def_bin_value {
            // Outputting a value is allowed only once.
            if self.decision.is_none() && b == coin {
                self.decide(b);
            }
            b
        } else {
            coin
        };

        self.update_epoch();

        self.estimated = Some(b);
        self.send_bval(b)?;
        let queued_msgs = replace(&mut self.incoming_queue, Vec::new());
        for (sender_id, msg) in queued_msgs {
            self.handle_message(&sender_id, msg)?;
        }
        Ok(())
    }

    /// Computes the coin schedule for the current `Agreement` epoch.
    fn coin_schedule(&self) -> CoinSchedule {
        match self.epoch % 3 {
            0 => CoinSchedule::True,
            1 => CoinSchedule::False,
            _ => CoinSchedule::Random,
        }
    }

    /// Propagates Common Coin messages to the top level.
    fn extend_common_coin(&mut self) {
        let epoch = self.epoch;
        self.messages.extend(self.common_coin.message_iter().map(
            |msg: TargetedMessage<CommonCoinMessage, NodeUid>| {
                AgreementContent::Coin(Box::new(msg.message)).with_epoch(epoch)
            },
        ));
    }

    /// Decides on a value and broadcasts a `Term` message with that value.
    fn decide(&mut self, b: bool) {
        // Output the agreement value.
        self.output = Some(b);
        // Latch the decided state.
        self.decision = Some(b);
        if self.netinfo.is_peer() {
            self.messages
                .push_back(AgreementContent::Term(b).with_epoch(self.epoch));
            self.received_term.insert(self.netinfo.our_uid().clone(), b);
        }
        self.terminated = true;
        debug!(
            "Agreement instance {:?} decided: {}",
            self.netinfo.our_uid(),
            b
        );
    }

    fn try_finish_conf_round(&mut self) -> AgreementResult<()> {
        if self.conf_round {
            let (count_vals, _) = self.count_conf();
            if count_vals < self.netinfo.num_nodes() - self.netinfo.num_faulty() {
                // Continue waiting for (N - f) `Conf` messages
                return Ok(());
            }
            // Invoke the comon coin.
            self.common_coin.input(())?;
            self.extend_common_coin();
        }
        Ok(())
    }

    fn send_aux(&mut self, b: bool) -> AgreementResult<()> {
        if !self.netinfo.is_peer() {
            return Ok(());
        }
        // Multicast `Aux`.
        self.messages
            .push_back(AgreementContent::Aux(b).with_epoch(self.epoch));
        // Receive the `Aux` message locally.
        let our_uid = &self.netinfo.our_uid().clone();
        self.handle_aux(our_uid, b)
    }

    /// The count of `Aux` messages such that the set of values carried by those messages is a
    /// subset of bin_values_r. The count of matching `Term` messages from terminated nodes is also
    /// added to the count of `Aux` messages as witnesses of the terminated nodes' decision.
    ///
    /// In general, we can't expect every good node to send the same `Aux` value, so waiting for N -
    /// f agreeing messages would not always terminate. We can, however, expect every good node to
    /// send an `Aux` value that will eventually end up in our `bin_values`.
    fn count_aux(&self) -> (usize, BinValues) {
        let mut aux: BTreeMap<_, _> = self
            .received_aux
            .iter()
            .filter(|(_, &b)| self.bin_values.contains(b))
            .collect();

        let term: BTreeMap<_, _> = self
            .received_term
            .iter()
            .filter(|(_, &b)| self.bin_values.contains(b))
            .collect();

        // Ensure that nodes are not counted twice.
        aux.extend(term);
        let bin: BinValues = aux.values().map(|&&v| BinValues::from_bool(v)).collect();
        (aux.len(), bin)
    }

    /// Counts the number of received `Conf` messages.
    fn count_conf(&self) -> (usize, BinValues) {
        let (vals_cnt, vals) = self
            .received_conf
            .values()
            .filter(|&conf| conf.is_subset(self.bin_values))
            .tee();

        (vals_cnt.count(), vals.cloned().collect())
    }

    fn update_epoch(&mut self) {
        self.bin_values.clear();
        self.received_bval.clear();
        self.sent_bval.clear();
        self.received_aux.clear();
        self.received_conf.clear();
        self.conf_round = false;
        self.epoch += 1;
        let nonce = Nonce::new(
            self.netinfo.invocation_id().as_ref(),
            self.session_id,
            *self.netinfo.node_index(&self.proposer_id).unwrap(),
            self.epoch,
        );
        // TODO: Don't spend time creating a `CommonCoin` instance in epochs where the common coin
        // is known.
        self.common_coin = CommonCoin::new(self.netinfo.clone(), nonce);
        self.coin_schedule = self.coin_schedule();
        debug!(
            "{:?} Agreement instance {:?} started epoch {}",
            self.netinfo.our_uid(),
            self.proposer_id,
            self.epoch
        );
    }
}

#[derive(Clone)]
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
