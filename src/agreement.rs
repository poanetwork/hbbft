//! Binary Byzantine agreement protocol from a common coin protocol.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::mem::replace;

use messaging::{DistAlgorithm, Target, TargetedMessage};

error_chain!{
    types {
        Error, ErrorKind, ResultExt, AgreementResult;
    }

    errors {
        InputNotAccepted
        Terminated
    }
}

/// A lattice-valued description of the state of `bin_values`.
#[cfg_attr(feature = "serialization-serde", derive(Serialize))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BinValues {
    None,
    False,
    True,
    Both,
}

impl BinValues {
    pub fn new() -> Self {
        BinValues::None
    }

    pub fn clear(&mut self) {
        replace(self, BinValues::None);
    }

    fn single(b: bool) -> Self {
        if b {
            BinValues::True
        } else {
            BinValues::False
        }
    }

    /// Inserts a boolean value into the `BinValues` and returns true iff the `BinValues` has
    /// changed as a result.
    pub fn insert(&mut self, b: bool) -> bool {
        match self {
            BinValues::None => {
                replace(self, BinValues::single(b));
                true
            }
            BinValues::False if b => {
                replace(self, BinValues::Both);
                true
            }
            BinValues::True if !b => {
                replace(self, BinValues::Both);
                true
            }
            _ => false,
        }
    }

    pub fn contains(&self, b: bool) -> bool {
        match self {
            BinValues::None => false,
            BinValues::Both => true,
            BinValues::False if !b => true,
            BinValues::True if b => true,
            _ => false,
        }
    }

    pub fn is_subset(&self, other: &BinValues) -> bool {
        match self {
            BinValues::None => true,
            BinValues::False if *other == BinValues::False || *other == BinValues::Both => true,
            BinValues::True if *other == BinValues::True || *other == BinValues::Both => true,
            BinValues::Both if *other == BinValues::Both => true,
            _ => false,
        }
    }

    pub fn definite(&self) -> Option<bool> {
        match self {
            BinValues::False => Some(false),
            BinValues::True => Some(true),
            _ => None,
        }
    }
}

/// Messages sent during the binary Byzantine agreement stage.
#[cfg_attr(feature = "serialization-serde", derive(Serialize))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgreementMessage {
    /// BVAL message with an epoch.
    BVal(u32, bool),
    /// AUX message with an epoch.
    Aux(u32, bool),
    /// CONF message with an epoch.
    Conf(u32, BinValues),
}

impl AgreementMessage {
    fn epoch(&self) -> u32 {
        match *self {
            AgreementMessage::BVal(epoch, _) => epoch,
            AgreementMessage::Aux(epoch, _) => epoch,
            AgreementMessage::Conf(epoch, _) => epoch,
        }
    }
}

/// Binary Agreement instance
pub struct Agreement<NodeUid> {
    /// This node's ID.
    uid: NodeUid,
    num_nodes: usize,
    num_faulty_nodes: usize,
    epoch: u32,
    /// Bin values. Reset on every epoch update.
    bin_values: BinValues,
    /// Values received in BVAL messages. Reset on every epoch update.
    received_bval: BTreeMap<NodeUid, BTreeSet<bool>>,
    /// Sent BVAL values. Reset on every epoch update.
    sent_bval: BTreeSet<bool>,
    /// Values received in AUX messages. Reset on every epoch update.
    received_aux: BTreeMap<NodeUid, bool>,
    /// Received CONF messages. Reset on every epoch update.
    received_conf: BTreeMap<NodeUid, BinValues>,
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
    /// Whether the CONF message round has been started in the current epoch.
    conf_sent: bool,
}

impl<NodeUid: Clone + Debug + Eq + Hash + Ord> DistAlgorithm for Agreement<NodeUid> {
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
        if self.terminated {
            return Err(ErrorKind::Terminated.into());
        }
        if message.epoch() < self.epoch {
            return Ok(()); // Message is obsolete: We are already in a later epoch.
        }
        if message.epoch() > self.epoch {
            // Message is for a later epoch. We can't handle that yet.
            self.incoming_queue.push((sender_id.clone(), message));
            return Ok(());
        }
        match message {
            AgreementMessage::BVal(_, b) => self.handle_bval(sender_id, b),
            AgreementMessage::Aux(_, b) => self.handle_aux(sender_id, b),
            AgreementMessage::Conf(_, v) => self.handle_conf(sender_id, v),
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
        &self.uid
    }
}

impl<NodeUid: Clone + Debug + Eq + Hash + Ord> Agreement<NodeUid> {
    pub fn new(uid: NodeUid, num_nodes: usize) -> Self {
        let num_faulty_nodes = (num_nodes - 1) / 3;

        Agreement {
            uid,
            num_nodes,
            num_faulty_nodes,
            epoch: 0,
            bin_values: BinValues::new(),
            received_bval: BTreeMap::new(),
            sent_bval: BTreeSet::new(),
            received_aux: BTreeMap::new(),
            received_conf: BTreeMap::new(),
            estimated: None,
            output: None,
            decision: None,
            incoming_queue: Vec::new(),
            terminated: false,
            messages: VecDeque::new(),
            conf_sent: false,
        }
    }

    /// Sets the input value for agreement.
    pub fn set_input(&mut self, input: bool) -> AgreementResult<()> {
        if self.epoch != 0 || self.estimated.is_some() {
            return Err(ErrorKind::InputNotAccepted.into());
        }
        if self.num_nodes == 1 {
            self.decision = Some(input);
            self.output = Some(input);
            self.terminated = true;
        }

        // Set the initial estimated value to the input value.
        self.estimated = Some(input);
        // Record the input value as sent.
        self.send_bval(input)
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

        // upon receiving BVAL_r(b) messages from 2f + 1 nodes,
        // bin_values_r := bin_values_r ∪ {b}
        if count_bval == 2 * self.num_faulty_nodes + 1 {
            let previous_bin_values = self.bin_values.clone();
            let bin_values_changed = self.bin_values.insert(b);

            // wait until bin_values_r != 0, then multicast AUX_r(w)
            // where w ∈ bin_values_r
            if previous_bin_values == BinValues::None {
                // Send an AUX message at most once per epoch.
                self.send_aux(b)
            } else if self.conf_sent
                && bin_values_changed
                && self.count_conf() >= self.num_nodes - self.num_faulty_nodes
            {
                // Respond to a change in `bin_values` from the CONF round. Since BVAL messages
                // continue getting handled during the CONF round and `bin_values` is still allowed
                // to change, the value of `count_conf` may increase at this point. The COIN subalgo
                // has to be invoked without waiting for another CONF message to trigger it.
                self.invoke_coin()
            } else {
                Ok(())
            }
        } else if count_bval == self.num_faulty_nodes + 1 && !self.sent_bval.contains(&b) {
            // upon receiving BVAL_r(b) messages from f + 1 nodes, if
            // BVAL_r(b) has not been sent, multicast BVAL_r(b)
            self.send_bval(b)
        } else {
            Ok(())
        }
    }

    fn send_bval(&mut self, b: bool) -> AgreementResult<()> {
        // Record the value `b` as sent.
        self.sent_bval.insert(b);
        // Multicast BVAL.
        self.messages
            .push_back(AgreementMessage::BVal(self.epoch, b));
        // Receive the BVAL message locally.
        let our_uid = self.uid.clone();
        self.handle_bval(&our_uid, b)
    }

    fn send_conf(&mut self) -> AgreementResult<()> {
        if self.conf_sent {
            // Only one CONF message is allowed in an epoch.
            return Ok(());
        }

        // Trigger the start of the CONF round.
        self.conf_sent = true;
        let v = &self.bin_values.clone();
        // Multicast CONF.
        self.messages
            .push_back(AgreementMessage::Conf(self.epoch, v.clone()));
        // Receive the CONF message locally.
        let our_uid = self.uid.clone();
        self.handle_conf(&our_uid, v.clone())
    }

    /// Waits until at least (N − f) AUX_r messages have been received, such that
    /// the set of values carried by these messages, vals, are a subset of
    /// bin_values_r (note that bin_values_r may continue to change as BVAL_r
    /// messages are received, thus this condition may be triggered upon arrival
    /// of either an AUX_r or a BVAL_r message).
    fn handle_aux(&mut self, sender_id: &NodeUid, b: bool) -> AgreementResult<()> {
        // Perform the AUX message round only if a CONF round hasn't started yet.
        if self.conf_sent {
            return Ok(());
        }
        self.received_aux.insert(sender_id.clone(), b);
        if self.bin_values == BinValues::None {
            return Ok(());
        }
        if self.count_aux() < self.num_nodes - self.num_faulty_nodes {
            // Continue waiting for the (N - f) AUX messages.
            return Ok(());
        }
        // Start the CONF message round.
        self.send_conf()
    }

    fn handle_conf(&mut self, sender_id: &NodeUid, v: BinValues) -> AgreementResult<()> {
        self.received_conf.insert(sender_id.clone(), v);
        if !self.conf_sent {
            return Ok(());
        }
        if self.count_conf() < self.num_nodes - self.num_faulty_nodes {
            // Continue waiting for (N - f) CONF messages
            return Ok(());
        }
        self.invoke_coin()
    }

    fn send_aux(&mut self, b: bool) -> AgreementResult<()> {
        // Multicast AUX.
        self.messages
            .push_back(AgreementMessage::Aux(self.epoch, b));
        // Receive the AUX message locally.
        let our_uid = self.uid.clone();
        self.handle_aux(&our_uid, b)
    }

    /// The count of AUX_r messages such that the set of values carried by those messages is a
    /// subset of bin_values_r. Outputs this subset.
    ///
    /// FIXME: Clarify whether the values of AUX messages should be the same or
    /// not. It is assumed in `count_aux` that they can differ.
    ///
    /// In general, we can't expect every good node to send the same AUX value,
    /// so waiting for N - f agreeing messages would not always terminate. We
    /// can, however, expect every good node to send an AUX value that will
    /// eventually end up in our bin_values.
    fn count_aux(&self) -> usize {
        self.received_aux
            .values()
            .filter(|&&b| self.bin_values.contains(b))
            .count()
    }

    /// Counts the number of received CONF messages.
    fn count_conf(&self) -> usize {
        self.received_conf
            .values()
            .filter(|&conf| conf.is_subset(&self.bin_values))
            .count()
    }

    fn start_next_epoch(&mut self) {
        self.bin_values.clear();
        self.received_bval.clear();
        self.sent_bval.clear();
        self.received_aux.clear();
        self.received_conf.clear();
        self.conf_sent = false;
        self.epoch += 1;
    }

    /// Gets a common coin and uses it to compute the next decision estimate and outputs the
    /// optional decision value.  The function may start the next epoch. In that case, it also
    /// returns a message for broadcast.
    fn invoke_coin(&mut self) -> AgreementResult<()> {
        debug!("{:?} invoke_coin in epoch {}", self.uid, self.epoch);
        // FIXME: Implement the Common Coin algorithm. At the moment the
        // coin value is common across different nodes but not random.
        let coin = (self.epoch % 2) == 0;

        // Check the termination condition: "continue looping until both a
        // value b is output in some round r, and the value Coin_r' = b for
        // some round r' > r."
        self.terminated = self.terminated || self.decision == Some(coin);
        if self.terminated {
            debug!("Agreement instance {:?} terminated", self.uid);
            return Ok(());
        }

        self.start_next_epoch();
        debug!(
            "Agreement instance {:?} started epoch {}",
            self.uid, self.epoch
        );

        if let Some(b) = self.bin_values.definite() {
            self.estimated = Some(b);
            // Outputting a value is allowed only once.
            if self.decision.is_none() && b == coin {
                // Output the agreement value.
                self.output = Some(b);
                // Latch the decided state.
                self.decision = Some(b);
                debug!("Agreement instance {:?} output: {}", self.uid, b);
            }
        } else {
            self.estimated = Some(coin);
        }

        let b = self.estimated.unwrap();
        self.send_bval(b)?;
        let queued_msgs = replace(&mut self.incoming_queue, Vec::new());
        for (sender_id, msg) in queued_msgs {
            self.handle_message(&sender_id, msg)?;
        }
        Ok(())
    }
}
