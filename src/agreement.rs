//! Binary Byzantine agreement protocol from a common coin protocol.

use itertools::Itertools;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

use messaging::{DistAlgorithm, Target, TargetedMessage};

/// Messages sent during the binary Byzantine agreement stage.
#[cfg_attr(feature = "serialization-serde", derive(Serialize))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgreementMessage {
    /// BVAL message with an epoch.
    BVal(u32, bool),
    /// AUX message with an epoch.
    Aux(u32, bool),
}

/// Binary Agreement instance
pub struct Agreement<NodeUid> {
    /// The UID of the corresponding proposer node.
    uid: NodeUid,
    num_nodes: usize,
    num_faulty_nodes: usize,
    epoch: u32,
    /// Bin values. Reset on every epoch update.
    bin_values: BTreeSet<bool>,
    /// Values received in BVAL messages. Reset on every epoch update.
    received_bval: HashMap<NodeUid, BTreeSet<bool>>,
    /// Sent BVAL values. Reset on every epoch update.
    sent_bval: BTreeSet<bool>,
    /// Values received in AUX messages. Reset on every epoch update.
    received_aux: HashMap<NodeUid, bool>,
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
    /// Termination flag. The Agreement instance doesn't terminate immediately
    /// upon deciding on the agreed value. This is done in order to help other
    /// nodes decide despite asynchrony of communication. Once the instance
    /// determines that all the remote nodes have reached agreement, it sets the
    /// `terminated` flag and accepts no more incoming messages.
    terminated: bool,
    /// The outgoing message queue.
    messages: VecDeque<AgreementMessage>,
}

impl<NodeUid: Clone + Debug + Eq + Hash + Ord> DistAlgorithm for Agreement<NodeUid> {
    type NodeUid = NodeUid;
    type Input = bool;
    type Output = bool;
    type Message = AgreementMessage;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        self.set_input(input)
    }

    /// Receive input from a remote node.
    fn handle_message(
        &mut self,
        sender_id: &Self::NodeUid,
        message: Self::Message,
    ) -> Result<(), Self::Error> {
        match message {
            // The algorithm instance has already terminated.
            _ if self.terminated => Err(Error::Terminated),

            AgreementMessage::BVal(epoch, b) if epoch == self.epoch => {
                self.handle_bval(sender_id, b)
            }

            AgreementMessage::Aux(epoch, b) if epoch == self.epoch => self.handle_aux(sender_id, b),

            // Epoch does not match. Ignore the message.
            _ => Ok(()),
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

impl<NodeUid: Clone + Debug + Eq + Hash> Agreement<NodeUid> {
    pub fn new(uid: NodeUid, num_nodes: usize) -> Self {
        let num_faulty_nodes = (num_nodes - 1) / 3;

        Agreement {
            uid,
            num_nodes,
            num_faulty_nodes,
            epoch: 0,
            bin_values: BTreeSet::new(),
            received_bval: HashMap::new(),
            sent_bval: BTreeSet::new(),
            received_aux: HashMap::new(),
            estimated: None,
            output: None,
            decision: None,
            terminated: false,
            messages: VecDeque::new(),
        }
    }

    /// Sets the input value for agreement.
    pub fn set_input(&mut self, input: bool) -> Result<(), Error> {
        if self.epoch != 0 || self.estimated.is_some() {
            return Err(Error::InputNotAccepted);
        }

        // Set the initial estimated value to the input value.
        self.estimated = Some(input);
        // Record the input value as sent.
        self.sent_bval.insert(input);
        // Receive the BVAL message locally.
        self.received_bval
            .entry(self.uid.clone())
            .or_insert_with(BTreeSet::new)
            .insert(input);
        // Multicast BVAL
        self.messages
            .push_back(AgreementMessage::BVal(self.epoch, input));
        Ok(())
    }

    /// Acceptance check to be performed before setting the input value.
    pub fn accepts_input(&self) -> bool {
        self.epoch == 0 && self.estimated.is_none()
    }

    fn handle_bval(&mut self, sender_id: &NodeUid, b: bool) -> Result<(), Error> {
        self.received_bval
            .entry(sender_id.clone())
            .or_insert_with(BTreeSet::new)
            .insert(b);
        let count_bval = self.received_bval
            .values()
            .filter(|values| values.contains(&b))
            .count();

        // upon receiving BVAL_r(b) messages from 2f + 1 nodes,
        // bin_values_r := bin_values_r ∪ {b}
        if count_bval == 2 * self.num_faulty_nodes + 1 {
            let bin_values_was_empty = self.bin_values.is_empty();
            self.bin_values.insert(b);

            // wait until bin_values_r != 0, then multicast AUX_r(w)
            // where w ∈ bin_values_r
            if bin_values_was_empty {
                // Send an AUX message at most once per epoch.
                self.messages
                    .push_back(AgreementMessage::Aux(self.epoch, b));
                // Receive the AUX message locally.
                self.received_aux.insert(self.uid.clone(), b);
            }

            self.try_coin();
        }
        // upon receiving BVAL_r(b) messages from f + 1 nodes, if
        // BVAL_r(b) has not been sent, multicast BVAL_r(b)
        else if count_bval == self.num_faulty_nodes + 1 && !self.sent_bval.contains(&b) {
            // Record the value `b` as sent.
            self.sent_bval.insert(b);
            // Receive the BVAL message locally.
            self.received_bval
                .entry(self.uid.clone())
                .or_insert_with(BTreeSet::new)
                .insert(b);
            // Multicast BVAL.
            self.messages
                .push_back(AgreementMessage::BVal(self.epoch, b));
        }
        Ok(())
    }

    fn handle_aux(&mut self, sender_id: &NodeUid, b: bool) -> Result<(), Error> {
        self.received_aux.insert(sender_id.clone(), b);
        if !self.bin_values.is_empty() {
            self.try_coin();
        }
        Ok(())
    }

    /// AUX_r messages such that the set of values carried by those messages is
    /// a subset of bin_values_r. Outputs this subset.
    ///
    /// FIXME: Clarify whether the values of AUX messages should be the same or
    /// not. It is assumed in `count_aux` that they can differ.
    ///
    /// In general, we can't expect every good node to send the same AUX value,
    /// so waiting for N - f agreeing messages would not always terminate. We
    /// can, however, expect every good node to send an AUX value that will
    /// eventually end up in our bin_values.
    fn count_aux(&self) -> (usize, BTreeSet<bool>) {
        let (vals_cnt, vals) = self.received_aux
            .values()
            .filter(|b| self.bin_values.contains(b))
            .tee();

        (vals_cnt.count(), vals.cloned().collect())
    }

    /// Waits until at least (N − f) AUX_r messages have been received, such that
    /// the set of values carried by these messages, vals, are a subset of
    /// bin_values_r (note that bin_values_r may continue to change as BVAL_r
    /// messages are received, thus this condition may be triggered upon arrival
    /// of either an AUX_r or a BVAL_r message).
    ///
    /// Once the (N - f) messages are received, gets a common coin and uses it
    /// to compute the next decision estimate and outputs the optional decision
    /// value.  The function may start the next epoch. In that case, it also
    /// returns a message for broadcast.
    fn try_coin(&mut self) {
        let (count_aux, vals) = self.count_aux();
        if count_aux < self.num_nodes - self.num_faulty_nodes {
            // Continue waiting for the (N - f) AUX messages.
            return;
        }

        debug!("{:?} try_coin in epoch {}", self.uid, self.epoch);
        // FIXME: Implement the Common Coin algorithm. At the moment the
        // coin value is common across different nodes but not random.
        let coin = (self.epoch % 2) == 0;

        // Check the termination condition: "continue looping until both a
        // value b is output in some round r, and the value Coin_r' = b for
        // some round r' > r."
        self.terminated = self.terminated || self.decision == Some(coin);
        if self.terminated {
            debug!("Agreement instance {:?} terminated", self.uid);
        }

        // Start the next epoch.
        self.bin_values.clear();
        self.received_bval.clear();
        self.sent_bval.clear();
        self.received_aux.clear();
        self.epoch += 1;
        debug!(
            "Agreement instance {:?} started epoch {}",
            self.uid, self.epoch
        );

        let decision = if vals.len() != 1 {
            self.estimated = Some(coin);
            None
        } else {
            // NOTE: `vals` has exactly one element due to `vals.len() == 1`
            let v: Vec<bool> = vals.into_iter().collect();
            let b = v[0];
            self.estimated = Some(b);
            // Outputting a value is allowed only once.
            if self.output.is_none() && b == coin {
                // Output the agreement value.
                self.output = Some(b);
                debug!("Agreement instance {:?} output: {}", self.uid, b);
                self.output
            } else {
                None
            }
        };

        let b = self.estimated.unwrap();
        self.sent_bval.insert(b);
        self.messages
            .push_back(AgreementMessage::BVal(self.epoch, b));
        self.output = decision;
        // Latch the decided state.
        if decision.is_some() {
            self.decision = decision;
        }
    }
}

#[derive(Clone, Debug)]
pub enum Error {
    Terminated,
    InputNotAccepted,
}
