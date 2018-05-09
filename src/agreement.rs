//! Binary Byzantine agreement protocol from a common coin protocol.

use rand::random;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::hash::Hash;

use proto::message;

type AgreementOutput = (Option<bool>, VecDeque<AgreementMessage>);

/// Messages sent during the binary Byzantine agreement stage.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgreementMessage {
    /// BVAL message with an epoch.
    BVal((u32, bool)),
    /// AUX message with an epoch.
    Aux((u32, bool)),
}

impl AgreementMessage {
    pub fn into_proto(self) -> message::AgreementProto {
        let mut p = message::AgreementProto::new();
        match self {
            AgreementMessage::BVal((e, b)) => {
                p.set_epoch(e);
                p.set_bval(b);
            }
            AgreementMessage::Aux((e, b)) => {
                p.set_epoch(e);
                p.set_aux(b);
            }
        }
        p
    }

    // TODO: Re-enable lint once implemented.
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn from_proto(mp: message::AgreementProto) -> Option<Self> {
        let epoch = mp.get_epoch();
        if mp.has_bval() {
            Some(AgreementMessage::BVal((epoch, mp.get_bval())))
        } else if mp.has_aux() {
            Some(AgreementMessage::Aux((epoch, mp.get_aux())))
        } else {
            None
        }
    }
}

pub struct Agreement<NodeUid> {
    /// The UID of the corresponding proposer node.
    uid: NodeUid,
    num_nodes: usize,
    num_faulty_nodes: usize,
    epoch: u32,
    input: Option<bool>,
    /// Bin values. Reset on every epoch update.
    bin_values: BTreeSet<bool>,
    /// Values received in BVAL messages. Reset on every epoch update.
    received_bval: HashMap<NodeUid, BTreeSet<bool>>,
    /// Sent BVAL values. Reset on every epoch update.
    sent_bval: BTreeSet<bool>,
    /// Values received in AUX messages. Reset on every epoch update.
    received_aux: HashMap<NodeUid, BTreeSet<bool>>,
    /// All the output values in all epochs.
    estimated: BTreeMap<u32, bool>,
    /// Termination flag.
    terminated: bool,
}

impl<NodeUid: Clone + Eq + Hash> Agreement<NodeUid> {
    pub fn new(uid: NodeUid, num_nodes: usize) -> Self {
        let num_faulty_nodes = (num_nodes - 1) / 3;

        Agreement {
            uid,
            num_nodes,
            num_faulty_nodes,
            epoch: 0,
            input: None,
            bin_values: BTreeSet::new(),
            received_bval: HashMap::new(),
            sent_bval: BTreeSet::new(),
            received_aux: HashMap::new(),
            estimated: BTreeMap::new(),
            terminated: false,
        }
    }

    /// Algorithm has terminated.
    pub fn terminated(&self) -> bool {
        self.terminated
    }

    pub fn set_input(&mut self, input: bool) -> AgreementMessage {
        self.input = Some(input);
        // Receive the BVAL message locally.
        self.received_bval
            .entry(self.uid.clone())
            .or_insert_with(BTreeSet::new)
            .insert(input);
        // Multicast BVAL
        AgreementMessage::BVal((self.epoch, input))
    }

    pub fn has_input(&self) -> bool {
        self.input.is_some()
    }

    /// Receive input from a remote node.
    ///
    /// Outputs an optional agreement result and a queue of agreement messages
    /// to remote nodes. There can be up to 2 messages.
    pub fn on_input(
        &mut self,
        sender_id: NodeUid,
        message: &AgreementMessage,
    ) -> Result<AgreementOutput, Error> {
        match *message {
            // The algorithm instance has already terminated.
            _ if self.terminated => Err(Error::Terminated),

            AgreementMessage::BVal((epoch, b)) if epoch == self.epoch => self.on_bval(sender_id, b),

            AgreementMessage::Aux((epoch, b)) if epoch == self.epoch => self.on_aux(sender_id, b),

            // Epoch does not match. Ignore the message.
            _ => Ok((None, VecDeque::new())),
        }
    }

    fn on_bval(&mut self, sender_id: NodeUid, b: bool) -> Result<AgreementOutput, Error> {
        let mut outgoing = VecDeque::new();

        self.received_bval
            .entry(sender_id)
            .or_insert_with(BTreeSet::new)
            .insert(b);
        let count_bval = self.received_bval
            .values()
            .filter(|values| values.contains(&b))
            .count();

        // upon receiving BVAL_r(b) messages from 2f + 1 nodes,
        // bin_values_r := bin_values_r ∪ {b}
        if count_bval == 2 * self.num_faulty_nodes + 1 {
            self.bin_values.insert(b);

            // wait until bin_values_r != 0, then multicast AUX_r(w)
            // where w ∈ bin_values_r
            if self.bin_values.len() == 1 {
                // Send an AUX message at most once per epoch.
                outgoing.push_back(AgreementMessage::Aux((self.epoch, b)));
                // Receive the AUX message locally.
                self.received_aux
                    .entry(self.uid.clone())
                    .or_insert_with(BTreeSet::new)
                    .insert(b);
            }

            let coin_result = self.try_coin();
            if let Some(output_message) = coin_result.1 {
                outgoing.push_back(output_message);
            }
            Ok((coin_result.0, outgoing))
        }
        // upon receiving BVAL_r(b) messages from f + 1 nodes, if
        // BVAL_r(b) has not been sent, multicast BVAL_r(b)
        else if count_bval == self.num_faulty_nodes + 1 && !self.sent_bval.contains(&b) {
            outgoing.push_back(AgreementMessage::BVal((self.epoch, b)));
            // Receive the BVAL message locally.
            self.received_bval
                .entry(self.uid.clone())
                .or_insert_with(BTreeSet::new)
                .insert(b);
            Ok((None, outgoing))
        } else {
            Ok((None, outgoing))
        }
    }

    fn on_aux(&mut self, sender_id: NodeUid, b: bool) -> Result<AgreementOutput, Error> {
        let mut outgoing = VecDeque::new();

        self.received_aux
            .entry(sender_id)
            .or_insert_with(BTreeSet::new)
            .insert(b);
        if !self.bin_values.is_empty() {
            let coin_result = self.try_coin();
            if let Some(output_message) = coin_result.1 {
                outgoing.push_back(output_message);
            }
            Ok((coin_result.0, outgoing))
        } else {
            Ok((None, outgoing))
        }
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
        let vals = BTreeSet::new();
        (
            self.received_aux
                .values()
                .filter(|values| values.is_subset(&self.bin_values))
                .map(|values| vals.union(values))
                .count(),
            vals,
        )
    }

    /// Waits until at least (N − f) AUX_r messages have been received, such that
    /// the set of values carried by these messages, vals, are a subset of
    /// bin_values_r (note that bin_values_r may continue to change as BVAL_r
    /// messages are received, thus this condition may be triggered upon arrival
    /// of either an AUX_r or a BVAL_r message).
    ///
    /// `try_coin` outputs an optional combination of the agreement value and
    /// the agreement broadcast message.
    fn try_coin(&mut self) -> (Option<bool>, Option<AgreementMessage>) {
        let (count_aux, vals) = self.count_aux();
        if count_aux < self.num_nodes - self.num_faulty_nodes {
            // Continue waiting for the (N - f) AUX messages.
            (None, None)
        } else {
            // FIXME: Implement the Common Coin algorithm. At the moment the
            // coin value is random and local to each instance of Agreement.
            let coin2 = random::<bool>();

            // Check the termination condition: "continue looping until both a
            // value b is output in some round r, and the value Coin_r' = b for
            // some round r' > r."
            self.terminated = self.terminated || self.estimated.values().any(|b| *b == coin2);

            // Prepare to start the next epoch.
            self.bin_values.clear();

            if vals.len() != 1 {
                // Start the next epoch.
                self.epoch += 1;
                (None, Some(self.set_input(coin2)))
            } else {
                let mut message = None;
                // NOTE: `vals` has exactly one element due to `vals.len() == 1`
                let output: Vec<Option<bool>> = vals.into_iter()
                    .take(1)
                    .map(|b| {
                        message = Some(self.set_input(b));

                        if b == coin2 {
                            // Record the output to perform a termination check later.
                            self.estimated.insert(self.epoch, b);
                            // Output the agreement value.
                            Some(b)
                        } else {
                            // Don't output a value.
                            None
                        }
                    })
                    .collect();
                // Start the next epoch.
                self.epoch += 1;
                (output[0], message)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum Error {
    Terminated,
    NotImplemented,
}
