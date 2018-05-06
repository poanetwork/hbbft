//! Binary Byzantine agreement protocol from a common coin protocol.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::hash::Hash;

use proto::AgreementMessage;

pub struct Agreement<NodeUid> {
    /// The UID of the corresponding node.
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
    outputs: BTreeMap<u32, bool>,
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
            outputs: BTreeMap::new(),
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
        update_map_of_sets(&mut self.received_bval, self.uid.clone(), input);
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
        uid: NodeUid,
        message: &AgreementMessage,
    ) -> Result<(Option<bool>, VecDeque<AgreementMessage>), Error> {
        let mut outgoing = VecDeque::new();

        match *message {
            AgreementMessage::BVal((epoch, b)) if epoch == self.epoch => {
                update_map_of_sets(&mut self.received_bval, uid, b);
                let count_bval = self.received_bval.iter().fold(0, |count, (_, values)| {
                    if values.contains(&b) {
                        count + 1
                    } else {
                        count
                    }
                });

                // upon receiving BVAL_r(b) messages from 2f + 1 nodes,
                // bin_values_r := bin_values_r ∪ {b}
                if count_bval == 2 * self.num_faulty_nodes + 1 {
                    self.bin_values.insert(b);

                    // wait until bin_values_r /= 0, then multicast AUX_r(w)
                    // where w ∈ bin_values_r
                    outgoing.push_back(AgreementMessage::Aux((self.epoch, b)));
                    // Receive the AUX message locally.
                    update_map_of_sets(&mut self.received_aux, self.uid.clone(), b);

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
                    update_map_of_sets(&mut self.received_bval, self.uid.clone(), b);
                    Ok((None, outgoing))
                } else {
                    Ok((None, outgoing))
                }
            }

            AgreementMessage::Aux((_epoch, b)) => {
                update_map_of_sets(&mut self.received_aux, uid, b);
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

            _ => {
                // Epoch does not match. Ignore the message.
                Ok((None, outgoing))
            }
        }
    }

    /// AUX_r messages such that the set of values carried by those messages is
    /// a subset of bin_values_r. Outputs this subset.
    ///
    /// FIXME: Clarify whether the values of AUX messages should be the same or
    /// not. It is assumed in `count_aux` that they can differ.
    fn count_aux(&self) -> (usize, BTreeSet<bool>) {
        let vals = BTreeSet::new();
        (
            self.received_aux.iter().fold(0, |count, (_, values)| {
                if values.is_subset(&self.bin_values) {
                    vals.union(values);
                    count + 1
                } else {
                    count
                }
            }),
            vals,
        )
    }

    /// Wait until at least (N − f) AUX_r messages have been received, such that
    /// the set of values carried by these messages, vals, are a subset of
    /// bin_values_r (note that bin_values_r may continue to change as BVAL_r
    /// messages are received, thus this condition may be triggered upon arrival
    /// of either an AUX_r or a BVAL_r message).
    ///
    /// `try_coin` output an optional combination of the agreement value and the
    /// agreement broadcast message.
    fn try_coin(&mut self) -> (Option<bool>, Option<AgreementMessage>) {
        let (count_aux, vals) = self.count_aux();
        if count_aux >= self.num_nodes - self.num_faulty_nodes {
            // FIXME: Implement the Common Coin algorithm. At the moment the
            // coin value is constant `true`.
            let coin: u64 = 1;

            let coin2 = coin % 2 != 0;

            // Check the termination condition: "continue looping until both a
            // value b is output in some round r, and the value Coin_r' = b for
            // some round r' > r."
            self.terminated = self.terminated || self.outputs.values().any(|b| *b == coin2);

            // Prepare to start the next epoch.
            self.bin_values.clear();

            if vals.len() == 1 {
                let mut message = None;
                // NOTE: `vals` has exactly one element due to `vals.len() == 1`
                let output: Vec<Option<bool>> = vals.into_iter()
                    .take(1)
                    .map(|b| {
                        message = Some(self.set_input(b));

                        if b == coin2 {
                            // Record the output to perform a termination check later.
                            self.outputs.insert(self.epoch, b);
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
            } else {
                // Start the next epoch.
                self.epoch += 1;
                (None, Some(self.set_input(coin2)))
            }
        } else {
            // Continue waiting for the (N - f) AUX messages.
            (None, None)
        }
    }
}

// Insert an element into a hash map of sets of values of type `Elt`.
fn update_map_of_sets<Key, Elt>(map: &mut HashMap<Key, BTreeSet<Elt>>, key: Key, elt: Elt)
where
    Key: Eq + Hash,
    Elt: Copy + Ord,
{
    map.entry(key)
        .and_modify(|values| {
            values.insert(elt);
        })
        .or_insert({
            let mut values = BTreeSet::new();
            values.insert(elt);
            values
        });
}

#[derive(Clone, Debug)]
pub enum Error {
    NotImplemented,
}
