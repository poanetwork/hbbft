//! # Synchronized Binary Value Broadcast
//!
//! This performs the `BVal` and `Aux` steps for `BinaryAgreement`.
//!
//! Validators input binary values, and each node outputs a set of one or two binary values.
//! These outputs are not necessarily the same in each node, but it is guaranteed that whenever two
//! nodes output singletons _{v}_ and _{w}_, then _v = w_.
//!
//! It will only output once, but can continue handling messages and will keep track of the set
//! `bin_values` of values for which _2 f + 1_ `BVal`s were received.

use std::sync::Arc;

use rand::distributions::{Distribution, Standard};
use rand::{seq::SliceRandom, Rng};
use serde_derive::{Deserialize, Serialize};

use super::bool_multimap::BoolMultimap;
use super::bool_set::{self, BoolSet};
use super::{FaultKind, Result};
use crate::fault_log::Fault;
use crate::{NetworkInfo, NodeIdT, Target};

pub type Step<N> = crate::Step<Message, BoolSet, N, FaultKind>;

/// A message belonging to the Synchronized Binary Value Broadcast phase of a `BinaryAgreement`
/// epoch.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum Message {
    /// Contains the sender's estimate for the current epoch.
    BVal(bool),
    /// A confirmation that the sender has received _2 f + 1_ `BVal`s with the same value.
    Aux(bool),
}

// NOTE: Extending rand_derive to correctly generate random values from boxes would make this
// implementation obsolete; however at the time of this writing, `rand_derive` is already deprecated
// with no replacement in sight.
impl Distribution<Message> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Message {
        let message_type = *["bval", "aux"].choose(rng).unwrap();

        match message_type {
            "bval" => Message::BVal(rng.gen()),
            "aux" => Message::Aux(rng.gen()),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub struct SbvBroadcast<N> {
    /// Shared network information.
    netinfo: Arc<NetworkInfo<N>>,
    /// The set of values for which _2 f + 1_ `BVal`s have been received.
    bin_values: BoolSet,
    /// The nodes that sent us a `BVal(b)`, by `b`.
    received_bval: BoolMultimap<N>,
    /// The values `b` for which we already sent `BVal(b)`.
    sent_bval: BoolSet,
    /// The nodes that sent us an `Aux(b)`, by `b`.
    received_aux: BoolMultimap<N>,
    /// Whether we have already output.
    terminated: bool,
}

impl<N: NodeIdT> SbvBroadcast<N> {
    pub fn new(netinfo: Arc<NetworkInfo<N>>) -> Self {
        SbvBroadcast {
            netinfo,
            bin_values: bool_set::NONE,
            received_bval: BoolMultimap::default(),
            sent_bval: bool_set::NONE,
            received_aux: BoolMultimap::default(),
            terminated: false,
        }
    }

    /// Resets the algorithm, but assumes the given `init` values have already been received as
    /// both `BVal` and `Aux` messages.
    pub fn clear(&mut self, init: &BoolMultimap<N>) {
        self.bin_values = bool_set::NONE;
        self.received_bval = init.clone();
        self.sent_bval = bool_set::NONE;
        self.received_aux = init.clone();
        self.terminated = false;
    }

    pub fn handle_message(&mut self, sender_id: &N, msg: &Message) -> Result<Step<N>> {
        match msg {
            Message::BVal(b) => self.handle_bval(sender_id, *b),
            Message::Aux(b) => self.handle_aux(sender_id, *b),
        }
    }

    /// Returns the current `bin_values`: the set of `b` for which _2 f + 1_ `BVal`s were received.
    pub fn bin_values(&self) -> BoolSet {
        self.bin_values
    }

    /// Multicasts a `BVal(b)` message, and handles it.
    pub fn send_bval(&mut self, b: bool) -> Result<Step<N>> {
        // Record the value `b` as sent. If it was already there, don't send it again.
        if !self.sent_bval.insert(b) {
            return Ok(Step::default());
        }
        self.send(&Message::BVal(b))
    }

    /// Handles a `BVal(b)` message.
    ///
    /// Upon receiving _f + 1_ `BVal(b)`, multicasts `BVal(b)`. Upon receiving _2 f + 1_ `BVal(b)`,
    /// updates `bin_values`. When `bin_values` gets its first entry, multicasts `Aux(b)`.
    pub fn handle_bval(&mut self, sender_id: &N, b: bool) -> Result<Step<N>> {
        let count_bval = {
            if !self.received_bval[b].insert(sender_id.clone()) {
                return Ok(Fault::new(sender_id.clone(), FaultKind::DuplicateBVal).into());
            }
            self.received_bval[b].len()
        };

        let mut step = Step::default();

        if count_bval == 2 * self.netinfo.num_faulty() + 1 {
            self.bin_values.insert(b);

            if self.bin_values != bool_set::BOTH {
                step.extend(self.send(&Message::Aux(b))?) // First entry: send `Aux(b)`.
            } else {
                step.extend(self.try_output()?); // Otherwise just check for `Conf` condition.
            }
        }

        if count_bval == self.netinfo.num_faulty() + 1 {
            step.extend(self.send_bval(b)?);
        }

        Ok(step)
    }

    /// Multicasts and handles a message. Does nothing if we are only an observer.
    fn send(&mut self, msg: &Message) -> Result<Step<N>> {
        if !self.netinfo.is_validator() {
            return self.try_output();
        }
        let step: Step<_> = Target::All.message(msg.clone()).into();
        let our_id = &self.netinfo.our_id().clone();
        Ok(step.join(self.handle_message(our_id, &msg)?))
    }

    /// Handles an `Aux` message.
    pub fn handle_aux(&mut self, sender_id: &N, b: bool) -> Result<Step<N>> {
        if !self.received_aux[b].insert(sender_id.clone()) {
            return Ok(Fault::new(sender_id.clone(), FaultKind::DuplicateAux).into());
        }
        self.try_output()
    }

    /// Checks whether there are _N - f_ `Aux` messages with values in `bin_values`, and outputs.
    fn try_output(&mut self) -> Result<Step<N>> {
        if self.terminated || self.bin_values == bool_set::NONE {
            return Ok(Step::default());
        }
        let (aux_count, aux_vals) = self.count_aux();
        if aux_count < self.netinfo.num_correct() {
            return Ok(Step::default());
        }
        self.terminated = true;
        Ok(Step::default().with_output(aux_vals))
    }

    /// The count of `Aux` messages such that the set of values carried by those messages is a
    /// subset of `bin_values`.
    ///
    /// In general, we can't expect every good node to send the same `Aux` value, so waiting for
    /// _N - f_ agreeing messages would not always terminate. We can, however, expect every good
    /// node to send an `Aux` value that will eventually end up in our `bin_values`.
    fn count_aux(&self) -> (usize, BoolSet) {
        let mut values = bool_set::NONE;
        let mut count = 0;
        for b in self.bin_values {
            if !self.received_aux[b].is_empty() {
                values.insert(b);
                count += self.received_aux[b].len();
            }
        }
        (count, values)
    }
}
