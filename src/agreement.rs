//! Binary Byzantine agreement protocol from a common coin protocol.

use proto::AgreementMessage;
use std::collections::{BTreeSet, VecDeque};

pub struct Agreement {
    input: Option<bool>,
    bin_values: BTreeSet<bool>,
}

impl Agreement {
    pub fn new() -> Self {
        Agreement {
            input: None,
            bin_values: BTreeSet::new(),
        }
    }

    pub fn set_input(&mut self, input: bool) -> AgreementMessage {
        self.input = Some(input);
        // Multicast BVAL
        AgreementMessage::BVal(input)
    }

    pub fn has_input(&self) -> bool {
        self.input.is_some()
    }

    /// Receive input from a remote node.
    pub fn on_input(
        &self,
        _message: AgreementMessage,
    ) -> Result<VecDeque<AgreementMessage>, Error> {
        Err(Error::NotImplemented)
    }
}

#[derive(Clone, Debug)]
pub enum Error {
    NotImplemented,
}
