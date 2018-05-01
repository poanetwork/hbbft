//! Binary Byzantine agreement protocol from a common coin protocol.

pub struct Agreement {
    input: Option<bool>
}

impl Agreement {
    pub fn get_input(&self) -> Option<bool> {
        self.input
    }

    pub fn set_input(&mut self, input: bool) {
        self.input = Some(input);
    }
}
