//! Network adversary
//!
//!
//! FIXME: Use traits to limit adversary influence.

use net::{CrankError, NetMessage, VirtualNet};

use hbbft::messaging::{DistAlgorithm, Step};

pub trait Adversary<D>
where
    D: DistAlgorithm,
    D::Message: Clone,
{
    fn pre_crank(&mut self, _net: &mut VirtualNet<D>) {
        // The default implementation does not alter anything.
    }
    fn tamper(
        &mut self,
        net: &mut VirtualNet<D>,
        msg: NetMessage<D>,
    ) -> Result<Step<D>, CrankError<D>> {
        // By default, no tampering is done.
        net.dispatch_message(msg)
        // FIXME: process `Step`?
    }
}

pub struct NullAdversary {}

impl NullAdversary {
    pub fn new() -> NullAdversary {
        NullAdversary {}
    }
}

impl<D> Adversary<D> for NullAdversary
where
    D::Message: Clone,
    D: DistAlgorithm,
{
}
