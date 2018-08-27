//! Adversaries for test networks
//!
//! Adversaries can alter message ordering, inject messages and control the behaviour of any faulty
//! node. These functions are handled through callbacks, implemented individually by each adversary.
//!
//! This module contains algorithm-agnostic adversaries, which should work for (or rather, against)
//! any `DistAlgorithm`. Specific adversaries tailored to individual algorithms are implemented
//! alongside their other test cases.
//!
//! Note: Currently, adversaries are not "limited in power". In future versions, the references
//!       passed to various callbacks might receive a smaller interface, to prevent manipulations
//!       that are beyond the modelled adversaries capabilities. Currently, the implementor is
//!       responsible for ensuring no invariants are violated.

use net::{CrankError, NetMessage, VirtualNet};

use hbbft::messaging::{DistAlgorithm, Step};

/// Network adversary.
pub trait Adversary<D>
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
{
    /// Pre-crank hook.
    ///
    /// Executed before each crank, the `pre_crank` function allows the adversary to manipulate the
    /// order of network messages by manipulating the `net` parameter.
    ///
    /// The default implementation does not alter the passed network in any way.
    #[inline]
    fn pre_crank(&mut self, _net: &mut VirtualNet<D>) {
        // The default implementation does not alter anything.
    }

    /// Tamper with a faulty nodes operation.
    ///
    /// Faulty nodes can (but are not required to) be run like regular nodes. A core difference is
    /// that instead of passing the message directly to the node, if the destination is marked
    /// faulty, the message will be handed to `tamper` instead. The return value replaces whatever
    /// processing would have taken place otherwise.
    ///
    /// The default implementation does not perform any tampering, but instead calls
    /// `VirtualNet::dispatch_message`, which results in the message being processed as if it wasn't
    /// faulty.
    #[inline]
    fn tamper(
        &mut self,
        net: &mut VirtualNet<D>,
        msg: NetMessage<D>,
    ) -> Result<Step<D>, CrankError<D>> {
        // By default, no tampering is done.
        net.dispatch_message(msg)
    }
}

/// Passive adversary.
///
/// The `NullAdversary` does not interfere with operation in any way, it neither reorders messages
/// nor tampers with message, passing them through unchanged instead.
pub struct NullAdversary {}

impl NullAdversary {
    /// Create a new `NullAdversary`.
    #[inline]
    pub fn new() -> NullAdversary {
        NullAdversary {}
    }
}

impl<D> Adversary<D> for NullAdversary
where
    D: DistAlgorithm,
    D::Message: Clone,
    D::Output: Clone,
{}
