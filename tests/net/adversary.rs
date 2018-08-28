//! Adversaries for test networks
//!
//! Adversaries can alter message ordering, inject messages and control the behavior of any faulty
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
    fn pre_crank(&mut self, _net: &mut VirtualNet<D>) {}

    /// Tamper with a faulty node's operation.
    ///
    /// You can (but are not required to) run faulty nodes like regular nodes. However, if a node
    /// is marked faulty, a message is not passed directly to the node. It is handed to 'tamper'
    /// instead.
    ///
    /// The return value replaces what would otherwise have been output by the algorithm, the
    /// returned step is processed normally by the network (messages are queued and outputs
    /// are recorded).
    ///
    /// The default implementation does not perform any tampering, but instead calls
    /// `VirtualNet::dispatch_message`, which results in the message being processed as if the node
    /// was not faulty.
    #[inline]
    fn tamper(
        &mut self,
        net: &mut VirtualNet<D>,
        msg: NetMessage<D>,
    ) -> Result<Step<D>, CrankError<D>> {
        net.dispatch_message(msg)
    }
}

/// Passive adversary.
///
/// The `NullAdversary` does not interfere with operation in any way, it neither reorders messages
/// nor tampers with message, passing them through unchanged instead.
#[derive(Debug, Default)]
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
