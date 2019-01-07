use failure::Fail;
use std::fmt::Debug;

/// Sender queue error variants.
#[derive(Debug, Fail)]
pub enum Error<E>
where
    E: Debug + Fail,
{
    /// Failed to apply a function to the managed algorithm.
    #[fail(display = "Function application failure: {}", _0)]
    Apply(E),
    /// Failed to restart `DynamicHoneyBadger` because it had not been removed.
    #[fail(display = "DynamicHoneyBadger was not removed before restarting")]
    DynamicHoneyBadgerNotRemoved,
    /// Failed to start a new joining `DynamicHoneyBadger`.
    #[fail(display = "Failed to start a new joining DynamicHoneyBadger: {}", _0)]
    DynamicHoneyBadgerNewJoining(E),
}
