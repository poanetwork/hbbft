use failure::Fail;

/// A broadcast error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    /// Due to a limitation in `reed_solomon_erasure`, only up to 256 nodes are supported.
    #[fail(display = "Number of participants must be between 1 and 256")]
    InvalidNodeCount,
    /// Observers cannot propose a value.
    #[fail(display = "Instance cannot propose")]
    InstanceCannotPropose,
    /// Multiple inputs received. Only a single value can be proposed.
    #[fail(display = "Multiple inputs received")]
    MultipleInputs,
    /// Failed to construct a Merkle tree proof.
    #[fail(display = "Proof construction failed")]
    ProofConstructionFailed,
    /// Unknown sender.
    #[fail(display = "Unknown sender")]
    UnknownSender,
}

/// A broadcast result.
pub type Result<T> = ::std::result::Result<T, Error>;
