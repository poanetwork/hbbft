use failure::Fail;
use reed_solomon_erasure as rse;

/// A broadcast error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    /// Failed to create a `ReedSolomon` instance.
    #[fail(display = "CodingNewReedSolomon error: {}", _0)]
    CodingNewReedSolomon(#[cause] rse::Error),
    /// Failed to encode the value.
    #[fail(display = "CodingEncodeReedSolomon error: {}", _0)]
    CodingEncodeReedSolomon(#[cause] rse::Error),
    /// Failed to reconstruct the value.
    #[fail(display = "CodingReconstructShardsReedSolomon error: {}", _0)]
    CodingReconstructShardsReedSolomon(#[cause] rse::Error),
    /// Failed to reconstruct the value.
    // TODO: This should be unreachable.
    #[fail(display = "CodingReconstructShardsTrivialReedSolomon error: {}", _0)]
    CodingReconstructShardsTrivialReedSolomon(#[cause] rse::Error),
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
