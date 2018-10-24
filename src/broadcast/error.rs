use reed_solomon_erasure as rse;

/// A broadcast error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "CodingNewReedSolomon error: {}", _0)]
    CodingNewReedSolomon(#[cause] rse::Error),
    #[fail(display = "CodingEncodeReedSolomon error: {}", _0)]
    CodingEncodeReedSolomon(#[cause] rse::Error),
    #[fail(display = "CodingReconstructShardsReedSolomon error: {}", _0)]
    CodingReconstructShardsReedSolomon(#[cause] rse::Error),
    #[fail(
        display = "CodingReconstructShardsTrivialReedSolomon error: {}",
        _0
    )]
    CodingReconstructShardsTrivialReedSolomon(#[cause] rse::Error),
    #[fail(display = "Instance cannot propose")]
    InstanceCannotPropose,
    #[fail(display = "Multiple inputs received")]
    MultipleInputs,
    #[fail(display = "Not implemented")]
    NotImplemented,
    #[fail(display = "Proof construction failed")]
    ProofConstructionFailed,
    #[fail(display = "Root hash mismatch")]
    RootHashMismatch,
    #[fail(display = "Threading")]
    Threading,
    #[fail(display = "Unknown sender")]
    UnknownSender,
}

/// A broadcast result.
pub type Result<T> = ::std::result::Result<T, Error>;
