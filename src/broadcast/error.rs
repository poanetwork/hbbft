use failure::Fail;
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

/// Represents each reason why a broadcast message could be faulty.
#[derive(Debug, Fail, PartialEq)]
pub enum FaultKind {
    #[fail(display = "`Broadcast` received a `Value` from a node other than the proposer.")]
    ReceivedValueFromNonProposer,
    #[fail(display = "`Broadcast` received multiple different `Value`s from the proposer.")]
    MultipleValues,
    #[fail(display = "`Broadcast` received multiple different `Echo`s from the same sender.")]
    MultipleEchos,
    #[fail(display = "`Broadcast` received multiple different `Ready`s from the same sender.")]
    MultipleReadys,
    #[fail(display = "`Broadcast` recevied an Echo message containing an invalid proof.")]
    InvalidProof,
    #[fail(display = "`Broadcast` received shards with valid proofs, that couldn't be decoded.")]
    BroadcastDecoding,
}
