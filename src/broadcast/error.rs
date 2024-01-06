use thiserror::Error as ThisError;

/// A broadcast error.
#[derive(Clone, PartialEq, Debug, ThisError)]
pub enum Error {
    /// Due to a limitation in `reed_solomon_erasure`, only up to 256 nodes are supported.
    #[error("Number of participants must be between 1 and 256")]
    InvalidNodeCount,
    /// Observers cannot propose a value.
    #[error("Instance cannot propose")]
    InstanceCannotPropose,
    /// Multiple inputs received. Only a single value can be proposed.
    #[error("Multiple inputs received")]
    MultipleInputs,
    /// Failed to construct a Merkle tree proof.
    #[error("Proof construction failed")]
    ProofConstructionFailed,
    /// Unknown sender.
    #[error("Unknown sender")]
    UnknownSender,
}

/// A broadcast result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Represents each reason why a broadcast message could be faulty.
#[derive(Clone, Debug, ThisError, PartialEq)]
pub enum FaultKind {
    /// `Broadcast` received a `Value` from a node other than the proposer.
    #[error("`Broadcast` received a `Value` from a node other than the proposer.")]
    ReceivedValueFromNonProposer,
    /// `Broadcast` received multiple different `Value`s from the proposer.
    #[error("`Broadcast` received multiple different `Value`s from the proposer.")]
    MultipleValues,
    /// `Broadcast` received multiple different `Echo`s from the same sender.
    #[error("`Broadcast` received multiple different `Echo`s from the same sender.")]
    MultipleEchos,
    /// `Broadcast` received multiple different `EchoHash`s from the same sender.
    #[error("`Broadcast` received multiple different `EchoHash`s from the same sender.")]
    MultipleEchoHashes,
    /// `Broadcast` received multiple different `Ready`s from the same sender.
    #[error("`Broadcast` received multiple different `Ready`s from the same sender.")]
    MultipleReadys,
    /// `Broadcast` recevied an Echo message containing an invalid proof.
    #[error("`Broadcast` recevied an Echo message containing an invalid proof.")]
    InvalidProof,
    ///`Broadcast` received shards with valid proofs, that couldn't be decoded.
    #[error("`Broadcast` received shards with valid proofs, that couldn't be decoded.")]
    BroadcastDecoding,
}
