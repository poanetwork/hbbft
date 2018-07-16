//! Functionality for logging faulty node behavior encountered by each
//! algorithm.
//!
//! Each algorithm can propogate their faulty node logs upwards to a
//! calling algorithm via `DistAlgorihm`'s `.input()` and
//! `.handle_message()` trait methods.

/// Represents each reason why a node could be considered faulty.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FaultKind {
    /// `CommonCoin` received a signature share from an unverified sender.
    UnverifiedSignatureShareSender,
    /// `HoneyBadger` received a decryption share from an unverified sender.
    UnverifiedDecryptionShareSender,
    /// `HoneyBadger` was unable to deserialize a proposer's ciphertext.
    InvalidCiphertext,
    /// `HoneyBadger` was unable to decrypt a share received from a proposer.
    ShareDecryptionFailed,
    /// `Broadcast` received a `Value` from a node other than the proposer.
    ReceivedValueFromNonProposer,
    /// `Broadcast` recevied an Echo message containing an invalid proof.
    InvalidProof,
    /// `HoneyBadger` could not deserialize bytes (i.e. a serialized Batch)
    /// from a given proposer into a vector of transactions.
    BatchDeserializationFailed,
    /// `DynamicHoneyBadger` received a key generation message with an invalid
    /// signature.
    InvalidKeyGenMessageSignature,
    /// `DynamicHoneyBadger` received a message (Accept, Propose, or Change)
    /// with an invalid signature.
    IncorrectPayloadSignature,
    /// `DynamicHoneyBadger`/`SyncKeyGen` received an invalid Accept message.
    InvalidAcceptMessage,
    /// `DynamicHoneyBadger`/`SyncKeyGen` received an invalid Propose message.
    InvalidProposeMessage,
    /// `DynamicHoneyBadger` received a change vote with an invalid signature.
    InvalidVoteSignature,
    /// A validator committed an invalid vote in `DynamicHoneyBadger`.
    InvalidCommittedVote,
}

/// A structure representing the context of a faulty node. This structure
/// describes which node is faulty (`node_id`) and which faulty behavior
/// that the node exhibited ('kind').
#[derive(Debug, PartialEq)]
pub struct Fault<NodeUid> {
    pub node_id: NodeUid,
    pub kind: FaultKind,
}

impl<NodeUid> Fault<NodeUid> {
    pub fn new(node_id: NodeUid, kind: FaultKind) -> Self {
        Fault { node_id, kind }
    }
}

/// Creates a new `FaultLog` where `self` is the first element in the log
/// vector.
impl<NodeUid> Into<FaultLog<NodeUid>> for Fault<NodeUid> {
    fn into(self) -> FaultLog<NodeUid> {
        FaultLog(vec![self])
    }
}

/// A structure used to contain reports of faulty node behavior.
#[derive(Debug, PartialEq)]
pub struct FaultLog<NodeUid>(pub Vec<Fault<NodeUid>>);

impl<NodeUid> FaultLog<NodeUid> {
    /// Creates an empty `FaultLog`.
    pub fn new() -> Self {
        FaultLog::default()
    }

    /// Creates a new `FaultLog` initialized with a single log.
    pub fn init(node_id: NodeUid, kind: FaultKind) -> Self {
        Fault::new(node_id, kind).into()
    }

    /// Creates a new `Fault` and pushes it onto the fault log.
    pub fn append(&mut self, node_id: NodeUid, kind: FaultKind) {
        self.0.push(Fault::new(node_id, kind));
    }

    /// Consumes `new_logs`, appending its logs onto the end of `self`.
    pub fn extend(&mut self, new_logs: FaultLog<NodeUid>) {
        self.0.extend(new_logs.0);
    }

    /// Consumes `self`, appending its logs onto the end of `logs`.
    pub fn merge_into(self, logs: &mut FaultLog<NodeUid>) {
        logs.extend(self);
    }

    /// Returns `true` if there are no fault entries in the log.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<NodeUid> Default for FaultLog<NodeUid> {
    fn default() -> Self {
        FaultLog(vec![])
    }
}
