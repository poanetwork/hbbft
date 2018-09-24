//! Functionality for logging faulty node behavior encountered by each
//! algorithm.
//!
//! Each algorithm can propogate their faulty node logs upwards to a
//! calling algorithm via `DistAlgorihm`'s `.handle_input()` and
//! `.handle_message()` trait methods.

/// A fault log entry.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Fail)]
pub enum AckMessageFault {
    #[fail(display = "Wrong node count")]
    NodeCount,
    #[fail(display = "Sender does not exist")]
    SenderExist,
    #[fail(display = "Duplicate ack")]
    DuplicateAck,
    #[fail(display = "Value decryption failed")]
    ValueDecryption,
    #[fail(display = "Value deserialization failed")]
    ValueDeserialization,
    #[fail(display = "Invalid value")]
    ValueInvalid,
}

/// Represents each reason why a node could be considered faulty.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FaultKind {
    /// `Coin` received a signature share from an unverified sender.
    UnverifiedSignatureShareSender,
    /// `HoneyBadger` received a decryption share from an unverified sender.
    UnverifiedDecryptionShareSender,
    /// `HoneyBadger` received a decryption share for an unaccepted proposer.
    UnexpectedDecryptionShare,
    /// `HoneyBadger` was unable to deserialize a proposer's ciphertext.
    InvalidCiphertext,
    /// `HoneyBadger` was unable to decrypt a share received from a proposer.
    ShareDecryptionFailed,
    /// `ThresholdDecryption` received multiple shares from the same sender.
    MultipleDecryptionShares,
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
    /// `DynamicHoneyBadger` received a key generation message when there was no key generation in
    /// progress.
    UnexpectedKeyGenMessage,
    /// `DynamicHoneyBadger` received more key generation messages from the candidate than expected.
    TooManyCandidateKeyGenMessages,
    /// `DynamicHoneyBadger` received a message (Accept, Propose, or Change)
    /// with an invalid signature.
    IncorrectPayloadSignature,
    /// `DynamicHoneyBadger`/`SyncKeyGen` received an invalid Ack message.
    AckMessage(AckMessageFault),
    /// `DynamicHoneyBadger`/`SyncKeyGen` received an invalid Part message.
    InvalidPartMessage,
    /// `DynamicHoneyBadger` received a change vote with an invalid signature.
    InvalidVoteSignature,
    /// A validator committed an invalid vote in `DynamicHoneyBadger`.
    InvalidCommittedVote,
    /// `BinaryAgreement` received a duplicate `BVal` message.
    DuplicateBVal,
    /// `BinaryAgreement` received a duplicate `Aux` message.
    DuplicateAux,
    /// Incoming `HoneyBadger` message epoch is out of range.
    EpochOutOfRange,
}

/// A structure representing the context of a faulty node. This structure
/// describes which node is faulty (`node_id`) and which faulty behavior
/// that the node exhibited ('kind').
#[derive(Debug, PartialEq)]
pub struct Fault<N> {
    pub node_id: N,
    pub kind: FaultKind,
}

impl<N> Fault<N> {
    pub fn new(node_id: N, kind: FaultKind) -> Self {
        Fault { node_id, kind }
    }
}

/// Creates a new `FaultLog` where `self` is the first element in the log
/// vector.
impl<N> Into<FaultLog<N>> for Fault<N> {
    fn into(self) -> FaultLog<N> {
        FaultLog(vec![self])
    }
}

/// A structure used to contain reports of faulty node behavior.
#[derive(Debug, PartialEq)]
pub struct FaultLog<N>(pub Vec<Fault<N>>);

impl<N> FaultLog<N> {
    /// Creates an empty `FaultLog`.
    pub fn new() -> Self {
        FaultLog::default()
    }

    /// Creates a new `FaultLog` initialized with a single log.
    pub fn init(node_id: N, kind: FaultKind) -> Self {
        Fault::new(node_id, kind).into()
    }

    /// Creates a new `Fault` and pushes it onto the fault log.
    pub fn append(&mut self, node_id: N, kind: FaultKind) {
        self.0.push(Fault::new(node_id, kind));
    }

    /// Consumes `new_logs`, appending its logs onto the end of `self`.
    pub fn extend(&mut self, new_logs: FaultLog<N>) {
        self.0.extend(new_logs.0);
    }

    /// Consumes `self`, appending its logs onto the end of `logs`.
    pub fn merge_into(self, logs: &mut FaultLog<N>) {
        logs.extend(self);
    }

    /// Returns `true` if there are no fault entries in the log.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<N> Default for FaultLog<N> {
    fn default() -> Self {
        FaultLog(vec![])
    }
}
