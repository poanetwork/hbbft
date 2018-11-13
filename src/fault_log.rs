//! Functionality for logging faulty node behavior encountered by each
//! algorithm.
//!
//! Each algorithm can propogate their faulty node logs upwards to a
//! calling algorithm via `DistAlgorihm`'s `.handle_input()` and
//! `.handle_message()` trait methods.

pub use sync_key_gen::{AckFault, PartFault};

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
    DeserializeCiphertext,
    /// `HoneyBadger` received an invalid ciphertext from the proposer.
    InvalidCiphertext,
    /// `HoneyBadger` received a message with an invalid epoch.
    UnexpectedHbMessageEpoch,
    /// `HoneyBadger` received a signatures share for the random value even though it is disabled.
    UnexpectedSignatureShare,
    /// `ThresholdDecrypt` received multiple shares from the same sender.
    MultipleDecryptionShares,
    /// `Broadcast` received a `Value` from a node other than the proposer.
    ReceivedValueFromNonProposer,
    /// `Broadcast` received multiple different `Value`s from the proposer.
    MultipleValues,
    /// `Broadcast` received multiple different `Echo`s from the same sender.
    MultipleEchos,
    /// `Broadcast` received multiple different `Ready`s from the same sender.
    MultipleReadys,
    /// `Broadcast` recevied an Echo message containing an invalid proof.
    InvalidProof,
    /// `Broadcast` received shards with valid proofs, that couldn't be decoded.
    BroadcastDecoding,
    /// `HoneyBadger` could not deserialize bytes (i.e. a serialized Batch)
    /// from a given proposer into a vector of transactions.
    BatchDeserializationFailed,
    /// `DynamicHoneyBadger` received a key generation message with an invalid signature.
    InvalidKeyGenMessageSignature,
    /// `DynamicHoneyBadger` received a key generation message with an invalid era.
    InvalidKeyGenMessageEra,
    /// `DynamicHoneyBadger` received a key generation message when there was no key generation in
    /// progress.
    UnexpectedKeyGenMessage,
    /// `DynamicHoneyBadger` received a signed `Ack` when no key generation in progress.
    UnexpectedKeyGenAck,
    /// `DynamicHoneyBadger` received a signed `Part` when no key generation in progress.
    UnexpectedKeyGenPart,
    /// `DynamicHoneyBadger` received more key generation messages from the peer than expected.
    TooManyKeyGenMessages,
    /// `DynamicHoneyBadger` received a message (Accept, Propose, or Change)
    /// with an invalid signature.
    IncorrectPayloadSignature,
    /// `DynamicHoneyBadger`/`SyncKeyGen` received an invalid `Ack` message.
    SyncKeyGenAck(AckFault),
    /// `DynamicHoneyBadger`/`SyncKeyGen` received an invalid `Part` message.
    SyncKeyGenPart(PartFault),
    /// `DynamicHoneyBadger` received a change vote with an invalid signature.
    InvalidVoteSignature,
    /// A validator committed an invalid vote in `DynamicHoneyBadger`.
    InvalidCommittedVote,
    /// `DynamicHoneyBadger` received a message with an invalid era.
    UnexpectedDhbMessageEra,
    /// `BinaryAgreement` received a duplicate `BVal` message.
    DuplicateBVal,
    /// `BinaryAgreement` received a duplicate `Aux` message.
    DuplicateAux,
    /// `BinaryAgreement` received multiple `Conf` messages.
    MultipleConf,
    /// `BinaryAgreement` received multiple `Term` messages.
    MultipleTerm,
    /// `BinaryAgreement` received a message with an epoch too far ahead.
    AgreementEpoch,
}

/// A structure representing the context of a faulty node. This structure
/// describes which node is faulty (`node_id`) and which faulty behavior
/// that the node exhibited ('kind').
#[derive(Clone, Debug, PartialEq)]
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
