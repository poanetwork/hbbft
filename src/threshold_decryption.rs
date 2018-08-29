//! # Collaborative Threshold Decryption
//!
//! Each node inputs the same encrypted data, and after at least _f + 1_ correct validators have
//! done so, each node outputs the decrypted data.
//!
//! ## How it works
//!
//! The algorithm uses a threshold encryption scheme: A message encrypted to the network's public
//! key can be collaboratively decrypted by combining at least _f + 1_ decryption shares. Each
//! validator holds a secret key share, and uses it to produce and multicast a decryption share.
//! The algorithm outputs as soon as _f + 1_ of them have been received.

use std::collections::BTreeMap;
use std::sync::Arc;

use crypto::error as cerror;
use crypto::{Ciphertext, DecryptionShare};
use fault_log::{Fault, FaultKind, FaultLog};
use messaging::{self, DistAlgorithm, NetworkInfo, Target};
use traits::NodeUidT;

/// A threshold decryption error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "Redundant input provided: {:?}", _0)]
    MultipleInputs(Box<Ciphertext>),
    #[fail(display = "Invalid ciphertext: {:?}", _0)]
    InvalidCiphertext(Box<Ciphertext>),
    #[fail(display = "Unknown sender")]
    UnknownSender,
    #[fail(display = "Decryption failed: {:?}", _0)]
    Decryption(cerror::Error),
}

/// A threshold decryption result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// A Threshold Decryption message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Rand)]
pub struct Message(pub DecryptionShare);

/// A Threshold Decryption algorithm instance. If every node inputs the same data, encrypted to the
/// network's public key, every node will output the decrypted data.
#[derive(Debug)]
pub struct ThresholdDecryption<N> {
    netinfo: Arc<NetworkInfo<N>>,
    /// The encrypted data.
    ciphertext: Option<Ciphertext>,
    /// All received threshold decryption shares.
    shares: BTreeMap<N, DecryptionShare>,
    /// Whether we have already returned the output.
    terminated: bool,
}

pub type Step<N> = messaging::Step<ThresholdDecryption<N>>;

impl<N: NodeUidT> DistAlgorithm for ThresholdDecryption<N> {
    type NodeUid = N;
    type Input = Ciphertext;
    type Output = Vec<u8>;
    type Message = Message;
    type Error = Error;

    fn handle_input(&mut self, input: Ciphertext) -> Result<Step<N>> {
        self.set_ciphertext(input)
    }

    fn handle_message(&mut self, sender_id: &N, message: Message) -> Result<Step<N>> {
        self.handle_message(sender_id, message)
    }

    fn terminated(&self) -> bool {
        self.terminated
    }

    fn our_id(&self) -> &N {
        self.netinfo.our_uid()
    }
}

impl<N: NodeUidT> ThresholdDecryption<N> {
    /// Creates a new Threshold Decryption instance.
    pub fn new(netinfo: Arc<NetworkInfo<N>>) -> Self {
        ThresholdDecryption {
            netinfo,
            ciphertext: None,
            shares: BTreeMap::new(),
            terminated: false,
        }
    }

    /// Sets the ciphertext, sends the decryption share, and tries to decrypt it.
    /// This must be called exactly once, with the same ciphertext in all participating nodes.
    pub fn set_ciphertext(&mut self, ct: Ciphertext) -> Result<Step<N>> {
        if self.ciphertext.is_some() {
            return Err(Error::MultipleInputs(Box::new(ct)));
        }
        let share = match self.netinfo.secret_key_share().decrypt_share(&ct) {
            None => return Err(Error::InvalidCiphertext(Box::new(ct))),
            Some(share) => share,
        };
        self.ciphertext = Some(ct);
        let our_id = self.our_id().clone();
        let mut step = Step::default();
        step.fault_log.extend(self.remove_invalid_shares());
        if self.netinfo.is_validator() {
            let msg = Target::All.message(Message(share.clone()));
            step.messages.push_back(msg);
            self.shares.insert(our_id, share);
        }
        step.extend(self.try_output()?);
        Ok(step)
    }

    /// Returns an iterator over the IDs of all nodes who sent a share.
    pub fn sender_ids(&self) -> impl Iterator<Item = &N> {
        self.shares.keys()
    }

    fn handle_message(&mut self, sender_id: &N, message: Message) -> Result<Step<N>> {
        if self.terminated {
            return Ok(Step::default()); // Don't waste time on redundant shares.
        }
        let Message(share) = message;
        if !self.is_share_valid(sender_id, &share) {
            let fault_kind = FaultKind::UnverifiedDecryptionShareSender;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }
        if self.shares.insert(sender_id.clone(), share).is_some() {
            return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleDecryptionShares).into());
        }
        self.try_output()
    }

    /// Removes all shares that are invalid, and returns faults for their senders.
    fn remove_invalid_shares(&mut self) -> FaultLog<N> {
        let faulty_senders: Vec<N> = self
            .shares
            .iter()
            .filter(|(id, share)| !self.is_share_valid(id, share))
            .map(|(id, _)| id.clone())
            .collect();
        let mut fault_log = FaultLog::default();
        for id in faulty_senders {
            self.shares.remove(&id);
            fault_log.append(id, FaultKind::UnverifiedDecryptionShareSender);
        }
        fault_log
    }

    /// Returns `true` if the share is valid, or if we don't have the ciphertext yet.
    fn is_share_valid(&self, id: &N, share: &DecryptionShare) -> bool {
        let ct = match self.ciphertext {
            None => return true, // No ciphertext yet. Verification postponed.
            Some(ref ct) => ct,
        };
        match self.netinfo.public_key_share(id) {
            None => false, // Unknown sender.
            Some(pk) => pk.verify_decryption_share(share, ct),
        }
    }

    /// Outputs the decrypted message, if we have the ciphertext and enough shares.
    fn try_output(&mut self) -> Result<Step<N>> {
        if self.terminated || self.shares.len() <= self.netinfo.num_faulty() {
            return Ok(Step::default()); // Not enough shares yet, or already terminated.
        }
        let ct = match self.ciphertext {
            None => return Ok(Step::default()), // Still waiting for the ciphertext.
            Some(ref ct) => ct,
        };
        self.terminated = true;
        let plaintext = {
            let to_idx = |(id, share)| {
                let idx = self
                    .netinfo
                    .node_index(id)
                    .expect("we put only validators' shares in the map; qed");
                (idx, share)
            };
            let share_itr = self.shares.iter().map(to_idx);
            self.netinfo
                .public_key_set()
                .decrypt(share_itr, ct)
                .map_err(Error::Decryption)?
        };
        Ok(Step::default().with_output(plaintext))
    }
}
