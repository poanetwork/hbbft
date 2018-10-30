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

use crypto::{self, Ciphertext, DecryptionShare};
use failure::Fail;
use rand_derive::Rand;
use serde_derive::{Deserialize, Serialize};

use fault_log::{Fault, FaultKind, FaultLog};
use {DistAlgorithm, NetworkInfo, NodeIdT, Target};

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
    Decryption(crypto::error::Error),
}

/// A threshold decryption result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// A Threshold Decryption message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Message {
    /// A decryption share from a peer.
    Share(DecryptionShare),
    /// A message setting nodeId's ciphertext Should only be transmitted locally.
    Cipher(Ciphertext),
}

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

pub type Step<N> = ::Step<ThresholdDecryption<N>>;

impl<N: NodeIdT> DistAlgorithm for ThresholdDecryption<N> {
    type NodeId = N;
    type Input = ();
    type Output = Vec<u8>;
    type Message = Message;
    type Error = Error;

    fn handle_input(&mut self, _input: ()) -> Result<Step<N>> {
        self.try_output()
    }

    fn handle_message(&mut self, sender_id: &N, message: Message) -> Result<Step<N>> {
        self.handle_message(sender_id, message)
    }

    fn terminated(&self) -> bool {
        self.terminated
    }

    fn our_id(&self) -> &N {
        self.netinfo.our_id()
    }
}

impl<N: NodeIdT> ThresholdDecryption<N> {
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
    /// If we have enough shares, outputs the plaintext.
    pub fn set_ciphertext(&mut self, ct: Ciphertext) -> Result<Step<N>> {
        if self.ciphertext.is_some() {
            return Err(Error::MultipleInputs(Box::new(ct)));
        }
        if !self.netinfo.is_validator() {
            self.ciphertext = Some(ct);
            return Ok(self.try_output()?);
        }
        let share = match self.netinfo.secret_key_share().decrypt_share(&ct) {
            None => return Err(Error::InvalidCiphertext(Box::new(ct))),
            Some(share) => share,
        };
        self.ciphertext = Some(ct);
        let our_id = self.our_id().clone();
        let mut step = Step::default();
        step.fault_log.extend(self.remove_invalid_shares());
        let msg = Target::All.message(Message::Share(share.clone()));
        step.messages.push(msg);
        self.shares.insert(our_id, share);
        step.extend(self.try_output()?);
        Ok(step)
    }

    /// Returns an iterator over the IDs of all nodes who sent a share.
    pub fn sender_ids(&self) -> impl Iterator<Item = &N> {
        self.shares.keys()
    }

    /// Handles a message with a decryption share received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    ///
    /// If we have collected enough, returns the decrypted message.
    pub fn handle_message(&mut self, sender_id: &N, message: Message) -> Result<Step<N>> {
        let mut step = Step::default();
        if self.terminated {
            return Ok(step); // Don't waste time on redundant shares.
        }
        step.extend(match message {
            Message::Share(share) => {
                if !self.is_share_valid(sender_id, &share) {
                    let fault_kind = FaultKind::UnverifiedDecryptionShareSender;
                    return Ok(Fault::new(sender_id.clone(), fault_kind).into());
                }
                if self.shares.insert(sender_id.clone(), share).is_some() {
                    return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleDecryptionShares).into());
                }
                Step::default()
            },
            Message::Cipher(ciphertext) => self.set_ciphertext(ciphertext)?,
        });
        step.extend(self.try_output()?);
        Ok(step)
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
