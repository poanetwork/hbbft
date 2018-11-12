//! # Collaborative Threshold Decryption
//!
//! Each node inputs the same encrypted data, and after at least _f + 1_ correct validators have
//! done so, each node outputs the decrypted data.
//!
//! ## How it works
//!
//! The algorithm uses a threshold encryption scheme: A message encrypted to the network's public
//! key can be collaboratively decrypted by combining at least _f + 1_ decryption shares. Each
//! validator holds a secret key share, and uses it to produce and multicast a decryption share once
//! a ciphertext is provided. The algorithm outputs as soon as it receives a ciphertext and _f + 1_
//! threshold shares.

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
    #[fail(display = "Start decryption called before setting ciphertext")]
    CiphertextIsNone,
}

/// A threshold decryption result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// A Threshold Decryption message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Rand)]
pub struct Message(pub DecryptionShare);

/// A Threshold Decrypt algorithm instance. If every node inputs the same data, encrypted to the
/// network's public key, every node will output the decrypted data.
#[derive(Debug)]
pub struct ThresholdDecrypt<N> {
    netinfo: Arc<NetworkInfo<N>>,
    /// The encrypted data.
    ciphertext: Option<Ciphertext>,
    /// All received threshold decryption shares.
    shares: BTreeMap<N, DecryptionShare>,
    /// Whether we already sent our shares.
    had_input: bool,
    /// Whether we have already returned the output.
    terminated: bool,
}

pub type Step<N> = ::DaStep<ThresholdDecrypt<N>>;

impl<N: NodeIdT> DistAlgorithm for ThresholdDecrypt<N> {
    type NodeId = N;
    type Input = ();
    type Output = Vec<u8>;
    type Message = Message;
    type Error = Error;

    fn handle_input(&mut self, _input: ()) -> Result<Step<N>> {
        self.start_decryption()
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

impl<N: NodeIdT> ThresholdDecrypt<N> {
    /// Creates a new Threshold Decrypt instance.
    pub fn new(netinfo: Arc<NetworkInfo<N>>) -> Self {
        ThresholdDecrypt {
            netinfo,
            ciphertext: None,
            shares: BTreeMap::new(),
            had_input: false,
            terminated: false,
        }
    }

    /// Creates a new instance of `ThresholdDecrypt`, including setting the ciphertext to
    /// decrypt.
    pub fn new_with_ciphertext(netinfo: Arc<NetworkInfo<N>>, ct: Ciphertext) -> Result<Self> {
        let mut td = ThresholdDecrypt::new(netinfo);
        td.set_ciphertext(ct)?;
        Ok(td)
    }

    /// Sets the ciphertext, sends the decryption share, and tries to decrypt it.
    /// This must be called exactly once, with the same ciphertext in all participating nodes.
    /// If we have enough shares, outputs the plaintext.
    pub fn set_ciphertext(&mut self, ct: Ciphertext) -> Result<()> {
        if self.ciphertext.is_some() {
            return Err(Error::MultipleInputs(Box::new(ct)));
        }
        if !ct.verify() {
            return Err(Error::InvalidCiphertext(Box::new(ct.clone())));
        }
        self.ciphertext = Some(ct);
        Ok(())
    }

    /// Sends our decryption shares to peers, and if we have collected enough, returns the decrypted
    /// message. Returns an error if the ciphertext hasn't been received yet.
    pub fn start_decryption(&mut self) -> Result<Step<N>> {
        if self.had_input {
            return Ok(Step::default()); // Don't waste time on redundant shares.
        }
        let ct = self.ciphertext.clone().ok_or(Error::CiphertextIsNone)?;
        let mut step = Step::default();
        step.fault_log.extend(self.remove_invalid_shares());
        self.had_input = true;
        if !self.netinfo.is_validator() {
            step.extend(self.try_output()?);
            return Ok(step);
        }
        let share = self.netinfo.secret_key_share().decrypt_share_no_verify(&ct);
        let our_id = self.our_id().clone();
        let msg = Target::All.message(Message(share.clone()));
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
        if self.terminated {
            return Ok(Step::default()); // Don't waste time on redundant shares.
        }
        // Before checking the share, ensure the sender is a known validator
        self.netinfo
            .public_key_share(sender_id)
            .ok_or(Error::UnknownSender)?;
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
            Some(ref ct) => ct.clone(),
        };
        self.terminated = true;
        let step = self.start_decryption()?; // Before terminating, make sure we sent our share.
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
                .decrypt(share_itr, &ct)
                .map_err(Error::Decryption)?
        };
        Ok(step.with_output(plaintext))
    }
}
