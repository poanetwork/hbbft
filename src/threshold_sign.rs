//! # Collaborative Threshold Signing
//!
//! The algorithm is instantiated and waits to recieve a document to sign, as well as signature
//! shares from threshold signature validation peers. Once `set_document` is successfully called,
//! then `handle_input(())` or `sign()` is called, which then sends a signature share to each
//! threshold signature validation peer. When at least _f + 1_ validators have shared their
//! signatures in this manner, each node outputs the same, valid signature of the data.
//!
//! In addition to signing, this can also be used as a source of pseudorandomness: The signature
//! cannot be known until more than _f_ validators have contributed their shares.
//!
//! ## How it works
//!
//! The algorithm uses a threshold signature scheme with the uniqueness property: For each public
//! key and message, there is exactly one valid signature. This group signature is produced using
//! signature shares from any combination of _f + 1_ secret key share holders.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::{fmt, result};

use crate::crypto::{self, hash_g2, Signature, SignatureShare, G2};
use failure::Fail;
use log::debug;
use rand::Rng;
use rand_derive::Rand;
use serde_derive::{Deserialize, Serialize};

use crate::fault_log::{Fault, FaultLog};
use crate::{DistAlgorithm, NetworkInfo, NodeIdT, Target};

/// A threshold signing error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    /// Redundant input provided.
    #[fail(display = "Redundant input provided")]
    MultipleMessagesToSign,
    /// Error combining and verifying signature shares.
    #[fail(display = "Error combining and verifying signature shares: {}", _0)]
    CombineAndVerifySigCrypto(crypto::error::Error),
    /// Unknown sender
    #[fail(display = "Unknown sender")]
    UnknownSender,
    /// Signature verification failed.
    #[fail(display = "Signature verification failed")]
    VerificationFailed,
    /// Document hash is not set, cannot sign or verify signatures.
    #[fail(display = "Document hash is not set, cannot sign or verify signatures")]
    DocumentHashIsNone,
}

/// A threshold signing result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// A threshold sign message fault
#[derive(Clone, Debug, Fail, PartialEq)]
pub enum FaultKind {
    /// `ThresholdSign` (`Coin`) received a signature share from an unverified sender.
    #[fail(
        display = "`ThresholdSign` (`Coin`) received a signature share from an unverified sender."
    )]
    UnverifiedSignatureShareSender,
    /// `HoneyBadger` received a signatures share for the random value even though it is disabled.
    #[fail(
        display = "`HoneyBadger` received a signatures share for the random value even though it
                   is disabled."
    )]
    UnexpectedSignatureShare,
}

/// A threshold signing message, containing a signature share.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Rand)]
pub struct Message(pub SignatureShare);

/// A threshold signing algorithm instance. On input, broadcasts our threshold signature share. Upon
/// receiving at least `num_faulty + 1` shares, attempts to combine them into a signature. If that
/// signature is valid, the instance outputs it and terminates; otherwise the instance aborts.
#[derive(Debug)]
pub struct ThresholdSign<N> {
    netinfo: Arc<NetworkInfo<N>>,
    /// The hash of the document to be signed.
    doc_hash: Option<G2>,
    /// All received threshold signature shares, together with the node index.
    received_shares: BTreeMap<N, (usize, SignatureShare)>,
    /// Whether we already sent our shares.
    had_input: bool,
    /// Termination flag.
    terminated: bool,
}

/// A step returned from `ThresholdSign`. It contains at most one output.
pub type Step<N> = crate::DaStep<ThresholdSign<N>>;

impl<N: NodeIdT> DistAlgorithm for ThresholdSign<N> {
    type NodeId = N;
    type Input = ();
    type Output = Signature;
    type Message = Message;
    type Error = Error;
    type FaultKind = FaultKind;

    /// Sends our threshold signature share if not yet sent.
    fn handle_input<R: Rng>(&mut self, _input: (), _rng: &mut R) -> Result<Step<N>> {
        self.sign()
    }

    /// Receives input from a remote node.
    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &Self::NodeId,
        message: Message,
        _rng: &mut R,
    ) -> Result<Step<N>> {
        self.handle_message(sender_id, message)
    }

    /// Whether the algorithm has terminated.
    fn terminated(&self) -> bool {
        self.terminated
    }

    fn our_id(&self) -> &Self::NodeId {
        self.netinfo.our_id()
    }
}

impl<N: NodeIdT> ThresholdSign<N> {
    /// Creates a new instance of `ThresholdSign`, with the goal to collaboratively sign `doc`.
    pub fn new(netinfo: Arc<NetworkInfo<N>>) -> Self {
        ThresholdSign {
            netinfo,
            doc_hash: None,
            received_shares: BTreeMap::new(),
            had_input: false,
            terminated: false,
        }
    }

    /// Creates a new instance of `ThresholdSign`, including setting the document to sign.
    pub fn new_with_document<M: AsRef<[u8]>>(netinfo: Arc<NetworkInfo<N>>, doc: M) -> Result<Self> {
        let mut ts = ThresholdSign::new(netinfo);
        ts.set_document(doc)?;
        Ok(ts)
    }

    /// Sets doc_hash. Signature shares can only be sent after this function is completed.
    pub fn set_document<M: AsRef<[u8]>>(&mut self, doc: M) -> Result<()> {
        if self.doc_hash.is_some() {
            return Err(Error::MultipleMessagesToSign);
        }
        self.doc_hash = Some(hash_g2(doc));
        Ok(())
    }

    /// Sends our signature shares, and if we have collected enough, returns the full signature.
    /// Returns an error if the message to sign hasn't been received yet.
    pub fn sign(&mut self) -> Result<Step<N>> {
        if self.had_input {
            // Don't waste time on redundant shares.
            return Ok(Step::default());
        }
        let hash = self.doc_hash.ok_or(Error::DocumentHashIsNone)?;
        self.had_input = true;
        let mut step = Step::default();
        step.fault_log.extend(self.remove_invalid_shares());
        let msg = match self.netinfo.secret_key_share() {
            Some(sks) => Message(sks.sign_g2(hash)),
            None => return Ok(step.join(self.try_output()?)), // Not a validator.
        };
        step.messages.push(Target::All.message(msg.clone()));
        let id = self.our_id().clone();
        step.extend(self.handle_message(&id, msg)?);
        Ok(step)
    }

    /// Handles a message with a signature share received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    ///
    /// If we have collected enough, returns the full signature.
    pub fn handle_message(&mut self, sender_id: &N, message: Message) -> Result<Step<N>> {
        if self.terminated {
            return Ok(Step::default());
        }
        let Message(share) = message;
        // Before checking the share, ensure the sender is a known validator
        let idx = self
            .netinfo
            .node_index(sender_id)
            .ok_or(Error::UnknownSender)?;
        if !self.is_share_valid(sender_id, &share) {
            let fault_kind = FaultKind::UnverifiedSignatureShareSender;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }
        self.received_shares.insert(sender_id.clone(), (idx, share));
        self.try_output()
    }

    /// Removes all shares that are invalid, and returns faults for their senders.
    fn remove_invalid_shares(&mut self) -> FaultLog<N, FaultKind> {
        let faulty_senders: Vec<N> = self
            .received_shares
            .iter()
            .filter(|(id, (_, ref share))| !self.is_share_valid(id, share))
            .map(|(id, _)| id.clone())
            .collect();
        let mut fault_log = FaultLog::default();
        for id in faulty_senders {
            self.received_shares.remove(&id);
            fault_log.append(id, FaultKind::UnverifiedSignatureShareSender);
        }
        fault_log
    }

    /// Returns `true` if the share is valid, or if we don't have the message data yet.
    fn is_share_valid(&self, id: &N, share: &SignatureShare) -> bool {
        let hash = match self.doc_hash {
            None => return true, // No document yet. Verification postponed.
            Some(ref doc_hash) => doc_hash,
        };
        match self.netinfo.public_key_share(id) {
            None => false, // Unknown sender.
            Some(pk_i) => pk_i.verify_g2(&share, *hash),
        }
    }

    fn try_output(&mut self) -> Result<Step<N>> {
        let hash = match self.doc_hash {
            Some(hash) => hash,
            None => return Ok(Step::default()),
        };
        if !self.terminated && self.received_shares.len() > self.netinfo.num_faulty() {
            let sig = self.combine_and_verify_sig(hash)?;
            self.terminated = true;
            let step = self.sign()?; // Before terminating, make sure we sent our share.
            debug!("{} output {:?}", self, sig);
            Ok(step.with_output(sig))
        } else {
            debug!(
                "{} received {} shares, {}",
                self,
                self.received_shares.len(),
                if self.had_input { ", had input" } else { "" }
            );
            Ok(Step::default())
        }
    }

    fn combine_and_verify_sig(&self, hash: G2) -> Result<Signature> {
        // Pass the indices of sender nodes to `combine_signatures`.
        let shares_itr = self
            .received_shares
            .values()
            .map(|&(ref idx, ref share)| (idx, share));
        let sig = self
            .netinfo
            .public_key_set()
            .combine_signatures(shares_itr)
            .map_err(Error::CombineAndVerifySigCrypto)?;
        if !self
            .netinfo
            .public_key_set()
            .public_key()
            .verify_g2(&sig, hash)
        {
            Err(Error::VerificationFailed)
        } else {
            Ok(sig)
        }
    }
}

impl<N: NodeIdT> fmt::Display for ThresholdSign<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{:?} TS({:?})", self.our_id(), self.doc_hash)
    }
}
