//! # Collaborative Threshold Signing
//!
//! The algorithm is instantiated with data to sign, and waits for the input (no data, just `()`),
//! then sends a signature share to the others. When at least _f + 1_ correct validators have done
//! so, each node outputs the same, valid signature of the data.
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

use crypto::{self, hash_g2, Signature, SignatureShare, G2};
use failure::Fail;
use log::debug;
use rand_derive::Rand;
use serde_derive::{Deserialize, Serialize};

use fault_log::{Fault, FaultKind, FaultLog};
use {DistAlgorithm, NetworkInfo, NodeIdT, Target};

/// A threshold signing error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "Redundant input provided")]
    MultipleMessagesToSign,
    #[fail(display = "CombineAndVerifySigCrypto error: {}", _0)]
    CombineAndVerifySigCrypto(crypto::error::Error),
    #[fail(display = "Unknown sender")]
    UnknownSender,
    #[fail(display = "Signature verification failed")]
    VerificationFailed,
}

/// A threshold signing result.
pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Rand)]
pub struct Message(SignatureShare);

impl Message {
    pub fn new(sig: SignatureShare) -> Self {
        Message(sig)
    }

    pub fn to_sig(&self) -> &SignatureShare {
        &self.0
    }
}

/// A threshold signing algorithm instance. On input, broadcasts our threshold signature share. Upon
/// receiving at least `num_faulty + 1` shares, attempts to combine them into a signature. If that
/// signature is valid, the instance outputs it and terminates; otherwise the instance aborts.
#[derive(Debug)]
pub struct ThresholdSign<N> {
    netinfo: Arc<NetworkInfo<N>>,
    /// The hash of the data to be signed.
    msg_hash: Option<G2>,
    /// All received threshold signature shares.
    received_shares: BTreeMap<N, SignatureShare>,
    /// Whether we already sent our shares.
    had_input: bool,
    /// Termination flag.
    terminated: bool,
}

pub type Step<N> = ::Step<ThresholdSign<N>>;

impl<N: NodeIdT> DistAlgorithm for ThresholdSign<N> {
    type NodeId = N;
    type Input = ();
    type Output = Signature;
    type Message = Message;
    type Error = Error;

    /// Sends our threshold signature share if not yet sent.
    fn handle_input(&mut self, _input: ()) -> Result<Step<N>> {
        self.sign()
    }

    /// Receives input from a remote node.
    fn handle_message(&mut self, sender_id: &N, message: Message) -> Result<Step<N>> {
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
    /// Creates a new instance of `ThresholdSign`, with the goal to collaboratively sign `msg`.
    pub fn new(netinfo: Arc<NetworkInfo<N>>) -> Self {
        ThresholdSign {
            netinfo,
            msg_hash: None,
            received_shares: BTreeMap::new(),
            had_input: false,
            terminated: false,
        }
    }

    /// Sets msg_hash and resets internal state accordingly.
    pub fn set_message<M: AsRef<[u8]>>(&mut self, msg: M) -> Result<()> {
        if self.msg_hash.is_some() {
            return Err(Error::MultipleMessagesToSign);
        }
        self.msg_hash = Some(hash_g2(msg));
        Ok(())
    }

    /// Sends our signature shares, and if we have collected enough, returns the full signature.
    /// Returns an empty step if the message to sign hasn't been received yet.
    pub fn sign(&mut self) -> Result<Step<N>> {
        if self.had_input || self.msg_hash.is_none() {
            return Ok(Step::default());
        }
        self.had_input = true;
        let mut step = Step::default();
        step.fault_log.extend(self.remove_invalid_shares());
        if !self.netinfo.is_validator() {
            return self.try_output();
        }
        let msg = Message(
            self.netinfo
                .secret_key_share()
                .sign_g2(self.msg_hash.unwrap()),
        );
        let mut step: Step<_> = Target::All.message(msg.clone()).into();
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
        self.netinfo.public_key_share(sender_id).ok_or(Error::UnknownSender)?;
        if !self.is_share_valid(sender_id, &share) {
            let fault_kind = FaultKind::UnverifiedSignatureShareSender;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        } else {
            self.received_shares.insert(sender_id.clone(), share);
        }
        self.received_shares.insert(sender_id.clone(), share);
        self.try_output()
    }

    /// Removes all shares that are invalid, and returns faults for their senders.
    fn remove_invalid_shares(&mut self) -> FaultLog<N> {
        let faulty_senders: Vec<N> = self
            .received_shares
            .iter()
            .filter(|(id, share)| !self.is_share_valid(id, share))
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
        let msg = match self.msg_hash {
            None => return true, // No data yet. Verification postponed.
            Some(ref msg_hash) => msg_hash,
        };
        match self.netinfo.public_key_share(id) {
            None => false, // Unknown sender.
            Some(pk_i) => pk_i.verify_g2(&share, *msg),
        }
    }

    fn try_output(&mut self) -> Result<Step<N>> {
        if self.had_input && self.received_shares.len() > self.netinfo.num_faulty() {
            let sig = self.combine_and_verify_sig()?;
            let step = self.sign()?; // Before terminating, make sure we sent our share.
            debug!("{} output {:?}", self, sig);
            self.terminated = true;
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

    fn combine_and_verify_sig(&self) -> Result<Signature> {
        // Pass the indices of sender nodes to `combine_signatures`.
        let to_idx = |(id, share)| (self.netinfo.node_index(id).unwrap(), share);
        let shares = self.received_shares.iter().map(to_idx);
        let sig = self
            .netinfo
            .public_key_set()
            .combine_signatures(shares)
            .map_err(Error::CombineAndVerifySigCrypto)?;
        if !self
            .netinfo
            .public_key_set()
            .public_key()
            .verify_g2(&sig, self.msg_hash.unwrap())
        {
            Err(Error::VerificationFailed)
        } else {
            Ok(sig)
        }
    }
}

impl<N: NodeIdT> fmt::Display for ThresholdSign<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{:?} TS({:?})", self.our_id(), self.msg_hash)
    }
}
