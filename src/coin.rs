//! # A Cryptographic Coin
//!
//! The Coin produces a pseudorandom binary value that the correct nodes agree on, and that
//! cannot be known beforehand.
//!
//! Every Coin instance has a _nonce_ that determines the value, without giving it away: It
//! is not feasible to compute the output from the nonce alone, and the output is uniformly
//! distributed.
//!
//! The nodes input a signal (no data, just `()`), and after _2 f + 1_ nodes have provided input,
//! everyone receives the output value. In particular, the adversary cannot know the output value
//! before at least one correct node has provided input.
//!
//! ## How it works
//!
//! The algorithm uses a threshold signature scheme with the uniqueness property: For each public
//! key and message, there is exactly one valid signature. This group signature is produced using
//! signature shares from any combination of _2 f + 1_ secret key share holders.
//!
//! * On input, a node signs the nonce and sends its signature share to everyone else.
//! * When a node has received _2 f + 1_ shares, it computes the main signature and outputs the XOR
//! of its bits.

use std::collections::BTreeMap;
use std::sync::Arc;

use crypto::{self, hash_g2, Signature, SignatureShare, G2};
use fault_log::{Fault, FaultKind};
use {DistAlgorithm, NetworkInfo, NodeIdT, Target};

/// A coin error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "CombineAndVerifySigCrypto error: {}", _0)]
    CombineAndVerifySigCrypto(crypto::error::Error),
    #[fail(display = "Unknown sender")]
    UnknownSender,
    #[fail(display = "Signature verification failed")]
    VerificationFailed,
}

/// A coin result.
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

/// A coin algorithm instance. On input, broadcasts our threshold signature share. Upon
/// receiving at least `num_faulty + 1` shares, attempts to combine them into a signature. If that
/// signature is valid, the instance outputs it and terminates; otherwise the instance aborts.
#[derive(Debug)]
pub struct Coin<N> {
    netinfo: Arc<NetworkInfo<N>>,
    /// The name of this coin. It is required to be unique for each coin round.
    msg_hash: G2,
    /// All received threshold signature shares.
    received_shares: BTreeMap<N, SignatureShare>,
    /// Whether we provided input to the coin.
    had_input: bool,
    /// Termination flag.
    terminated: bool,
}

pub type Step<N> = ::Step<Coin<N>>;

impl<N: NodeIdT> DistAlgorithm for Coin<N> {
    type NodeId = N;
    type Input = ();
    type Output = Signature;
    type Message = Message;
    type Error = Error;

    /// Sends our threshold signature share if not yet sent.
    fn handle_input(&mut self, _input: Self::Input) -> Result<Step<N>> {
        self.get_coin()
    }

    /// Receives input from a remote node.
    fn handle_message(
        &mut self,
        sender_id: &Self::NodeId,
        message: Self::Message,
    ) -> Result<Step<N>> {
        if !self.terminated {
            let Message(share) = message;
            self.handle_share(sender_id, share)
        } else {
            Ok(Step::default())
        }
    }

    /// Whether the algorithm has terminated.
    fn terminated(&self) -> bool {
        self.terminated
    }

    fn our_id(&self) -> &Self::NodeId {
        self.netinfo.our_id()
    }
}

impl<N: NodeIdT> Coin<N> {
    pub fn new<M: AsRef<[u8]>>(netinfo: Arc<NetworkInfo<N>>, msg: M) -> Self {
        Coin {
            netinfo,
            msg_hash: hash_g2(msg),
            received_shares: BTreeMap::new(),
            had_input: false,
            terminated: false,
        }
    }

    fn get_coin(&mut self) -> Result<Step<N>> {
        if self.had_input {
            return Ok(Step::default());
        }
        self.had_input = true;
        if !self.netinfo.is_validator() {
            return self.try_output();
        }
        let share = self.netinfo.secret_key_share().sign_g2(self.msg_hash);
        let mut step: Step<_> = Target::All.message(Message(share.clone())).into();
        let id = self.netinfo.our_id().clone();
        step.extend(self.handle_share(&id, share)?);
        Ok(step)
    }

    fn handle_share(&mut self, sender_id: &N, share: SignatureShare) -> Result<Step<N>> {
        if let Some(pk_i) = self.netinfo.public_key_share(sender_id) {
            if !pk_i.verify_g2(&share, self.msg_hash) {
                // Log the faulty node and ignore the invalid share.
                let fault_kind = FaultKind::UnverifiedSignatureShareSender;
                return Ok(Fault::new(sender_id.clone(), fault_kind).into());
            }
            self.received_shares.insert(sender_id.clone(), share);
        } else {
            return Err(Error::UnknownSender);
        }
        self.try_output()
    }

    fn try_output(&mut self) -> Result<Step<N>> {
        debug!(
            "{:?} received {} shares, had_input = {}",
            self.netinfo.our_id(),
            self.received_shares.len(),
            self.had_input
        );
        if self.had_input && self.received_shares.len() > self.netinfo.num_faulty() {
            let sig = self.combine_and_verify_sig()?;
            debug!("{:?} output {:?}", self.netinfo.our_id(), sig);
            self.terminated = true;
            let step = self.handle_input(())?; // Before terminating, make sure we sent our share.
            Ok(step.with_output(sig))
        } else {
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
            .verify_g2(&sig, self.msg_hash)
        {
            // Abort
            error!(
                "{:?} main public key verification failed",
                self.netinfo.our_id()
            );
            Err(Error::VerificationFailed)
        } else {
            Ok(sig)
        }
    }
}
