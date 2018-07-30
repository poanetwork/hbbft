//! # A Cryptographic Common Coin
//!
//! The Common Coin produces a pseudorandom binary value that the correct nodes agree on, and that
//! cannot be known beforehand.
//!
//! Every Common Coin instance has a _nonce_ that determines the value, without giving it away: It
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
use std::fmt::Debug;
use std::sync::Arc;

use crypto::error as cerror;
use crypto::{Signature, SignatureShare};
use fault_log::{Fault, FaultKind};
use messaging::{self, DistAlgorithm, NetworkInfo, Target};

error_chain! {
    links {
        Crypto(cerror::Error, cerror::ErrorKind);
    }

    errors {
        UnknownSender {
            description("unknown sender")
        }
        VerificationFailed {
            description("signature verification failed")
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Rand)]
pub struct CommonCoinMessage(SignatureShare);

impl CommonCoinMessage {
    pub fn new(sig: SignatureShare) -> Self {
        CommonCoinMessage(sig)
    }

    pub fn to_sig(&self) -> &SignatureShare {
        &self.0
    }
}

/// A common coin algorithm instance. On input, broadcasts our threshold signature share. Upon
/// receiving at least `num_faulty + 1` shares, attempts to combine them into a signature. If that
/// signature is valid, the instance outputs it and terminates; otherwise the instance aborts.
#[derive(Debug)]
pub struct CommonCoin<NodeUid, T> {
    netinfo: Arc<NetworkInfo<NodeUid>>,
    /// The name of this common coin. It is required to be unique for each common coin round.
    nonce: T,
    /// All received threshold signature shares.
    received_shares: BTreeMap<NodeUid, SignatureShare>,
    /// Whether we provided input to the common coin.
    had_input: bool,
    /// Termination flag.
    terminated: bool,
}

pub type Step<NodeUid, T> = messaging::Step<CommonCoin<NodeUid, T>>;

impl<NodeUid, T> DistAlgorithm for CommonCoin<NodeUid, T>
where
    NodeUid: Clone + Debug + Ord,
    T: Clone + AsRef<[u8]>,
{
    type NodeUid = NodeUid;
    type Input = ();
    type Output = bool;
    type Message = CommonCoinMessage;
    type Error = Error;

    /// Sends our threshold signature share if not yet sent.
    fn input(&mut self, _input: Self::Input) -> Result<Step<NodeUid, T>> {
        if !self.had_input {
            self.had_input = true;
            self.get_coin()
        } else {
            Ok(Step::default())
        }
    }

    /// Receives input from a remote node.
    fn handle_message(
        &mut self,
        sender_id: &Self::NodeUid,
        message: Self::Message,
    ) -> Result<Step<NodeUid, T>> {
        if !self.terminated {
            let CommonCoinMessage(share) = message;
            self.handle_share(sender_id, share)
        } else {
            Ok(Step::default())
        }
    }

    /// Whether the algorithm has terminated.
    fn terminated(&self) -> bool {
        self.terminated
    }

    fn our_id(&self) -> &Self::NodeUid {
        self.netinfo.our_uid()
    }
}

impl<NodeUid, T> CommonCoin<NodeUid, T>
where
    NodeUid: Clone + Debug + Ord,
    T: Clone + AsRef<[u8]>,
{
    pub fn new(netinfo: Arc<NetworkInfo<NodeUid>>, nonce: T) -> Self {
        CommonCoin {
            netinfo,
            nonce,
            received_shares: BTreeMap::new(),
            had_input: false,
            terminated: false,
        }
    }

    fn get_coin(&mut self) -> Result<Step<NodeUid, T>> {
        if !self.netinfo.is_validator() {
            return self.try_output();
        }
        let share = self.netinfo.secret_key_share().sign(&self.nonce);
        let mut step: Step<_, _> = Target::All.message(CommonCoinMessage(share.clone())).into();
        let id = self.netinfo.our_uid().clone();
        step.extend(self.handle_share(&id, share)?);
        Ok(step)
    }

    fn handle_share(
        &mut self,
        sender_id: &NodeUid,
        share: SignatureShare,
    ) -> Result<Step<NodeUid, T>> {
        if let Some(pk_i) = self.netinfo.public_key_share(sender_id) {
            if !pk_i.verify(&share, &self.nonce) {
                // Log the faulty node and ignore the invalid share.
                let fault_kind = FaultKind::UnverifiedSignatureShareSender;
                return Ok(Fault::new(sender_id.clone(), fault_kind).into());
            }
            self.received_shares.insert(sender_id.clone(), share);
        } else {
            return Err(ErrorKind::UnknownSender.into());
        }
        self.try_output()
    }

    fn try_output(&mut self) -> Result<Step<NodeUid, T>> {
        debug!(
            "{:?} received {} shares, had_input = {}",
            self.netinfo.our_uid(),
            self.received_shares.len(),
            self.had_input
        );
        if self.had_input && self.received_shares.len() > self.netinfo.num_faulty() {
            let sig = self.combine_and_verify_sig()?;
            // Output the parity of the verified signature.
            let parity = sig.parity();
            debug!("{:?} output {}", self.netinfo.our_uid(), parity);
            self.terminated = true;
            let step = self.input(())?; // Before terminating, make sure we sent our share.
            Ok(step.with_output(parity))
        } else {
            Ok(Step::default())
        }
    }

    fn combine_and_verify_sig(&self) -> Result<Signature> {
        // Pass the indices of sender nodes to `combine_signatures`.
        let to_idx = |(id, share)| (self.netinfo.node_index(id).unwrap(), share);
        let shares = self.received_shares.iter().map(to_idx);
        let sig = self.netinfo.public_key_set().combine_signatures(shares)?;
        if !self
            .netinfo
            .public_key_set()
            .public_key()
            .verify(&sig, &self.nonce)
        {
            // Abort
            error!(
                "{:?} main public key verification failed",
                self.netinfo.our_uid()
            );
            Err(ErrorKind::VerificationFailed.into())
        } else {
            Ok(sig)
        }
    }
}
