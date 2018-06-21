//! Common coin from a given set of keys based on a `pairing` threshold signature scheme.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::rc::Rc;

use pairing::bls12_381::Bls12;

use crypto::error as cerror;
use crypto::Signature;
use messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};

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

#[cfg_attr(feature = "serialization-serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct CommonCoinMessage(Signature<Bls12>);

impl CommonCoinMessage {
    pub fn new(sig: Signature<Bls12>) -> Self {
        CommonCoinMessage(sig)
    }

    pub fn to_sig(&self) -> &Signature<Bls12> {
        &self.0
    }
}

/// A common coin algorithm instance. On input, broadcasts our threshold signature share. Upon
/// receiving at least `num_faulty + 1` shares, attempts to combine them into a signature. If that
/// signature is valid, the instance outputs it and terminates; otherwise the instance aborts.
#[derive(Debug)]
pub struct CommonCoin<NodeUid, T>
where
    NodeUid: Eq + Hash,
{
    netinfo: Rc<NetworkInfo<NodeUid>>,
    /// The name of this common coin. It is required to be unique for each common coin round.
    nonce: T,
    /// The result of combination of at least `num_faulty + 1` threshold signature shares.
    output: Option<bool>,
    /// Outgoing message queue.
    messages: VecDeque<CommonCoinMessage>,
    /// All received threshold signature shares.
    received_shares: BTreeMap<NodeUid, Signature<Bls12>>,
    /// Whether we provided input to the common coin.
    had_input: bool,
    /// Termination flag.
    terminated: bool,
}

impl<NodeUid, T> DistAlgorithm for CommonCoin<NodeUid, T>
where
    NodeUid: Clone + Debug + Hash + Ord,
    T: Clone + AsRef<[u8]>,
{
    type NodeUid = NodeUid;
    type Input = ();
    type Output = bool;
    type Message = CommonCoinMessage;
    type Error = Error;

    /// Sends our threshold signature share if not yet sent.
    fn input(&mut self, _input: Self::Input) -> Result<()> {
        if !self.had_input {
            self.had_input = true;
            self.get_coin()
        } else {
            Ok(())
        }
    }

    /// Receives input from a remote node.
    fn handle_message(&mut self, sender_id: &Self::NodeUid, message: Self::Message) -> Result<()> {
        if self.terminated {
            return Ok(());
        }
        let CommonCoinMessage(share) = message;
        self.handle_share(sender_id, share)
    }

    /// Takes the next share of a threshold signature message for multicasting to all other nodes.
    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, Self::NodeUid>> {
        self.messages
            .pop_front()
            .map(|msg| Target::All.message(msg))
    }

    /// Consumes the output. Once consumed, the output stays `None` forever.
    fn next_output(&mut self) -> Option<Self::Output> {
        self.output.take()
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
    NodeUid: Clone + Debug + Hash + Ord,
    T: Clone + AsRef<[u8]>,
{
    pub fn new(netinfo: Rc<NetworkInfo<NodeUid>>, nonce: T) -> Self {
        CommonCoin {
            netinfo,
            nonce,
            output: None,
            messages: VecDeque::new(),
            received_shares: BTreeMap::new(),
            had_input: false,
            terminated: false,
        }
    }

    fn get_coin(&mut self) -> Result<()> {
        let share = self.netinfo.secret_key().sign(&self.nonce);
        self.messages.push_back(CommonCoinMessage(share.clone()));
        let id = self.netinfo.our_uid().clone();
        self.handle_share(&id, share)
    }

    fn handle_share(&mut self, sender_id: &NodeUid, share: Signature<Bls12>) -> Result<()> {
        if let Some(i) = self.netinfo.node_index(sender_id) {
            let pk_i = self.netinfo.public_key_set().public_key_share(*i as u64);
            if !pk_i.verify(&share, &self.nonce) {
                // Silently ignore the invalid share.
                return Ok(());
            }
            self.received_shares.insert(sender_id.clone(), share);
            let received_shares = &self.received_shares;
            if self.had_input && received_shares.len() > self.netinfo.num_faulty() {
                let sig = self.combine_and_verify_sig()?;
                // Output the parity of the verified signature.
                let parity = sig.parity();
                self.output = Some(parity);
                self.terminated = true;
            }
            Ok(())
        } else {
            Err(ErrorKind::UnknownSender.into())
        }
    }

    fn combine_and_verify_sig(&self) -> Result<Signature<Bls12>> {
        // Pass the indices of sender nodes to `combine_signatures`.
        let ids_shares: BTreeMap<&NodeUid, &Signature<Bls12>> =
            self.received_shares.iter().collect();
        let ids_u64: BTreeMap<&NodeUid, u64> = ids_shares
            .keys()
            .map(|&id| (id, *self.netinfo.node_index(id).unwrap() as u64))
            .collect();
        // Convert indices to `u64` which is an interface type for `pairing`.
        let shares: BTreeMap<&u64, &Signature<Bls12>> = ids_shares
            .iter()
            .map(|(id, &share)| (&ids_u64[id], share))
            .collect();
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
