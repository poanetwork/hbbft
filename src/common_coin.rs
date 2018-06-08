//! Common coin from a given set of keys based on a `pairing` threshold signature scheme.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;
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
        NotImplemented {
            description("not implemented")
        }
    }
}

#[cfg_attr(feature = "serialization-serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum CommonCoinMessage {
    Share(Signature<Bls12>),
}

/// A common coin algorithm instance. On input, broadcasts our threshold signature share. Upon
/// receiving at least `num_faulty + 1` shares, attempts to combine them into a signature. If that
/// signature is valid, the instance outputs it and terminates; otherwise the instance aborts.
#[derive(Debug)]
pub struct CommonCoin<N, T>
where
    N: Debug,
{
    netinfo: Rc<NetworkInfo<N>>,
    /// The name of this common coin. It is required to be unique for each common coin round.
    nonce: T,
    /// The result of combination of at least `num_faulty + 1` threshold signature shares.
    output: Option<bool>,
    /// Outgoing message queue.
    messages: VecDeque<CommonCoinMessage>,
    /// All received threshold signature shares.
    received_shares: BTreeMap<N, Signature<Bls12>>,
    /// Termination flag.
    terminated: bool,
}

impl<N, T> DistAlgorithm for CommonCoin<N, T>
where
    N: Clone + Debug + Ord,
    T: Clone + AsRef<[u8]>,
{
    type NodeUid = N;
    type Input = ();
    type Output = bool;
    type Message = CommonCoinMessage;
    type Error = Error;

    /// Sends our threshold signature share if not yet sent.
    fn input(&mut self, _input: Self::Input) -> Result<()> {
        let share_sent = self.received_shares.keys().fold(false, |result, k| {
            if !result && k == self.netinfo.our_uid() {
                true
            } else {
                result
            }
        });
        if !share_sent {
            self.get_coin()
        } else {
            Ok(())
        }
    }

    /// Receives input from a remote node.
    fn handle_message(&mut self, sender_id: &Self::NodeUid, message: Self::Message) -> Result<()> {
        // FIXME
        let CommonCoinMessage::Share(share) = message;
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

impl<N, T> CommonCoin<N, T>
where
    N: Clone + Debug + Ord,
    T: Clone + AsRef<[u8]>,
{
    pub fn new(netinfo: Rc<NetworkInfo<N>>, nonce: T) -> Self {
        CommonCoin {
            netinfo,
            nonce,
            output: None,
            messages: VecDeque::new(),
            received_shares: BTreeMap::new(),
            terminated: false,
        }
    }

    fn get_coin(&mut self) -> Result<()> {
        let share = self.netinfo.secret_key().sign(&self.nonce);
        self.messages
            .push_back(CommonCoinMessage::Share(share.clone()));
        let id = self.netinfo.our_uid().clone();
        self.handle_share(&id, share)
    }

    fn handle_share(&mut self, sender_id: &N, share: Signature<Bls12>) -> Result<()> {
        let node_indices = self.netinfo.node_indices();
        if let Some(i) = node_indices.get(sender_id) {
            let pk_i = self.netinfo.public_key_set().public_key_share(*i);
            if !pk_i.verify(&share, &self.nonce) {
                // Silently ignore the invalid share.
                return Ok(());
            }

            self.received_shares.insert(sender_id.clone(), share);
            let received_shares = &self.received_shares;
            if received_shares.len() > self.netinfo.num_faulty() {
                // Pass the indices of sender nodes to `combine_signatures`.
                let shares: BTreeMap<&u64, &Signature<Bls12>> = self
                    .netinfo
                    .all_uids()
                    .iter()
                    .map(|id| (&node_indices[id], received_shares.get(id)))
                    .filter(|(_, share)| share.is_some())
                    .map(|(n, share)| (n, share.unwrap()))
                    .collect();
                let sig = self.netinfo.public_key_set().combine_signatures(shares)?;
                // Verify the successfully combined signature with the main public key.
                if self
                    .netinfo
                    .public_key_set()
                    .public_key()
                    .verify(&sig, &self.nonce)
                {
                    // Output the parity of the verified signature.
                    self.output = Some(sig.parity());
                    self.terminated = true;
                } else {
                    // Abort
                    self.terminated = true;
                }
            }
            Ok(())
        } else {
            Err(ErrorKind::UnknownSender.into())
        }
    }
}
