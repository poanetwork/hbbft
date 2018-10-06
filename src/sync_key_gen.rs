//! A _synchronous_ algorithm for dealerless distributed key generation.
//!
//! This protocol is meant to run in a _completely synchronous_ setting where each node handles all
//! messages in the same order. It can e.g. exchange messages as transactions on top of
//! `HoneyBadger`, or it can run "on-chain", i.e. committing its messages to a blockchain.
//!
//! Its messages are encrypted where necessary, so they can be publicly broadcast.
//!
//! When the protocol completes, every node receives a secret key share suitable for threshold
//! signatures and encryption. The secret master key is not known by anyone. The protocol succeeds
//! if up to _t_ nodes are faulty, where _t_ is the `threshold` parameter. The number of nodes must
//! be at least _2 t + 1_.
//!
//! ## Usage
//!
//! Before beginning the threshold key generation process, each validator needs to generate a
//! regular (non-threshold) key pair and multicast its public key. `SyncKeyGen::new` returns the
//! instance itself and a `Part` message, containing a contribution to the new threshold keys.
//! It needs to be sent to all nodes. `SyncKeyGen::handle_part` in turn produces an `Ack`
//! message, which is also multicast.
//!
//! All nodes must handle the exact same set of `Part` and `Ack` messages. In this sense the
//! algorithm is synchronous: If Alice's `Ack` was handled by Bob but not by Carol, Bob and
//! Carol could receive different public key sets, and secret key shares that don't match. One way
//! to ensure this is to commit the messages to a public ledger before handling them, e.g. by
//! feeding them to a preexisting instance of Honey Badger. The messages will then appear in the
//! same order for everyone.
//!
//! To complete the process, call `SyncKeyGen::generate`. It produces your secret key share and the
//! public key set.
//!
//! While not asynchronous, the algorithm is fault tolerant: It is not necessary to handle a
//! `Part` and all `Ack` messages from every validator. A `Part` is _complete_ if it
//! received at least _2 t + 1_ valid `Ack`s. Only complete `Part`s are used for key
//! generation in the end, and as long as at least one complete `Part` is from a correct node,
//! the new key set is secure. You can use `SyncKeyGen::is_ready` to check whether at least
//! _t + 1_ `Part`s are complete. So all nodes can call `generate` as soon as `is_ready` returns
//! `true`.
//!
//! Alternatively, you can use any stronger criterion, too, as long as all validators call
//! `generate` at the same point, i.e. after handling the same set of messages.
//! `SyncKeyGen::count_complete` returns the number of complete `Part` messages. And
//! `SyncKeyGen::is_node_ready` can be used to check whether a particluar node's `Part` is
//! complete.
//!
//! Finally, observer nodes can also use `SyncKeyGen`. For observers, no `Part` and `Ack`
//! messages will be created and they do not need to send anything. On completion, they will only
//! receive the public key set, but no secret key share.
//!
//! ## Example
//!
//! ```
//! extern crate rand;
//! extern crate hbbft;
//! extern crate threshold_crypto;
//!
//! use std::collections::BTreeMap;
//!
//! use threshold_crypto::{PublicKey, SecretKey, SignatureShare};
//! use hbbft::sync_key_gen::{PartOutcome, SyncKeyGen};
//!
//! // Use a default random number generator for any randomness:
//! let mut rng = rand::thread_rng();
//!
//! // Two out of four shares will suffice to sign or encrypt something.
//! let (threshold, node_num) = (1, 4);
//!
//! // Generate individual key pairs for encryption. These are not suitable for threshold schemes.
//! let sec_keys: Vec<SecretKey> = (0..node_num).map(|_| rand::random()).collect();
//! let pub_keys: BTreeMap<usize, PublicKey> = sec_keys
//!     .iter()
//!     .map(SecretKey::public_key)
//!     .enumerate()
//!     .collect();
//!
//! // Create the `SyncKeyGen` instances. The constructor also outputs the part that needs to
//! // be sent to all other participants, so we save the parts together with their sender ID.
//! let mut nodes = BTreeMap::new();
//! let mut parts = Vec::new();
//! for (id, sk) in sec_keys.into_iter().enumerate() {
//!     let (sync_key_gen, opt_part) = SyncKeyGen::new(&mut rng, id, sk, pub_keys.clone(), threshold)
//!         .unwrap_or_else(|_| panic!("Failed to create `SyncKeyGen` instance for node #{}", id));
//!     nodes.insert(id, sync_key_gen);
//!     parts.push((id, opt_part.unwrap())); // Would be `None` for observer nodes.
//! }
//!
//! // All nodes now handle the parts and send the resulting `Ack` messages.
//! let mut acks = Vec::new();
//! for (sender_id, part) in parts {
//!     for (&id, node) in &mut nodes {
//!         match node.handle_part(&mut rng, &sender_id, part.clone()) {
//!             Some(PartOutcome::Valid(ack)) => acks.push((id, ack)),
//!             Some(PartOutcome::Invalid(faults)) => panic!("Invalid part: {:?}", faults),
//!             None => panic!("We are not an observer, so we should send Ack."),
//!         }
//!     }
//! }
//!
//! // Finally, we handle all the `Ack`s.
//! for (sender_id, ack) in acks {
//!     for node in nodes.values_mut() {
//!         node.handle_ack(&sender_id, ack.clone());
//!     }
//! }
//!
//! // We have all the information and can generate the key sets.
//! // Generate the public key set; which is identical for all nodes.
//! let pub_key_set = nodes[&0].generate().expect("Failed to create `PublicKeySet` from node #0").0;
//! let mut secret_key_shares = BTreeMap::new();
//! for (&id, node) in &mut nodes {
//!     assert!(node.is_ready());
//!     let (pks, opt_sks) = node.generate().unwrap_or_else(|_|
//!         panic!("Failed to create `PublicKeySet` and `SecretKeyShare` for node #{}", id)
//!     );
//!     assert_eq!(pks, pub_key_set); // All nodes now know the public keys and public key shares.
//!     let sks = opt_sks.expect("Not an observer node: We receive a secret key share.");
//!     secret_key_shares.insert(id, sks);
//! }
//!
//! // Three out of four nodes can now sign a message. Each share can be verified individually.
//! let msg = "Nodes 0 and 1 does not agree with this.";
//! let mut sig_shares: BTreeMap<usize, SignatureShare> = BTreeMap::new();
//! for (&id, sks) in &secret_key_shares {
//!     if id != 0 && id != 1 {
//!         let sig_share = sks.sign(msg);
//!         let pks = pub_key_set.public_key_share(id);
//!         assert!(pks.verify(&sig_share, msg));
//!         sig_shares.insert(id, sig_share);
//!     }
//! }
//!
//! // Two signatures are over the threshold. They are enough to produce a signature that matches
//! // the public master key.
//! let sig = pub_key_set
//!     .combine_signatures(&sig_shares)
//!     .expect("The shares can be combined.");
//! assert!(pub_key_set.public_key().verify(&sig, msg));
//! ```
//!
//! ## How it works
//!
//! The algorithm is based on ideas from
//! [Distributed Key Generation in the Wild](https://eprint.iacr.org/2012/377.pdf) and
//! [A robust threshold elliptic curve digital signature providing a new verifiable secret sharing scheme](https://www.researchgate.net/profile/Ihab_Ali/publication/4205262_A_robust_threshold_elliptic_curve_digital_signature_providing_a_new_verifiable_secret_sharing_scheme/links/02e7e538f15726323a000000/A-robust-threshold-elliptic-curve-digital-signature-providing-a-new-verifiable-secret-sharing-scheme.pdf?origin=publication_detail).
//!
//! In a trusted dealer scenario, the following steps occur:
//!
//! 1. Dealer generates a `BivarPoly` of degree _t_ and publishes the `BivarCommitment` which is
//!    used to publicly verify the polynomial's values.
//! 2. Dealer sends _row_ _m > 0_ to node number _m_.
//! 3. Node _m_, in turn, sends _value_ number _s_ to node number _s_.
//! 4. This process continues until _2 t + 1_ nodes confirm they have received a valid row. If
//!    there are at most _t_ faulty nodes, we know that at least _t + 1_ correct nodes sent on an
//!    entry of every other node's column to that node.
//! 5. This means every node can reconstruct its column, and the value at _0_ of its column.
//! 6. These values all lie on a univariate polynomial of degree _t_ and can be used as secret keys.
//!
//! In our _dealerless_ environment, at least _t + 1_ nodes each generate a polynomial using the
//! method above. The sum of the secret keys we received from each node is then used as our secret
//! key. No single node knows the secret master key.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use bincode;
use crypto::{
    error::Error as CryptoError,
    poly::{BivarCommitment, BivarPoly, Poly},
    serde_impl::field_vec::FieldWrap,
    Ciphertext, PublicKey, PublicKeySet, SecretKey, SecretKeyShare,
};
use crypto::{Fr, G1Affine};
use pairing::{CurveAffine, Field};
use rand;

use fault_log::{AckMessageFault as Fault, FaultKind, FaultLog};
use {NetworkInfo, NodeIdT};

// TODO: No need to send our own row and value to ourselves.

// A sync-key-gen error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "Error creating SyncKeyGen: {}", _0)]
    Creation(CryptoError),
    #[fail(display = "Error generating keys: {}", _0)]
    Generation(CryptoError),
    #[fail(display = "Error acknowledging part: {}", _0)]
    Ack(CryptoError),
}

/// A submission by a validator for the key generation. It must to be sent to all participating
/// nodes and handled by all of them, including the one that produced it.
///
/// The message contains a commitment to a bivariate polynomial, and for each node, an encrypted
/// row of values. If this message receives enough `Ack`s, it will be used as summand to produce
/// the the key set in the end.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq)]
pub struct Part(BivarCommitment, Vec<Ciphertext>);

impl Debug for Part {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("Part")
            .field(&format!("<degree {}>", self.0.degree()))
            .field(&format!("<{} rows>", self.1.len()))
            .finish()
    }
}

/// A confirmation that we have received and verified a validator's part. It must be sent to
/// all participating nodes and handled by all of them, including ourselves.
///
/// The message is only produced after we verified our row against the commitment in the `Part`.
/// For each node, it contains one encrypted value of that row.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq)]
pub struct Ack(u64, Vec<Ciphertext>);

impl Debug for Ack {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("Ack")
            .field(&self.0)
            .field(&format!("<{} values>", self.1.len()))
            .finish()
    }
}

/// The information needed to track a single proposer's secret sharing process.
#[derive(Debug)]
struct ProposalState {
    /// The proposer's commitment.
    commit: BivarCommitment,
    /// The verified values we received from `Ack` messages.
    values: BTreeMap<u64, Fr>,
    /// The nodes which have acked this part, valid or not.
    acks: BTreeSet<u64>,
}

impl ProposalState {
    /// Creates a new part state with a commitment.
    fn new(commit: BivarCommitment) -> ProposalState {
        ProposalState {
            commit,
            values: BTreeMap::new(),
            acks: BTreeSet::new(),
        }
    }

    /// Returns `true` if at least `2 * threshold + 1` nodes have acked.
    fn is_complete(&self, threshold: usize) -> bool {
        self.acks.len() > 2 * threshold
    }
}

/// The outcome of handling and verifying a `Part` message.
pub enum PartOutcome<N: Clone> {
    /// The message was valid: the part of it that was encrypted to us matched the public
    /// commitment, so we can multicast an `Ack` message for it.
    Valid(Ack),
    // If the Part message passed to `handle_part()` is invalid, the
    // fault is logged and passed onto the caller.
    /// The message was invalid: the part encrypted to us was malformed or didn't match the
    /// commitment. We now know that the proposer is faulty, and dont' send an `Ack`.
    Invalid(FaultLog<N>),
}

/// A synchronous algorithm for dealerless distributed key generation.
///
/// It requires that all nodes handle all messages in the exact same order.
#[derive(Debug)]
pub struct SyncKeyGen<N> {
    /// Our node ID.
    our_id: N,
    /// Our node index.
    our_idx: Option<u64>,
    /// Our secret key.
    sec_key: SecretKey,
    /// The public keys of all nodes, by node index.
    pub_keys: BTreeMap<N, PublicKey>,
    /// Proposed bivariate polynomials.
    parts: BTreeMap<u64, ProposalState>,
    /// The degree of the generated polynomial.
    threshold: usize,
}

impl<N: NodeIdT> SyncKeyGen<N> {
    /// Creates a new `SyncKeyGen` instance, together with the `Part` message that should be
    /// multicast to all nodes.
    ///
    /// If we are not a validator but only an observer, no `Part` message is produced and no
    /// messages need to be sent.
    pub fn new<R: rand::Rng>(
        rng: &mut R,
        our_id: N,
        sec_key: SecretKey,
        pub_keys: BTreeMap<N, PublicKey>,
        threshold: usize,
    ) -> Result<(SyncKeyGen<N>, Option<Part>), Error> {
        let our_idx = pub_keys
            .keys()
            .position(|id| *id == our_id)
            .map(|idx| idx as u64);
        let key_gen = SyncKeyGen {
            our_id,
            our_idx,
            sec_key,
            pub_keys,
            parts: BTreeMap::new(),
            threshold,
        };
        if our_idx.is_none() {
            return Ok((key_gen, None)); // No part: we are an observer.
        }

        let our_part = BivarPoly::random(threshold, rng);
        let commit = our_part.commitment();
        let encrypt = |(i, pk): (usize, &PublicKey)| {
            let row = our_part.row(i + 1);
            let bytes = bincode::serialize(&row).expect("failed to serialize row");
            Ok(pk.encrypt_with_rng(rng, &bytes))
        };
        let rows = key_gen
            .pub_keys
            .values()
            .enumerate()
            .map(encrypt)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok((key_gen, Some(Part(commit, rows))))
    }

    /// Handles a `Part` message. If it is valid, returns an `Ack` message to be broadcast.
    ///
    /// If we are only an observer, `None` is returned instead and no messages need to be sent.
    ///
    /// All participating nodes must handle the exact same sequence of messages.
    /// Note that `handle_part` also needs to explicitly be called with this instance's own `Part`.
    pub fn handle_part<R: rand::Rng>(
        &mut self,
        rng: &mut R,
        sender_id: &N,
        Part(commit, rows): Part,
    ) -> Option<PartOutcome<N>> {
        let sender_idx = self.node_index(sender_id)?;
        let opt_commit_row = self.our_idx.map(|idx| commit.row(idx + 1));
        match self.parts.entry(sender_idx) {
            Entry::Occupied(_) => {
                debug!("Received multiple parts from node {:?}.", sender_id);
                return None;
            }
            Entry::Vacant(entry) => {
                entry.insert(ProposalState::new(commit));
            }
        }
        // If we are only an observer, return `None`. We don't need to send `Ack`.
        let our_idx = self.our_idx?;
        let commit_row = opt_commit_row?;
        let ser_row = self.sec_key.decrypt(rows.get(our_idx as usize)?)?;
        let row: Poly = if let Ok(row) = bincode::deserialize(&ser_row) {
            row
        } else {
            // Log the faulty node and ignore invalid messages.
            let fault_log = FaultLog::init(sender_id.clone(), FaultKind::InvalidPartMessage);
            return Some(PartOutcome::Invalid(fault_log));
        };
        if row.commitment() != commit_row {
            error!("Invalid part from node {:?}.", sender_id);
            let fault_log = FaultLog::init(sender_id.clone(), FaultKind::InvalidPartMessage);
            return Some(PartOutcome::Invalid(fault_log));
        }
        // The row is valid: now encrypt one value for each node.
        let encrypt = |(idx, pk): (usize, &PublicKey)| {
            let val = row.evaluate(idx + 1);
            let wrap = FieldWrap::new(val);
            // TODO: Handle errors.
            let ser_val = bincode::serialize(&wrap).expect("failed to serialize value");
            pk.encrypt_with_rng(rng, ser_val)
        };
        let values = self.pub_keys.values().enumerate().map(encrypt).collect();
        Some(PartOutcome::Valid(Ack(sender_idx, values)))
    }

    /// Handles an `Ack` message.
    ///
    /// All participating nodes must handle the exact same sequence of messages.
    /// Note that `handle_ack` also needs to explicitly be called with this instance's own `Ack`s.
    pub fn handle_ack(&mut self, sender_id: &N, ack: Ack) -> FaultLog<N> {
        let mut fault_log = FaultLog::new();
        if let Some(sender_idx) = self.node_index(sender_id) {
            if let Err(fault) = self.handle_ack_or_err(sender_idx, ack) {
                debug!("Invalid ack from node {:?}: {}", sender_id, fault);
                fault_log.append(sender_id.clone(), FaultKind::AckMessage(fault));
            }
        }
        fault_log
    }

    /// Returns the number of complete parts. If this is at least `threshold + 1`, the keys can
    /// be generated, but it is possible to wait for more to increase security.
    pub fn count_complete(&self) -> usize {
        self.parts
            .values()
            .filter(|part| part.is_complete(self.threshold))
            .count()
    }

    /// Returns `true` if the part of the given node is complete.
    pub fn is_node_ready(&self, proposer_id: &N) -> bool {
        self.node_index(proposer_id)
            .and_then(|proposer_idx| self.parts.get(&proposer_idx))
            .map_or(false, |part| part.is_complete(self.threshold))
    }

    /// Returns `true` if enough parts are complete to safely generate the new key.
    pub fn is_ready(&self) -> bool {
        self.count_complete() > self.threshold
    }

    /// Returns the new secret key share and the public key set.
    ///
    /// These are only secure if `is_ready` returned `true`. Otherwise it is not guaranteed that
    /// none of the nodes knows the secret master key.
    ///
    /// If we are only an observer node, no secret key share is returned.
    ///
    /// All participating nodes must have handled the exact same sequence of `Part` and `Ack`
    /// messages before calling this method. Otherwise their key shares will not match.
    pub fn generate(&self) -> Result<(PublicKeySet, Option<SecretKeyShare>), Error> {
        let mut pk_commit = Poly::zero().commitment();
        let mut opt_sk_val = self.our_idx.map(|_| Fr::zero());
        let is_complete = |part: &&ProposalState| part.is_complete(self.threshold);
        for part in self.parts.values().filter(is_complete) {
            pk_commit += part.commit.row(0);
            if let Some(sk_val) = opt_sk_val.as_mut() {
                let row = Poly::interpolate(part.values.iter().take(self.threshold + 1));
                sk_val.add_assign(&row.evaluate(0));
            }
        }
        let opt_sk = if let Some(mut fr) = opt_sk_val {
            let sk = SecretKeyShare::from_mut(&mut fr);
            Some(sk)
        } else {
            None
        };
        Ok((pk_commit.into(), opt_sk))
    }

    /// Consumes the instance, generates the key set and returns a new `NetworkInfo` with the new
    /// keys.
    ///
    /// All participating nodes must have handled the exact same sequence of `Part` and `Ack`
    /// messages before calling this method. Otherwise their key shares will not match.
    pub fn into_network_info(self) -> Result<NetworkInfo<N>, Error> {
        let (pk_set, opt_sk_share) = self.generate()?;
        let sk_share = opt_sk_share.unwrap_or_default(); // TODO: Make this an option.
        let netinfo = NetworkInfo::new(self.our_id, sk_share, pk_set, self.sec_key, self.pub_keys);
        Ok(netinfo)
    }

    /// Handles an `Ack` message or returns an error string.
    fn handle_ack_or_err(
        &mut self,
        sender_idx: u64,
        Ack(proposer_idx, values): Ack,
    ) -> Result<(), Fault> {
        if values.len() != self.pub_keys.len() {
            return Err(Fault::NodeCount);
        }
        let part = self
            .parts
            .get_mut(&proposer_idx)
            .ok_or_else(|| Fault::SenderExist)?;
        if !part.acks.insert(sender_idx) {
            return Err(Fault::DuplicateAck);
        }
        let our_idx = match self.our_idx {
            Some(our_idx) => our_idx,
            None => return Ok(()), // We are only an observer. Nothing to decrypt for us.
        };
        let ser_val: Vec<u8> = self
            .sec_key
            .decrypt(&values[our_idx as usize])
            .ok_or_else(|| Fault::ValueDecryption)?;
        let val = bincode::deserialize::<FieldWrap<Fr, Fr>>(&ser_val)
            .map_err(|err| {
                error!(
                    "Secure value deserialization failed while handling ack: {:?}",
                    err
                );
                Fault::ValueDeserialization
            })?.into_inner();
        if part.commit.evaluate(our_idx + 1, sender_idx + 1) != G1Affine::one().mul(val) {
            return Err(Fault::ValueInvalid);
        }
        part.values.insert(sender_idx + 1, val);
        Ok(())
    }

    /// Returns the index of the node, or `None` if it is unknown.
    fn node_index(&self, node_id: &N) -> Option<u64> {
        if let Some(node_idx) = self.pub_keys.keys().position(|id| id == node_id) {
            Some(node_idx as u64)
        } else {
            error!("Unknown node {:?}", node_id);
            None
        }
    }
}
