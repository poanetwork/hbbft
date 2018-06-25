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
//! if up to `threshold` nodes are faulty.
//!
//! # How it works
//!
//! The algorithm is based on ideas from
//! [Distributed Key Generation in the Wild](https://eprint.iacr.org/2012/377.pdf) and
//! [A robust threshold elliptic curve digital signature providing a new verifiable secret sharing scheme](https://www.researchgate.net/profile/Ihab_Ali/publication/4205262_A_robust_threshold_elliptic_curve_digital_signature_providing_a_new_verifiable_secret_sharing_scheme/links/02e7e538f15726323a000000/A-robust-threshold-elliptic-curve-digital-signature-providing-a-new-verifiable-secret-sharing-scheme.pdf?origin=publication_detail).
//!
//! In a trusted dealer scenario, the following steps occur:
//!
//! 1. Dealer generates a `BivarPoly` of degree `t` and publishes the `BivarCommitment` which is
//!    used to publicly verify the polynomial's values.
//! 2. Dealer sends _row_ `m > 0` to node number `m`.
//! 3. Node `m`, in turn, sends _value_ `s` to node number `s`.
//! 4. This process continues until `2 * t + 1` nodes confirm they have received a valid row. If
//!    there are at most `t` faulty nodes, we know that at least `t + 1` correct nodes sent on an
//!    entry of every other node’s column to that node.
//! 5. This means every node can reconstruct its column, and the value at `0` of its column.
//! 6. These values all lie on a univariate polynomial of degree `t` and can be used as secret keys.
//!
//! In our _dealerless_ environment, at least `t + 1` nodes each generate a polynomial using the
//! method above. The sum of the secret keys we received from each node is then used as our secret
//! key. No single node knows the secret master key.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use bincode;
use clear_on_drop::ClearOnDrop;
use pairing::bls12_381::{Fr, G1Affine};
use pairing::{CurveAffine, Field};
use rand::OsRng;

use crypto::poly::{BivarCommitment, BivarPoly, Poly};
use crypto::serde_impl::field_vec::FieldWrap;
use crypto::{Ciphertext, PublicKey, PublicKeySet, SecretKey};

// TODO: No need to send our own row and value to ourselves.

/// A commitment to a bivariate polynomial, and for each node, an encrypted row of values.
#[derive(Deserialize, Serialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct Propose(BivarCommitment, Vec<Ciphertext>);

/// A confirmation that we have received a node's proposal and verified our row against the
/// commitment. For each node, it contains one encrypted value of our row.
#[derive(Deserialize, Serialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct Accept(u64, Vec<Ciphertext>);

/// The information needed to track a single proposer's secret sharing process.
struct ProposalState {
    /// The proposer's commitment.
    commit: BivarCommitment,
    /// The verified values we received from `Accept` messages.
    values: BTreeMap<u64, Fr>,
    /// The nodes which have accepted this proposal, valid or not.
    accepts: BTreeSet<u64>,
}

impl ProposalState {
    /// Creates a new proposal state with a commitment.
    fn new(commit: BivarCommitment) -> ProposalState {
        ProposalState {
            commit,
            values: BTreeMap::new(),
            accepts: BTreeSet::new(),
        }
    }

    /// Returns `true` if at least `2 * threshold + 1` nodes have accepted.
    fn is_complete(&self, threshold: usize) -> bool {
        self.accepts.len() > 2 * threshold
    }
}

/// A synchronous algorithm for dealerless distributed key generation.
///
/// It requires that all nodes handle all messages in the exact same order.
pub struct SyncKeyGen<NodeUid> {
    /// Our node index.
    our_idx: u64,
    /// Our secret key.
    sec_key: SecretKey,
    /// The public keys of all nodes, by node index.
    pub_keys: BTreeMap<NodeUid, PublicKey>,
    /// Proposed bivariate polynomial.
    proposals: BTreeMap<u64, ProposalState>,
    /// The degree of the generated polynomial.
    threshold: usize,
}

impl<NodeUid: Ord + Debug> SyncKeyGen<NodeUid> {
    /// Creates a new `SyncKeyGen` instance, together with the `Propose` message that should be
    /// broadcast.
    pub fn new(
        our_uid: &NodeUid,
        sec_key: SecretKey,
        pub_keys: BTreeMap<NodeUid, PublicKey>,
        threshold: usize,
    ) -> (SyncKeyGen<NodeUid>, Propose) {
        let our_idx = pub_keys
            .keys()
            .position(|uid| uid == our_uid)
            .expect("missing pub key for own ID") as u64;
        let mut rng = OsRng::new().expect("OS random number generator");
        let our_proposal = BivarPoly::random(threshold, &mut rng);
        let commit = our_proposal.commitment();
        let rows: Vec<_> = pub_keys
            .values()
            .enumerate()
            .map(|(i, pk)| {
                let row = our_proposal.row(i as u64 + 1);
                let bytes = bincode::serialize(&row).expect("failed to serialize row");
                pk.encrypt(&bytes)
            })
            .collect();
        let key_gen = SyncKeyGen {
            our_idx,
            sec_key,
            pub_keys,
            proposals: BTreeMap::new(),
            threshold,
        };
        (key_gen, Propose(commit, rows))
    }

    /// Handles a `Propose` message. If it is valid, returns an `Accept` message to be broadcast.
    pub fn handle_propose(
        &mut self,
        sender_id: &NodeUid,
        Propose(commit, rows): Propose,
    ) -> Option<Accept> {
        let sender_idx =
            if let Some(sender_idx) = self.pub_keys.keys().position(|uid| uid == sender_id) {
                sender_idx as u64
            } else {
                debug!("Unknown sender {:?}", sender_id);
                return None;
            };
        let commit_row = commit.row(self.our_idx + 1);
        match self.proposals.entry(sender_idx) {
            Entry::Occupied(_) => return None, // Ignore multiple proposals.
            Entry::Vacant(entry) => {
                entry.insert(ProposalState::new(commit));
            }
        }
        let ser_row = self.sec_key.decrypt(rows.get(self.our_idx as usize)?)?;
        let row: Poly = bincode::deserialize(&ser_row).ok()?; // Ignore invalid messages.
        if row.commitment() != commit_row {
            debug!("Invalid proposal from node {}.", sender_idx);
            return None;
        }
        // The row is valid: now encrypt one value for each node.
        let values = self
            .pub_keys
            .values()
            .enumerate()
            .map(|(idx, pk)| {
                let val = row.evaluate(idx as u64 + 1);
                let ser_val =
                    bincode::serialize(&FieldWrap::new(val)).expect("failed to serialize value");
                pk.encrypt(ser_val)
            })
            .collect();
        Some(Accept(sender_idx, values))
    }

    /// Handles an `Accept` message.
    pub fn handle_accept(&mut self, sender_id: &NodeUid, accept: Accept) {
        let sender_idx =
            if let Some(sender_idx) = self.pub_keys.keys().position(|uid| uid == sender_id) {
                sender_idx as u64
            } else {
                debug!("Unknown sender {:?}", sender_id);
                return;
            };
        if let Err(err) = self.handle_accept_or_err(sender_idx, accept) {
            debug!("Invalid accept from node {}: {}", sender_idx, err);
        }
    }

    /// Returns the number of complete proposals. If this is at least `threshold + 1`, the keys can
    /// be generated, but it is possible to wait for more to increase security.
    pub fn count_complete(&self) -> usize {
        self.proposals
            .values()
            .filter(|proposal| proposal.is_complete(self.threshold))
            .count()
    }

    /// Returns `true` if the proposal of the given node is complete.
    pub fn is_node_ready(&self, proposer_idx: u64) -> bool {
        self.proposals
            .get(&proposer_idx)
            .map_or(false, |proposal| proposal.is_complete(self.threshold))
    }

    /// Returns `true` if enough proposals are complete to safely generate the new key.
    pub fn is_ready(&self) -> bool {
        self.count_complete() > self.threshold
    }

    /// Returns the new secret key and the public key set.
    ///
    /// These are only secure if `is_ready` returned `true`. Otherwise it is not guaranteed that
    /// none of the nodes knows the secret master key.
    pub fn generate(&self) -> (PublicKeySet, ClearOnDrop<Box<SecretKey>>) {
        let mut pk_commit = Poly::zero().commitment();
        let mut sk_val = Fr::zero();
        for proposal in self
            .proposals
            .values()
            .filter(|proposal| proposal.is_complete(self.threshold))
        {
            pk_commit += proposal.commit.row(0);
            let row: Poly = Poly::interpolate(proposal.values.iter().take(self.threshold + 1));
            sk_val.add_assign(&row.evaluate(0));
        }
        let sk = ClearOnDrop::new(Box::new(SecretKey::from_value(sk_val)));
        (pk_commit.into(), sk)
    }

    /// Handles an `Accept` message or returns an error string.
    fn handle_accept_or_err(
        &mut self,
        sender_idx: u64,
        Accept(proposer_idx, values): Accept,
    ) -> Result<(), String> {
        let proposal = self
            .proposals
            .get_mut(&proposer_idx)
            .ok_or_else(|| "sender does not exist".to_string())?;
        if !proposal.accepts.insert(sender_idx) {
            return Err("duplicate accept".to_string());
        }
        if values.len() != self.pub_keys.len() {
            return Err("wrong node count".to_string());
        }
        let ser_val: Vec<u8> = self
            .sec_key
            .decrypt(&values[self.our_idx as usize])
            .ok_or_else(|| "value decryption failed".to_string())?;
        let val = bincode::deserialize::<FieldWrap<Fr, Fr>>(&ser_val)
            .map_err(|err| format!("deserialization failed: {:?}", err))?
            .into_inner();
        if proposal.commit.evaluate(self.our_idx + 1, sender_idx + 1) != G1Affine::one().mul(val) {
            return Err("wrong value".to_string());
        }
        proposal.values.insert(sender_idx + 1, val);
        Ok(())
    }
}
