//! A _synchronous_ algorithm for dealerless distributed key generation.
//!
//! This protocol is meant to run in a _completely synchronous_ setting where each node handles all
//! messages in the same order. This can be achieved by making its messages transactions on top of
//! `HoneyBadger`, or by running it "on-chain", i.e. committing its messages to a blockchain.
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
//! If there were a trusted dealer, they would generate a `BivarPoly` of degree `t` and publish
//! the `BivarCommitment`, with which the polynomial's values can be publicly verified. They'd
//! then send _row_ `m > 0` to node number `m`. Node `m`, in turn, sends _value_ `s` to node number
//! `s`. Then if `2 * t + 1` nodes confirm that they received a valid row, and there are at most
//! `t` faulty nodes, then at least `t + 1` honest nodes sent on an entry of every other node's
//! column to that node. So we know that every node can now reconstruct its column and the value at
//! `0` of its column. These values all lie on a univariate polynomial of degree `t`, so they can
//! be used as secret keys.
//!
//! To avoid trusting a single dealer, we make sure that at least `t + 1` nodes use the above
//! method to generate a polynomial each. We then sum up the secret keys we received from each
//! "dealer", and use that as our secret key. Then no single node knows the sum of the master keys.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use crypto::poly::{BivarCommitment, BivarPoly, Poly};
use crypto::serde_impl::field_vec::FieldWrap;
use crypto::{Ciphertext, PublicKey, PublicKeySet, SecretKey};

use bincode;
use pairing::bls12_381::{Bls12, Fr, G1Affine};
use pairing::{CurveAffine, Field};
use rand::OsRng;

// TODO: No need to send our own row and value to ourselves.

/// A commitment to a bivariate polynomial, and for each node, an encrypted row of values.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Propose(BivarCommitment<Bls12>, Vec<Ciphertext<Bls12>>);

/// A confirmation that we have received a node's proposal and verified our row against the
/// commitment. For each node, it contains one encrypted value of our row.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Accept(u64, Vec<Ciphertext<Bls12>>);

/// The information needed to track a single proposer's secret sharing process.
struct ProposalState {
    /// The proposer's commitment.
    commit: BivarCommitment<Bls12>,
    /// The verified values we received from `Accept` messages.
    values: BTreeMap<u64, Fr>,
    /// The nodes which have accepted this proposal, valid or not.
    accepts: BTreeSet<u64>,
}

impl ProposalState {
    /// Creates a new proposal state with a commitment.
    fn new(commit: BivarCommitment<Bls12>) -> ProposalState {
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
pub struct SyncKeyGen {
    /// Our node index.
    our_idx: u64,
    /// Our secret key.
    sec_key: SecretKey<Bls12>,
    /// The public keys of all nodes, by node index.
    pub_keys: Vec<PublicKey<Bls12>>,
    /// Proposed bivariate polynomial.
    proposals: BTreeMap<u64, ProposalState>,
    /// The degree of the generated polynomial.
    threshold: usize,
}

impl SyncKeyGen {
    /// Creates a new `SyncKeyGen` instance, together with the `Propose` message that should be
    /// broadcast.
    pub fn new(
        our_idx: u64,
        sec_key: SecretKey<Bls12>,
        pub_keys: Vec<PublicKey<Bls12>>,
        threshold: usize,
    ) -> (SyncKeyGen, Propose) {
        let mut rng = OsRng::new().expect("OS random number generator");
        let our_proposal = BivarPoly::random(threshold, &mut rng);
        let commit = our_proposal.commitment();
        let rows: Vec<_> = pub_keys
            .iter()
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
        sender_idx: u64,
        Propose(commit, rows): Propose,
    ) -> Option<Accept> {
        let commit_row = commit.row(self.our_idx + 1);
        match self.proposals.entry(sender_idx) {
            Entry::Occupied(_) => return None, // Ignore multiple proposals.
            Entry::Vacant(entry) => {
                entry.insert(ProposalState::new(commit));
            }
        }
        let ser_row = self.sec_key.decrypt(rows.get(self.our_idx as usize)?)?;
        let row: Poly<Bls12> = bincode::deserialize(&ser_row).ok()?; // Ignore invalid messages.
        if row.commitment() != commit_row {
            debug!("Invalid proposal from node {}.", sender_idx);
            return None;
        }
        // The row is valid: now encrypt one value for each node.
        let values = self
            .pub_keys
            .iter()
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
    pub fn handle_accept(&mut self, sender_idx: u64, accept: Accept) {
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
    pub fn generate(&self) -> (PublicKeySet<Bls12>, SecretKey<Bls12>) {
        let mut pk_commit = Poly::zero().commitment();
        let mut sk_val = Fr::zero();
        for proposal in self
            .proposals
            .values()
            .filter(|proposal| proposal.is_complete(self.threshold))
        {
            pk_commit += proposal.commit.row(0);
            let row: Poly<Bls12> =
                Poly::interpolate(proposal.values.iter().take(self.threshold + 1));
            sk_val.add_assign(&row.evaluate(0));
        }
        (pk_commit.into(), SecretKey::from_value(sk_val))
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
