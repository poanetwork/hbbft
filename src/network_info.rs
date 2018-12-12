use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::{self, PublicKey, PublicKeySet, PublicKeyShare, SecretKey, SecretKeyShare};
use rand;

use crate::{util, NodeIdT};

/// Common data shared between algorithms: the nodes' IDs and key shares.
#[derive(Debug, Clone)]
pub struct NetworkInfo<N> {
    /// This node's ID.
    our_id: N,
    /// The number _N_ of nodes in the network. Equal to the size of `public_keys`.
    num_nodes: usize,
    /// The number _f_ of faulty nodes that can be tolerated. Less than a third of _N_.
    num_faulty: usize,
    /// Whether this node is a validator. This is true if `public_keys` contains our own ID.
    is_validator: bool,
    /// This node's secret key share. Only validators have one.
    secret_key_share: Option<SecretKeyShare>,
    /// This node's secret key.
    secret_key: SecretKey,
    /// The public key set for threshold cryptography. Each validator has a secret key share.
    public_key_set: PublicKeySet,
    /// The validators' public key shares, computed from `public_key_set`.
    public_key_shares: BTreeMap<N, PublicKeyShare>,
    /// The validators' public keys.
    public_keys: BTreeMap<N, PublicKey>,
    /// The indices in the list of sorted validator IDs.
    node_indices: BTreeMap<N, usize>,
}

impl<N: NodeIdT> NetworkInfo<N> {
    /// Creates a new `NetworkInfo` with the given ID and keys.
    ///
    /// All nodes in the network must share the same public information. Validators' IDs must be
    /// keys in the `public_keys` map, and their secret key share must match their share in the
    /// `public_key_set`.
    ///
    /// # Panics
    ///
    /// Panics if `public_keys` is empty.
    pub fn new<SKS: Into<Option<SecretKeyShare>>>(
        our_id: N,
        secret_key_share: SKS,
        public_key_set: PublicKeySet,
        secret_key: SecretKey,
        public_keys: BTreeMap<N, PublicKey>,
    ) -> Self {
        let num_nodes = public_keys.len();
        let num_faulty = util::max_faulty(num_nodes);
        assert!(3 * num_faulty < num_nodes, " 3 f >= N. This is a bug!");
        let is_validator = public_keys.contains_key(&our_id);
        let node_indices: BTreeMap<N, usize> = public_keys
            .keys()
            .enumerate()
            .map(|(n, id)| (id.clone(), n))
            .collect();
        let public_key_shares = node_indices
            .iter()
            .map(|(id, idx)| (id.clone(), public_key_set.public_key_share(*idx)))
            .collect();
        NetworkInfo {
            our_id,
            num_nodes,
            num_faulty,
            is_validator,
            secret_key_share: secret_key_share.into(),
            secret_key,
            public_key_set,
            public_key_shares,
            node_indices,
            public_keys,
        }
    }

    /// The ID of the node the algorithm runs on.
    #[inline]
    pub fn our_id(&self) -> &N {
        &self.our_id
    }

    /// ID of all nodes in the network.
    #[inline]
    pub fn all_ids(&self) -> impl Iterator<Item = &N> {
        self.public_keys.keys()
    }

    /// The total number _N_ of nodes.
    #[inline]
    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    /// The maximum number _f_ of faulty, Byzantine nodes up to which Honey Badger is guaranteed to
    /// be correct.
    #[inline]
    pub fn num_faulty(&self) -> usize {
        self.num_faulty
    }

    /// The minimum number _N - f_ of correct nodes with which Honey Badger is guaranteed to be
    /// correct.
    #[inline]
    pub fn num_correct(&self) -> usize {
        // As asserted in `new`, `num_faulty` is never greater than `num_nodes`.
        self.num_nodes - self.num_faulty
    }

    /// Returns our secret key share for threshold cryptography, or `None` if not a validator.
    #[inline]
    pub fn secret_key_share(&self) -> Option<&SecretKeyShare> {
        self.secret_key_share.as_ref()
    }

    /// Returns our secret key for encryption and signing.
    #[inline]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Returns the public key set for threshold cryptography.
    #[inline]
    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.public_key_set
    }

    /// Returns the public key share if a node with that ID exists, otherwise `None`.
    #[inline]
    pub fn public_key_share(&self, id: &N) -> Option<&PublicKeyShare> {
        self.public_key_shares.get(id)
    }

    /// Returns a map of all node IDs to their public key shares.
    #[inline]
    pub fn public_key_share_map(&self) -> &BTreeMap<N, PublicKeyShare> {
        &self.public_key_shares
    }

    /// Returns a map of all node IDs to their public keys.
    #[inline]
    pub fn public_key(&self, id: &N) -> Option<&PublicKey> {
        self.public_keys.get(id)
    }

    /// Returns a map of all node IDs to their public keys.
    #[inline]
    pub fn public_key_map(&self) -> &BTreeMap<N, PublicKey> {
        &self.public_keys
    }

    /// The index of a node in a canonical numbering of all nodes. This is the index where the
    /// node appears in `all_ids`.
    #[inline]
    pub fn node_index(&self, id: &N) -> Option<usize> {
        self.node_indices.get(id).cloned()
    }

    /// Returns `true` if this node takes part in the consensus itself. If not, it is only an
    /// observer.
    #[inline]
    pub fn is_validator(&self) -> bool {
        self.is_validator
    }

    /// Returns `true` if the given node takes part in the consensus itself. If not, it is only an
    /// observer.
    #[inline]
    pub fn is_node_validator(&self, id: &N) -> bool {
        self.public_keys.contains_key(id)
    }

    /// Generates a map of matching `NetworkInfo`s for testing.
    pub fn generate_map<I, R>(
        ids: I,
        rng: &mut R,
    ) -> Result<BTreeMap<N, NetworkInfo<N>>, crypto::error::Error>
    where
        I: IntoIterator<Item = N>,
        R: rand::Rng,
    {
        use crate::crypto::SecretKeySet;

        let all_ids: BTreeSet<N> = ids.into_iter().collect();
        let num_faulty = util::max_faulty(all_ids.len());

        // Generate the keys for threshold cryptography.
        let sk_set = SecretKeySet::random(num_faulty, rng);
        let pk_set = sk_set.public_keys();

        // Generate keys for individually signing and encrypting messages.
        let sec_keys: BTreeMap<_, SecretKey> =
            all_ids.iter().map(|id| (id.clone(), rng.gen())).collect();
        let pub_keys: BTreeMap<_, PublicKey> = sec_keys
            .iter()
            .map(|(id, sk)| (id.clone(), sk.public_key()))
            .collect();

        // Create the corresponding `NetworkInfo` for each node.
        let create_netinfo = |(i, id): (usize, N)| {
            let netinfo = NetworkInfo::new(
                id.clone(),
                sk_set.secret_key_share(i),
                pk_set.clone(),
                sec_keys[&id].clone(),
                pub_keys.clone(),
            );
            Ok((id, netinfo))
        };
        all_ids
            .into_iter()
            .enumerate()
            .map(create_netinfo)
            .collect()
    }
}
