use std::collections::{BTreeMap, BTreeSet};

use crypto::{self, PublicKey, PublicKeySet, PublicKeyShare, SecretKey, SecretKeyShare};
use rand;

use NodeIdT;

/// Common data shared between algorithms: the nodes' IDs and key shares.
#[derive(Debug, Clone)]
pub struct NetworkInfo<N> {
    our_id: N,
    num_nodes: usize,
    num_faulty: usize,
    is_validator: bool,
    // TODO: Should this be an option? It only makes sense for validators.
    secret_key_share: SecretKeyShare,
    secret_key: SecretKey,
    public_key_set: PublicKeySet,
    public_key_shares: BTreeMap<N, PublicKeyShare>,
    public_keys: BTreeMap<N, PublicKey>,
    node_indices: BTreeMap<N, usize>,
}

impl<N: NodeIdT> NetworkInfo<N> {
    pub fn new(
        our_id: N,
        secret_key_share: SecretKeyShare,
        public_key_set: PublicKeySet,
        secret_key: SecretKey,
        public_keys: BTreeMap<N, PublicKey>,
    ) -> Self {
        let num_nodes = public_keys.len();
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
            num_faulty: (num_nodes - 1) / 3,
            is_validator,
            secret_key_share,
            secret_key,
            public_key_set,
            public_key_shares,
            node_indices,
            public_keys,
        }
    }

    /// The ID of the node the algorithm runs on.
    pub fn our_id(&self) -> &N {
        &self.our_id
    }

    /// ID of all nodes in the network.
    pub fn all_ids(&self) -> impl Iterator<Item = &N> {
        self.public_keys.keys()
    }

    /// The total number _N_ of nodes.
    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    /// The maximum number _f_ of faulty, Byzantine nodes up to which Honey Badger is guaranteed to
    /// be correct.
    pub fn num_faulty(&self) -> usize {
        self.num_faulty
    }

    /// The minimum number _N - f_ of correct nodes with which Honey Badger is guaranteed to be
    /// correct.
    pub fn num_correct(&self) -> usize {
        self.num_nodes - self.num_faulty
    }

    /// Returns our secret key share for threshold cryptography.
    pub fn secret_key_share(&self) -> &SecretKeyShare {
        &self.secret_key_share
    }

    /// Returns our secret key for encryption and signing.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Returns the public key set for threshold cryptography.
    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.public_key_set
    }

    /// Returns the public key share if a node with that ID exists, otherwise `None`.
    pub fn public_key_share(&self, id: &N) -> Option<&PublicKeyShare> {
        self.public_key_shares.get(id)
    }

    /// Returns a map of all node IDs to their public key shares.
    pub fn public_key_share_map(&self) -> &BTreeMap<N, PublicKeyShare> {
        &self.public_key_shares
    }

    /// Returns a map of all node IDs to their public keys.
    pub fn public_key(&self, id: &N) -> Option<&PublicKey> {
        self.public_keys.get(id)
    }

    /// Returns a map of all node IDs to their public keys.
    pub fn public_key_map(&self) -> &BTreeMap<N, PublicKey> {
        &self.public_keys
    }

    /// The index of a node in a canonical numbering of all nodes.
    pub fn node_index(&self, id: &N) -> Option<usize> {
        self.node_indices.get(id).cloned()
    }

    /// Returns the unique ID of the Honey Badger invocation.
    ///
    /// FIXME: Using the public key as the invocation ID either requires agreeing on the keys on
    /// each invocation, or makes it unsafe to reuse keys for different invocations. A better
    /// invocation ID would be one that is distributed to all nodes on each invocation and would be
    /// independent from the public key, so that reusing keys would be safer.
    pub fn invocation_id(&self) -> Vec<u8> {
        self.public_key_set.public_key().to_bytes()
    }

    /// Returns `true` if this node takes part in the consensus itself. If not, it is only an
    /// observer.
    pub fn is_validator(&self) -> bool {
        self.is_validator
    }

    /// Returns `true` if the given node takes part in the consensus itself. If not, it is only an
    /// observer.
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
        use crypto::SecretKeySet;

        let all_ids: BTreeSet<N> = ids.into_iter().collect();
        let num_faulty = (all_ids.len() - 1) / 3;

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
