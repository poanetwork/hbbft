use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::crypto::{self, PublicKey, PublicKeySet, PublicKeyShare, SecretKey, SecretKeyShare};
use rand;

use crate::{util, NodeIdT};

/// The set of all node IDs of the network's validators.
#[derive(Debug, Clone)]
pub struct ValidatorSet<N> {
    num_faulty: usize,
    indices: BTreeMap<N, usize>,
}

impl<I, N> From<I> for ValidatorSet<N>
where
    I: IntoIterator,
    I::Item: Borrow<N>,
    N: NodeIdT,
{
    fn from(i: I) -> Self {
        let indices: BTreeMap<N, usize> = i
            .into_iter()
            .enumerate()
            .map(|(n, id)| (id.borrow().clone(), n))
            .collect();
        let num_faulty = util::max_faulty(indices.len());
        assert!(3 * num_faulty < indices.len(), "3 f >= N. This is a bug!");
        ValidatorSet {
            num_faulty,
            indices,
        }
    }
}

impl<N: NodeIdT> ValidatorSet<N> {
    /// Returns `true` if the given ID belongs to a known validator.
    #[inline]
    pub fn contains(&self, id: &N) -> bool {
        self.indices.contains_key(id)
    }

    /// Returns the validators index in the ordered list of all IDs.
    #[inline]
    pub fn index(&self, id: &N) -> Option<usize> {
        self.indices.get(id).cloned()
    }

    /// The total number _N_ of validators.
    #[inline]
    pub fn num(&self) -> usize {
        self.indices.len()
    }

    /// The maximum number _f_ of faulty, Byzantine validators up to which Honey Badger is
    /// guaranteed to be correct.
    #[inline]
    pub fn num_faulty(&self) -> usize {
        self.num_faulty
    }

    /// The minimum number _N - f_ of correct validators with which Honey Badger is guaranteed to
    /// be correct.
    #[inline]
    pub fn num_correct(&self) -> usize {
        // As asserted in `new`, `num_faulty` is never greater than `num`.
        self.num() - self.num_faulty
    }

    /// IDs of all validators in the network.
    #[inline]
    pub fn all_ids(&self) -> impl Iterator<Item = &N> + Clone {
        self.indices.keys()
    }

    /// IDs and indices of all validators in the network.
    #[inline]
    pub fn all_indices(&self) -> impl Iterator<Item = (&N, &usize)> + Clone {
        self.indices.iter()
    }
}

/// Common data shared between algorithms: the nodes' IDs and key shares.
#[derive(Debug, Clone)]
pub struct NetworkInfo<N> {
    /// This node's ID.
    our_id: N,
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
    val_set: Arc<ValidatorSet<N>>,
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
        let val_set = Arc::new(ValidatorSet::from(public_keys.keys()));
        let is_validator = val_set.contains(&our_id);
        let public_key_shares = public_keys
            .keys()
            .enumerate()
            .map(|(idx, id)| (id.clone(), public_key_set.public_key_share(idx)))
            .collect();
        NetworkInfo {
            our_id,
            is_validator,
            secret_key_share: secret_key_share.into(),
            secret_key,
            public_key_set,
            public_key_shares,
            val_set,
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
    pub fn all_ids(&self) -> impl Iterator<Item = &N> + Clone {
        self.val_set.all_ids()
    }

    /// ID of all nodes in the network except this one.
    #[inline]
    pub fn other_ids(&self) -> impl Iterator<Item = &N> + Clone {
        let our_id = self.our_id.clone();
        self.all_ids().filter(move |id| **id != our_id)
    }

    /// The total number _N_ of nodes.
    #[inline]
    pub fn num_nodes(&self) -> usize {
        self.val_set.num()
    }

    /// The maximum number _f_ of faulty, Byzantine nodes up to which Honey Badger is guaranteed to
    /// be correct.
    #[inline]
    pub fn num_faulty(&self) -> usize {
        self.val_set.num_faulty()
    }

    /// The minimum number _N - f_ of correct nodes with which Honey Badger is guaranteed to be
    /// correct.
    #[inline]
    pub fn num_correct(&self) -> usize {
        self.val_set.num_correct()
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
        self.val_set.index(id)
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

    /// Returns the set of validator IDs.
    pub fn validator_set(&self) -> &Arc<ValidatorSet<N>> {
        &self.val_set
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
