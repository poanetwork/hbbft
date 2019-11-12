use std::mem;

use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

pub type Digest = [u8; 32];

/// A Merkle tree: The leaves are values and their hashes. Each level consists of the hashes of
/// pairs of values on the previous level. The root is the value in the first level with only one
/// entry.
#[derive(Debug)]
pub struct MerkleTree<T> {
    levels: Vec<Vec<Digest>>,
    values: Vec<T>,
    root_hash: Digest,
}

impl<T: AsRef<[u8]> + Clone> MerkleTree<T> {
    /// Creates a new Merkle tree with the given values.
    pub fn from_vec(values: Vec<T>) -> Self {
        let mut levels = Vec::new();
        let mut cur_lvl: Vec<Digest> = values.iter().map(hash).collect();
        while cur_lvl.len() > 1 {
            let next_lvl = cur_lvl.chunks(2).map(hash_chunk).collect();
            levels.push(mem::replace(&mut cur_lvl, next_lvl));
        }
        let root_hash = cur_lvl[0];
        MerkleTree {
            levels,
            values,
            root_hash,
        }
    }

    /// Returns the proof for entry `index`, if that is a valid index.
    pub fn proof(&self, index: usize) -> Option<Proof<T>> {
        let value = self.values.get(index)?.clone();
        let mut lvl_i = index;
        let mut digests = Vec::new();
        for level in &self.levels {
            // Insert the sibling hash if there is one.
            if let Some(digest) = level.get(lvl_i ^ 1) {
                digests.push(*digest);
            }
            lvl_i /= 2;
        }
        Some(Proof {
            index,
            digests,
            value,
            root_hash: self.root_hash,
        })
    }

    /// Returns the root hash of the tree.
    pub fn root_hash(&self) -> &Digest {
        &self.root_hash
    }

    /// Returns a the slice containing all leaf values.
    pub fn values(&self) -> &[T] {
        &self.values
    }

    /// Consumes the tree, and returns the vector of leaf values.
    pub fn into_values(self) -> Vec<T> {
        self.values
    }
}

/// A proof that a value is at a particular index in the Merkle tree specified by its root hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Proof<T> {
    value: T,
    index: usize,
    digests: Vec<Digest>,
    root_hash: Digest,
}

impl<T: AsRef<[u8]>> Proof<T> {
    /// Returns `true` if the digests in this proof constitute a valid branch in a Merkle tree with
    /// the root hash.
    pub fn validate(&self, n: usize) -> bool {
        let mut digest = hash(&self.value);
        let mut lvl_i = self.index;
        let mut lvl_n = n;
        let mut digest_itr = self.digests.iter();
        while lvl_n > 1 {
            if lvl_i ^ 1 < lvl_n {
                digest = match digest_itr.next() {
                    None => return false, // Not enough levels in the proof.
                    Some(sibling) if lvl_i & 1 == 1 => hash_pair(&sibling, &digest),
                    Some(sibling) => hash_pair(&digest, &sibling),
                };
            }
            lvl_i /= 2; // Our index on the next level.
            lvl_n = (lvl_n + 1) / 2; // The next level's size.
        }
        if digest_itr.next().is_some() {
            return false; // Too many levels in the proof.
        }
        digest == self.root_hash
    }

    /// Returns the index of this proof's value in the tree.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the tree's root hash.
    pub fn root_hash(&self) -> &Digest {
        &self.root_hash
    }

    /// Returns the leaf value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consumes the proof and returns the leaf value.
    pub fn into_value(self) -> T {
        self.value
    }
}

/// Takes a chunk of one or two digests. In the former case, returns the digest itself, in the
/// latter, it returns the hash of the two digests.
fn hash_chunk(chunk: &[Digest]) -> Digest {
    if chunk.len() == 1 {
        chunk[0]
    } else {
        hash_pair(&chunk[0], &chunk[1])
    }
}

/// Returns the hash of the concatenated bytes of `d0` and `d1`.
fn hash_pair<T0: AsRef<[u8]>, T1: AsRef<[u8]>>(v0: &T0, v1: &T1) -> Digest {
    let bytes: Vec<u8> = v0.as_ref().iter().chain(v1.as_ref()).cloned().collect();
    hash(&bytes)
}

/// Returns the SHA-256 hash of the value's `[u8]` representation.
fn hash<T: AsRef<[u8]>>(value: T) -> Digest {
    let mut sha3 = Sha3::v256();
    sha3.update(value.as_ref());

    let mut out = [0u8; 32];
    sha3.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;

    #[test]
    fn test_merkle() {
        for &n in &[4, 7, 8, 9, 17] {
            let tree = MerkleTree::from_vec((0..n).map(|i| vec![i as u8]).collect());
            for i in 0..n {
                let proof = tree.proof(i).expect("couldn't get proof");
                assert!(proof.validate(n));
            }
            assert!(tree.proof(n).is_none());
        }
    }
}
