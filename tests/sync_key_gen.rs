//! Tests for synchronous distributed key generation.

extern crate env_logger;
extern crate hbbft;
extern crate pairing;
extern crate rand;

use std::collections::BTreeMap;

use hbbft::crypto::{PublicKey, SecretKey};
use hbbft::sync_key_gen::SyncKeyGen;
use pairing::bls12_381::Bls12;

fn test_sync_key_gen_with(threshold: usize, node_num: usize) {
    let mut rng = rand::thread_rng();

    // Generate individual key pairs for encryption. These are not suitable for threshold schemes.
    let sec_keys: Vec<SecretKey<Bls12>> = (0..node_num).map(|_| SecretKey::new(&mut rng)).collect();
    let pub_keys: Vec<PublicKey<Bls12>> = sec_keys.iter().map(|sk| sk.public_key()).collect();

    // Create the `SyncKeyGen` instances and initial proposals.
    let mut nodes = Vec::new();
    let proposals: Vec<_> = sec_keys
        .into_iter()
        .enumerate()
        .map(|(idx, sk)| {
            let (sync_key_gen, proposal) =
                SyncKeyGen::new(idx as u64, sk, pub_keys.clone(), threshold);
            nodes.push(sync_key_gen);
            proposal
        })
        .collect();

    // Handle the first `threshold + 1` proposals. Those should suffice for key generation.
    let mut accepts = Vec::new();
    for (sender_idx, proposal) in proposals[..=threshold].iter().enumerate() {
        for (node_idx, node) in nodes.iter_mut().enumerate() {
            let accept = node
                .handle_propose(sender_idx as u64, proposal.clone())
                .expect("valid proposal");
            // Only the first `threshold + 1` manage to commit their `Accept`s.
            if node_idx <= 2 * threshold {
                accepts.push((node_idx, accept));
            }
        }
    }

    // Handle the `Accept`s from `2 * threshold + 1` nodes.
    for (sender_idx, accept) in accepts {
        for node in &mut nodes {
            assert!(!node.is_ready()); // Not enough `Accept`s yet.
            node.handle_accept(sender_idx as u64, accept.clone());
        }
    }

    // Compute the keys and test a threshold signature.
    let msg = "Help I'm trapped in a unit test factory";
    let pub_key_set = nodes[0].generate().0;
    let sig_shares: BTreeMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| {
            assert!(node.is_ready());
            let (pks, sk) = node.generate();
            assert_eq!(pks, pub_key_set);
            let sig = sk.sign(msg);
            assert!(pks.public_key_share(idx as u64).verify(&sig, msg));
            (idx as u64, sig)
        })
        .collect();
    let sig = pub_key_set
        .combine_signatures(sig_shares.iter().take(threshold + 1))
        .expect("signature shares match");
    assert!(pub_key_set.public_key().verify(&sig, msg));
}

#[test]
fn test_sync_key_gen() {
    // This returns an error in all but the first test.
    let _ = env_logger::try_init();

    for &node_num in &[1, 2, 3, 4, 8, 15] {
        let threshold = (node_num - 1) / 3;
        test_sync_key_gen_with(threshold, node_num);
    }
}
