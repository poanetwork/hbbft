#![deny(unused_must_use)]
//! Tests for synchronous distributed key generation.

extern crate env_logger;
extern crate hbbft;
extern crate rand;
extern crate threshold_crypto as crypto;

use std::collections::BTreeMap;

use crypto::{PublicKey, SecretKey};

use hbbft::sync_key_gen::{PartOutcome, SyncKeyGen};
use hbbft::util;

fn test_sync_key_gen_with(threshold: usize, node_num: usize) {
    // Generate individual key pairs for encryption. These are not suitable for threshold schemes.
    let sec_keys: Vec<SecretKey> = (0..node_num).map(|_| SecretKey::random()).collect();
    let pub_keys: BTreeMap<usize, PublicKey> = sec_keys
        .iter()
        .map(SecretKey::public_key)
        .enumerate()
        .collect();

    // Create the `SyncKeyGen` instances and initial proposals.
    let mut nodes = Vec::new();
    let proposals: Vec<_> = sec_keys
        .into_iter()
        .enumerate()
        .map(|(id, sk)| {
            let (sync_key_gen, proposal) =
                SyncKeyGen::new(&mut rand::thread_rng(), id, sk, pub_keys.clone(), threshold)
                    .unwrap_or_else(|_err| {
                        panic!("Failed to create `SyncKeyGen` instance #{}", id)
                    });
            nodes.push(sync_key_gen);
            proposal
        }).collect();

    // Handle the first `threshold + 1` proposals. Those should suffice for key generation.
    let mut acks = Vec::new();
    for (sender_id, proposal) in proposals[..=threshold].iter().enumerate() {
        for (node_id, node) in nodes.iter_mut().enumerate() {
            let proposal = proposal.clone().expect("proposal");
            let ack = match node
                .handle_part(&mut rand::thread_rng(), &sender_id, proposal)
                .expect("failed to handle part")
            {
                PartOutcome::Valid(Some(ack)) => ack,
                PartOutcome::Valid(None) => panic!("missing ack message"),
                PartOutcome::Invalid(fault) => panic!("invalid proposal: {:?}", fault),
            };
            // Only the first `threshold + 1` manage to commit their `Ack`s.
            if node_id <= 2 * threshold {
                acks.push((node_id, ack));
            }
        }
    }

    // Handle the `Ack`s from `2 * threshold + 1` nodes.
    for (sender_id, ack) in acks {
        for node in &mut nodes {
            assert!(!node.is_ready()); // Not enough `Ack`s yet.
            node.handle_ack(&sender_id, ack.clone())
                .expect("error handling ack");
        }
    }

    // Compute the keys and test a threshold signature.
    let msg = "Help I'm trapped in a unit test factory";
    let pub_key_set = nodes[0]
        .generate()
        .expect("Failed to generate `PublicKeySet` for node #0")
        .0;
    let sig_shares: BTreeMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| {
            assert!(node.is_ready());
            let (pks, opt_sk) = node.generate().unwrap_or_else(|_| {
                panic!(
                    "Failed to generate `PublicKeySet` and `SecretKeyShare` for node #{}",
                    idx
                )
            });
            let sk = opt_sk.expect("new secret key");
            assert_eq!(pks, pub_key_set);
            let sig = sk.sign(msg);
            assert!(pks.public_key_share(idx).verify(&sig, msg));
            (idx, sig)
        }).collect();
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
        let threshold = util::max_faulty(node_num);
        test_sync_key_gen_with(threshold, node_num);
    }
}
