use std::fmt::{self, Debug};

use hex_fmt::HexFmt;
use rand::distributions::{Distribution, Standard};
use rand::{self, seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};

use super::merkle::{Digest, MerkleTree, Proof};

/// The three kinds of message sent during the reliable broadcast stage of the
/// consensus algorithm.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum Message {
    /// A share of the value, sent from the sender to another validator.
    Value(Proof<Vec<u8>>),
    /// A copy of the value received from the sender, multicast by a validator.
    Echo(Proof<Vec<u8>>),
    /// Indicates that the sender knows that every node will eventually be able to decode.
    Ready(Digest),
    /// Indicates that this node has enough shares to decode the message with given Merkle root.
    CanDecode(Digest),
    /// Indicates that sender can send an Echo for given Merkle root.
    EchoHash(Digest),
}

// A random generation impl is provided for test cases. Unfortunately `#[cfg(test)]` does not work
// for integration tests.
impl Distribution<Message> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Message {
        let message_type = *["value", "echo", "ready", "can_decode", "echo_hash"]
            .choose(rng)
            .unwrap();

        // Create a random buffer for our proof.
        let mut buffer: [u8; 32] = [0; 32];
        rng.fill_bytes(&mut buffer);

        // Generate a dummy proof to fill broadcast messages with.
        let tree = MerkleTree::from_vec(vec![buffer.to_vec()]);
        let proof = tree.proof(0).unwrap();

        match message_type {
            "value" => Message::Value(proof),
            "echo" => Message::Echo(proof),
            "ready" => Message::Ready([b'r'; 32]),
            "can_decode" => Message::Ready([b'r'; 32]),
            "echo_hash" => Message::Ready([b'r'; 32]),
            _ => unreachable!(),
        }
    }
}

impl Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Message::Value(ref v) => f.debug_tuple("Value").field(&HexProof(v)).finish(),
            Message::Echo(ref v) => f.debug_tuple("Echo").field(&HexProof(v)).finish(),
            Message::Ready(ref b) => write!(f, "Ready({:0.10})", HexFmt(b)),
            Message::CanDecode(ref b) => write!(f, "CanDecode({:0.10})", HexFmt(b)),
            Message::EchoHash(ref b) => write!(f, "EchoHash({:0.10})", HexFmt(b)),
        }
    }
}
/// Wrapper for a `Proof`, to print the bytes as a shortened hexadecimal number.
pub struct HexProof<'a, T>(pub &'a Proof<T>);

impl<'a, T: AsRef<[u8]>> fmt::Debug for HexProof<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Proof {{ #{}, root_hash: {:0.10}, value: {:0.10}, .. }}",
            &self.0.index(),
            HexFmt(self.0.root_hash()),
            HexFmt(self.0.value())
        )
    }
}
