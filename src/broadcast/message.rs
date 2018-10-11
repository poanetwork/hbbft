use std::fmt::{self, Debug};

use hex_fmt::HexFmt;
use rand;

use super::merkle::{Digest, MerkleTree, Proof};

/// The three kinds of message sent during the reliable broadcast stage of the
/// consensus algorithm.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum Message {
    Value(Proof<Vec<u8>>),
    Echo(Proof<Vec<u8>>),
    Ready(Digest),
}

// A random generation impl is provided for test cases. Unfortunately `#[cfg(test)]` does not work
// for integration tests.
impl rand::Rand for Message {
    fn rand<R: rand::Rng>(rng: &mut R) -> Self {
        let message_type = *rng.choose(&["value", "echo", "ready"]).unwrap();

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
            _ => unreachable!(),
        }
    }
}

impl Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Message::Value(ref v) => f.debug_tuple("Value").field(&HexProof(v)).finish(),
            Message::Echo(ref v) => f.debug_tuple("Echo").field(&HexProof(v)).finish(),
            Message::Ready(ref b) => f.debug_tuple("Ready").field(&HexFmt(b)).finish(),
        }
    }
}
/// Wrapper for a `Proof`, to print the bytes as a shortened hexadecimal number.
pub struct HexProof<'a, T: 'a>(pub &'a Proof<T>);

impl<'a, T: AsRef<[u8]>> fmt::Debug for HexProof<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Proof {{ #{}, root_hash: {:?}, value: {:?}, .. }}",
            &self.0.index(),
            HexFmt(self.0.root_hash()),
            HexFmt(self.0.value())
        )
    }
}
