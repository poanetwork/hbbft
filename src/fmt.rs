use merkle::proof::{Lemma, Positioned, Proof};
use std::fmt;

/// Wrapper for a byte array, whose `Debug` implementation outputs shortened hexadecimal strings.
pub struct HexBytes<'a>(pub &'a [u8]);

impl<'a> fmt::Debug for HexBytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.len() > 6 {
            for byte in &self.0[..3] {
                write!(f, "{:02x}", byte)?;
            }
            write!(f, "..")?;
            for byte in &self.0[(self.0.len() - 3)..] {
                write!(f, "{:02x}", byte)?;
            }
        } else {
            for byte in self.0 {
                write!(f, "{:02x}", byte)?;
            }
        }
        Ok(())
    }
}

/// Wrapper for a list of byte arrays, whose `Debug` implementation outputs shortened hexadecimal
/// strings.
pub struct HexList<'a, T: 'a>(pub &'a [T]);

impl<'a, T: AsRef<[u8]>> fmt::Debug for HexList<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v: Vec<_> = self.0.iter().map(|t| HexBytes(t.as_ref())).collect();
        write!(f, "{:?}", v)
    }
}

pub struct HexProof<'a, T: 'a>(pub &'a Proof<T>);

impl<'a, T: AsRef<[u8]>> fmt::Debug for HexProof<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Proof {{ algorithm: {:?}, root_hash: {:?}, lemma for leaf #{}, value: {:?} }}",
            self.0.algorithm,
            HexBytes(&self.0.root_hash),
            path_of_lemma(&self.0.lemma),
            HexBytes(&self.0.value.as_ref())
        )
    }
}

/// The path of a lemma in a Merkle tree
struct BinaryPath(Vec<bool>);

/// The path of the lemma, as a binary string
fn path_of_lemma(mut lemma: &Lemma) -> BinaryPath {
    let mut result = Vec::new();
    loop {
        match lemma.sibling_hash {
            None => (),
            Some(Positioned::Left(_)) => result.push(true),
            Some(Positioned::Right(_)) => result.push(false),
        }
        lemma = match lemma.sub_lemma.as_ref() {
            Some(lemma) => lemma,
            None => return BinaryPath(result),
        }
    }
}

impl fmt::Display for BinaryPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in &self.0 {
            if *b {
                write!(f, "1")?;
            } else {
                write!(f, "0")?;
            }
        }
        Ok(())
    }
}
