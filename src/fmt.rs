use broadcast::merkle::Proof;
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
            "Proof {{ #{}, root_hash: {:?}, value: {:?}, .. }}",
            &self.0.index(),
            HexBytes(self.0.root_hash().as_ref()),
            HexBytes(self.0.value().as_ref())
        )
    }
}
