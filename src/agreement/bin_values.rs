use std::iter::FromIterator;
use std::mem::replace;

/// A lattice-valued description of the state of `bin_values`, essentially the same as the set of
/// subsets of `bool`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BinValues {
    None,
    False,
    True,
    Both,
}

impl BinValues {
    pub fn new() -> Self {
        BinValues::None
    }

    pub fn clear(&mut self) {
        replace(self, BinValues::None);
    }

    pub fn from_bool(b: bool) -> Self {
        if b {
            BinValues::True
        } else {
            BinValues::False
        }
    }

    /// Inserts a boolean value into the `BinValues` and returns true iff the `BinValues` has
    /// changed as a result.
    pub fn insert(&mut self, b: bool) -> bool {
        match self {
            BinValues::None => {
                replace(self, BinValues::from_bool(b));
                true
            }
            BinValues::False if b => {
                replace(self, BinValues::Both);
                true
            }
            BinValues::True if !b => {
                replace(self, BinValues::Both);
                true
            }
            _ => false,
        }
    }

    pub fn union(&mut self, other: BinValues) {
        match self {
            BinValues::None => {
                replace(self, other);
            }
            BinValues::False if other == BinValues::True => {
                replace(self, BinValues::Both);
            }
            BinValues::True if other == BinValues::False => {
                replace(self, BinValues::Both);
            }
            _ => {}
        }
    }

    pub fn contains(self, b: bool) -> bool {
        match self {
            BinValues::None => false,
            BinValues::Both => true,
            BinValues::False if !b => true,
            BinValues::True if b => true,
            _ => false,
        }
    }

    pub fn is_subset(self, other: BinValues) -> bool {
        match self {
            BinValues::None => true,
            BinValues::False if other == BinValues::False || other == BinValues::Both => true,
            BinValues::True if other == BinValues::True || other == BinValues::Both => true,
            BinValues::Both if other == BinValues::Both => true,
            _ => false,
        }
    }

    pub fn definite(self) -> Option<bool> {
        match self {
            BinValues::False => Some(false),
            BinValues::True => Some(true),
            _ => None,
        }
    }
}

impl Default for BinValues {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<BinValues> for BinValues {
    fn from_iter<I: IntoIterator<Item = BinValues>>(iter: I) -> Self {
        let mut v = BinValues::new();

        for i in iter {
            v.union(i);
        }

        v
    }
}
