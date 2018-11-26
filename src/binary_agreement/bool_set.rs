//! A single-byte representation of a set of boolean values.

use rand_derive::Rand;
use serde_derive::{Deserialize, Serialize};

/// The empty set of boolean values.
pub const NONE: BoolSet = BoolSet(0b00);

/// The set containing only `false`.
pub const FALSE: BoolSet = BoolSet(0b01);

/// The set containing only `true`.
pub const TRUE: BoolSet = BoolSet(0b10);

/// The set of both boolean values, `false` and `true`.
pub const BOTH: BoolSet = BoolSet(0b11);

/// A set of `bool` values, represented as a single byte in memory.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Rand, Default,
)]
pub struct BoolSet(u8);

impl BoolSet {
    /// Inserts a boolean value into the `BoolSet` and returns `true` iff the `BoolSet` has
    /// changed as a result.
    pub fn insert(&mut self, b: bool) -> bool {
        let prev = *self;
        self.0 |= Self::from(b).0;
        prev != *self
    }

    /// Removes a value from the set.
    pub fn remove(&mut self, b: bool) {
        self.0 &= Self::from(!b).0;
    }

    /// Returns `true` if the set contains the value `b`.
    pub fn contains(self, b: bool) -> bool {
        self.0 & Self::from(b).0 != 0
    }

    /// Returns `true` if every element of `self` is also an element of `other`.
    pub fn is_subset(self, other: BoolSet) -> bool {
        self.0 & other.0 == self.0
    }

    /// Returns `Some(b)` if the set is the singleton with the value `b`, otherwise `None`.
    pub fn definite(self) -> Option<bool> {
        match self {
            FALSE => Some(false),
            TRUE => Some(true),
            _ => None,
        }
    }
}

impl From<bool> for BoolSet {
    fn from(b: bool) -> Self {
        if b {
            TRUE
        } else {
            FALSE
        }
    }
}

/// An iterator over a `BoolSet`.
#[derive(Clone, Copy, Debug)]
pub struct BoolSetIter(BoolSet);

impl Iterator for BoolSetIter {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.0.contains(true) {
            self.0.remove(true);
            Some(true)
        } else if self.0.contains(false) {
            self.0.remove(false);
            Some(false)
        } else {
            None
        }
    }
}

impl IntoIterator for BoolSet {
    type Item = bool;
    type IntoIter = BoolSetIter;

    fn into_iter(self) -> Self::IntoIter {
        BoolSetIter(self)
    }
}
