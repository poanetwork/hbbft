use rand::Rng;

use std::{collections, ops};

// A quick reimplementation of dynamic honey badger utility functions.
// FIXME: Why do we need `Sized` here, really?
pub trait ChooseSubset: Sized {
    type Idx;

    /// Choose a random subset of items with no duplicates.
    fn choose_subset<'a, R: Rng>(
        &'a self,
        max_subset_size: usize,
        rng: R,
    ) -> Subset<'a, Self, Self::Idx>;
}

impl<T> ChooseSubset for Vec<T> {
    type Idx = usize;

    fn choose_subset<'a, R: Rng>(
        &'a self,
        max_subset_size: usize,
        mut rng: R,
    ) -> Subset<'a, Self, Self::Idx> {
        // Indices are always from 0..len, so we are safe using a range.
        let mut indices: Vec<_> = (0..max_subset_size).collect();
        rng.shuffle(&mut indices);
        Subset { indices, col: self }
    }
}

// impl<T> ChooseSubset for collections::BTreeSet<T> {
//     fn choose_subset<'a, R: Rng>(&'a self, max_subset_size: usize, mut rng: R) -> Subset<'a, Self> {
//         unimplemented!()
//     }
// }

/// A subset iterator.
///
/// The subset is chosen by storing a list of indices and gradually removing them.
///
/// # Panics
///
/// If `indices` contains a non-existant key, the iterator will panic.
pub struct Subset<'a, C: 'a, I> {
    indices: Vec<I>,
    col: &'a C,
}

impl<'a, C: 'a, I> Subset<'a, C, I> {
    /// Create a new subset iterator.
    ///
    /// Every item in `indices` **must** be present in `col`, otherwise the iterator will likely
    /// panic on iteration.
    pub fn new(indices: Vec<I>, col: &'a C) -> Self {
        Subset { indices, col }
    }
}

impl<'a, C, I> Iterator for Subset<'a, C, I>
where
    C: ops::Index<I>,
    I: 'a,
{
    type Item = &'a <C as ops::Index<I>>::Output;

    fn next(&mut self) -> Option<Self::Item> {
        self.indices.pop().map(|idx| &self.col[idx])
    }
}
