use rand::Rng;

use std::{cmp, collections, iter, ops, vec};

// A quick reimplementation of dynamic honey badger utility functions.
// FIXME: Why do we need `Sized` here, really?
pub trait ChooseSubset<'a>: Sized {
    type Iter: 'a;

    /// Choose a random subset of items with no duplicates.
    fn choose_subset<R: Rng>(&'a self, max_subset_size: usize, rng: R) -> Self::Iter;
}

impl<'a, T: 'a> ChooseSubset<'a> for Vec<T> {
    type Iter = IndexSubset<'a, Self, usize>;

    fn choose_subset<R: Rng>(&'a self, max_subset_size: usize, mut rng: R) -> Self::Iter {
        // Indices are always from 0..len, so we are safe using a range.
        let mut indices: Vec<_> = (0..max_subset_size).collect();
        rng.shuffle(&mut indices);
        IndexSubset::new(indices, self)
    }
}

impl<'a, T: 'a> ChooseSubset<'a> for collections::BTreeSet<T> {
    type Iter = iter::FilterMap<
        iter::Zip<vec::IntoIter<usize>, iter::Enumerate<collections::btree_set::Iter<'a, T>>>,
        for<'t> fn((usize, (usize, &'t T))) -> Option<&'t T>,
    >;

    fn choose_subset<R: Rng>(&'a self, max_subset_size: usize, mut rng: R) -> Self::Iter {
        // Construct a list of indices into the sorted set.
        let mut nidx: Vec<_> = (0..(self.len())).collect();
        let mut indices: Vec<_> = nidx.choose_subset(max_subset_size, rng).cloned().collect();
        indices.sort();

        fn combine<'b, T>(arg: (usize, (usize, &'b T))) -> Option<&'b T> {
            let (chosen, (idx, itemref)) = arg;

            if idx == chosen {
                Some(itemref)
            } else {
                None
            }
        }

        /// We now have random indices in ascending order. We can now construct our iterator.
        indices
            .into_iter()
            .zip(self.iter().enumerate())
            .filter_map(combine)
        //     |(chosen, (idx, itemref))| if idx == *chosen { Some(itemref) } else { None },
        // )

        // return refs;

        // Selection{
        //     rev_indices: indices,
        //     cur: 0,
        //     values: self.iter(),
        // }

        // We now have random indices in ascending order. We can now construct our iterator.
        // indices
        // .into_iter()
        // .zip(self.iter().enumerate())
        // .filter_map(combine)
        // |(chosen, (idx, itemref))| if idx == *chosen { Some(itemref) } else { None },
        // )

        // let mut items = Vec::with_capacity(max_subset_size);
        // while max_subset_size > 0/
        // unimplemented!()
    }
}

pub struct Selection<I> {
    rev_indices: Vec<usize>,
    cur: usize,
    values: I,
}

impl<I> Iterator for Selection<I>
where
    I: Iterator,
{
    type Item = <I as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(target_idx) = self.rev_indices.pop() {
            while let Some(candidate) = self.values.next() {
                if self.cur == target_idx {
                    // We hit an index we want to return.
                    self.cur += 1;
                    return Some(candidate);
                } else {
                    // No hit.
                    self.cur += 1;
                }
            }
            // We ran out of items.
            return None;
        } else {
            // No more indices to get, we are done.
            None
        }
    }
}

/// A subset iterator.
///
/// The subset is chosen by storing a list of indices and gradually removing them.
///
/// # Panics
///
/// If `indices` contains a non-existant key, the iterator will panic.
pub struct IndexSubset<'a, C: 'a, I> {
    indices: Vec<I>,
    col: &'a C,
}

impl<'a, C: 'a, I> IndexSubset<'a, C, I> {
    /// Create a new index-based subset iterator.
    ///
    /// Every item in `indices` **must** be present in `col`, otherwise the iterator will likely
    /// panic on iteration.
    pub fn new(indices: Vec<I>, col: &'a C) -> Self {
        IndexSubset { indices, col }
    }
}

impl<'a, C, I> Iterator for IndexSubset<'a, C, I>
where
    C: ops::Index<I>,
    I: 'a,
{
    type Item = &'a <C as ops::Index<I>>::Output;

    fn next(&mut self) -> Option<Self::Item> {
        self.indices.pop().map(|idx| &self.col[idx])
    }
}
