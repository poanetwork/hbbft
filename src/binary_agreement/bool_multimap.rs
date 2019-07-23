use std::collections::{btree_set, BTreeSet};
use std::ops::{Index, IndexMut};

/// A map from `bool` to `BTreeSet<N>`.
#[derive(Debug, Clone)]
pub struct BoolMultimap<N>([BTreeSet<N>; 2]);

impl<N: Ord> Default for BoolMultimap<N> {
    fn default() -> Self {
        BoolMultimap([BTreeSet::default(), BTreeSet::default()])
    }
}

impl<N: Ord> Index<bool> for BoolMultimap<N> {
    type Output = BTreeSet<N>;

    fn index(&self, index: bool) -> &Self::Output {
        &self.0[if index { 1 } else { 0 }]
    }
}

impl<N: Ord> IndexMut<bool> for BoolMultimap<N> {
    fn index_mut(&mut self, index: bool) -> &mut Self::Output {
        &mut self.0[if index { 1 } else { 0 }]
    }
}

impl<'a, N: Ord> IntoIterator for &'a BoolMultimap<N> {
    type Item = (bool, &'a N);
    type IntoIter = Iter<'a, N>;

    fn into_iter(self) -> Self::IntoIter {
        Iter::new(self)
    }
}

pub struct Iter<'a, N> {
    key: bool,
    set_iter: btree_set::Iter<'a, N>,
    map: &'a BoolMultimap<N>,
}

impl<'a, N: 'a + Ord> Iter<'a, N> {
    fn new(map: &'a BoolMultimap<N>) -> Self {
        Iter {
            key: false,
            set_iter: map[false].iter(),
            map,
        }
    }
}

impl<'a, N: 'a + Ord> Iterator for Iter<'a, N> {
    type Item = (bool, &'a N);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(n) = self.set_iter.next() {
            Some((self.key, n))
        } else if self.key {
            None
        } else {
            self.key = true;
            self.set_iter = self.map[true].iter();
            self.next()
        }
    }
}
