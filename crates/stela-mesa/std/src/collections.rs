//! `alloc`'s collections, and hash tables over `hashbrown`. Its own map has no
//! constructor without a hasher unless it brings a default one in, so these
//! wrap it with `std`'s.
use crate::hash::RandomState;
use alloc_crate::collections as owned;
use core::{
    borrow::Borrow,
    fmt,
    hash::{BuildHasher, Hash},
    ops::{Deref, DerefMut, Index},
};
pub use owned::{
    BTreeMap, BTreeSet, BinaryHeap, LinkedList, VecDeque, binary_heap, btree_map, btree_set,
    vec_deque,
};

pub mod hash_map {
    pub use super::HashMap;
    pub use hashbrown::hash_map::{
        Entry, IntoIter, Iter, IterMut, Keys, OccupiedEntry, VacantEntry, Values, ValuesMut,
    };
}

pub mod hash_set {
    pub use super::HashSet;
    pub use hashbrown::hash_set::{IntoIter, Iter};
}

macro_rules! table {
    ($name:ident, [$($key:ident),+], $inner:ty, $item:ty) => {
        pub struct $name<$($key,)+ S = RandomState>($inner);

        impl<$($key,)+> $name<$($key,)+ RandomState> {
            pub fn new() -> Self {
                Self::default()
            }
            pub fn with_capacity(capacity: usize) -> Self {
                Self::with_capacity_and_hasher(capacity, RandomState::default())
            }
        }

        impl<$($key,)+ S> $name<$($key,)+ S> {
            pub const fn with_hasher(hasher: S) -> Self {
                Self(<$inner>::with_hasher(hasher))
            }
            pub fn with_capacity_and_hasher(capacity: usize, hasher: S) -> Self {
                Self(<$inner>::with_capacity_and_hasher(capacity, hasher))
            }
        }

        impl<$($key,)+ S: Default> Default for $name<$($key,)+ S> {
            fn default() -> Self {
                Self::with_hasher(S::default())
            }
        }

        impl<$($key,)+ S> Deref for $name<$($key,)+ S> {
            type Target = $inner;
            fn deref(&self) -> &$inner {
                &self.0
            }
        }

        impl<$($key,)+ S> DerefMut for $name<$($key,)+ S> {
            fn deref_mut(&mut self) -> &mut $inner {
                &mut self.0
            }
        }

        impl<$($key: Clone,)+ S: Clone> Clone for $name<$($key,)+ S> {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<$($key: fmt::Debug,)+ S> fmt::Debug for $name<$($key,)+ S> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl<$($key,)+ S> IntoIterator for $name<$($key,)+ S> {
            type Item = $item;
            type IntoIter = <$inner as IntoIterator>::IntoIter;
            fn into_iter(self) -> Self::IntoIter {
                self.0.into_iter()
            }
        }
    };
}

table!(HashMap, [K, V], hashbrown::HashMap<K, V, S>, (K, V));
table!(HashSet, [V], hashbrown::HashSet<V, S>, V);

impl<K: Eq + Hash, V: PartialEq, S: BuildHasher> PartialEq for HashMap<K, V, S> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<K: Eq + Hash, V: Eq, S: BuildHasher> Eq for HashMap<K, V, S> {}

impl<V: Eq + Hash, S: BuildHasher> PartialEq for HashSet<V, S> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<V: Eq + Hash, S: BuildHasher> Eq for HashSet<V, S> {}

impl<'a, K, V, S> IntoIterator for &'a HashMap<K, V, S> {
    type Item = (&'a K, &'a V);
    type IntoIter = hashbrown::hash_map::Iter<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, K, V, S> IntoIterator for &'a mut HashMap<K, V, S> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = hashbrown::hash_map::IterMut<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<'a, V, S> IntoIterator for &'a HashSet<V, S> {
    type Item = &'a V;
    type IntoIter = hashbrown::hash_set::Iter<'a, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<K: Eq + Hash, V, S: BuildHasher + Default> FromIterator<(K, V)> for HashMap<K, V, S> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(items: I) -> Self {
        Self(items.into_iter().collect())
    }
}

impl<V: Eq + Hash, S: BuildHasher + Default> FromIterator<V> for HashSet<V, S> {
    fn from_iter<I: IntoIterator<Item = V>>(items: I) -> Self {
        Self(items.into_iter().collect())
    }
}

impl<K: Eq + Hash, V, S: BuildHasher> Extend<(K, V)> for HashMap<K, V, S> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, items: I) {
        self.0.extend(items);
    }
}

impl<V: Eq + Hash, S: BuildHasher> Extend<V> for HashSet<V, S> {
    fn extend<I: IntoIterator<Item = V>>(&mut self, items: I) {
        self.0.extend(items);
    }
}

impl<K: Eq + Hash + Borrow<Q>, Q: Eq + Hash + ?Sized, V, S: BuildHasher> Index<&Q>
    for HashMap<K, V, S>
{
    type Output = V;
    fn index(&self, key: &Q) -> &V {
        &self.0[key]
    }
}
