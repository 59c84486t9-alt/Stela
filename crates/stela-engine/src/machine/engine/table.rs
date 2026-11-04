//! The installed blocks' table: indexed like a `Vec`, grown a chunk at a
//! time. A `Vec` doubles in one allocation, which a heap with room left only
//! in pieces may not have (several PEs' machines share one heap), and holds
//! up to half again its entries unused.
use alloc::vec::Vec;
use core::ops::{Index, IndexMut};

/// Entries per chunk.
const CHUNK: usize = 1024;

pub(super) struct Table<T> {
    chunks: Vec<Vec<T>>,
    len: usize,
}

impl<T> Table<T> {
    pub(super) const fn new() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.chunks.len() * CHUNK
    }

    /// Drop every entry, keeping the chunks for the next ones.
    pub(super) fn clear(&mut self) {
        self.chunks.iter_mut().for_each(Vec::clear);
        self.len = 0;
    }

    /// Whether [`Self::push`] has room, allocating a chunk if it needs one;
    /// false when the heap has none.
    pub(super) fn try_reserve_one(&mut self) -> bool {
        if self.len < self.chunks.len() * CHUNK {
            return true;
        }
        let mut chunk = Vec::new();
        if chunk.try_reserve_exact(CHUNK).is_err() || self.chunks.try_reserve(1).is_err() {
            return false;
        }
        self.chunks.push(chunk);
        true
    }

    /// Append `value`; its index.
    pub(super) fn push(&mut self, value: T) -> usize {
        if self.len == self.chunks.len() * CHUNK {
            self.chunks.push(Vec::with_capacity(CHUNK));
        }
        self.chunks[self.len / CHUNK].push(value);
        self.len += 1;
        self.len - 1
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        self.chunks.iter().flatten()
    }
}

impl<T> Index<usize> for Table<T> {
    type Output = T;
    fn index(&self, index: usize) -> &T {
        &self.chunks[index / CHUNK][index % CHUNK]
    }
}

impl<T> IndexMut<usize> for Table<T> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        &mut self.chunks[index / CHUNK][index % CHUNK]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_keep_their_index_across_chunks_and_a_clear_keeps_the_chunks() {
        let mut table = Table::new();
        assert!(table.is_empty());
        for value in 0..CHUNK * 2 + 3 {
            assert!(table.try_reserve_one());
            assert_eq!(table.push(value), value);
        }
        assert_eq!(table.len(), CHUNK * 2 + 3);
        assert_eq!(table[CHUNK + 5], CHUNK + 5);
        table[CHUNK * 2] = 7;
        assert_eq!(table[CHUNK * 2], 7);
        assert_eq!(table.iter().count(), table.len());
        assert_eq!(table.chunks.len(), 3);
        // Room is reserved a chunk at a time.
        let reserved = table.chunks.len();
        assert!(table.try_reserve_one());
        assert_eq!(table.chunks.len(), reserved);
        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.chunks.len(), 3);
        assert_eq!(table.push(9), 0);
        assert_eq!(table.iter().copied().collect::<Vec<_>>(), [9]);
    }
}
