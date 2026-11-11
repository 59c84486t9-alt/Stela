//! Registers every PE reads without the devices' lock
//! ([`PassiveRegisters`]): 64-bit words whose value only software's writes
//! change and whose read has no effect, such as the CPM counters CLPC's
//! samplers read tens of thousands of times a second. The model keeps each
//! such word in a [`Words`] cell it shares with the board's [`PassiveMap`];
//! its writes, which still take the lock, store there, and a read loads
//! there. Any other width, offset or register reads the locked way, where
//! the model answers or refuses as before.
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use stela_engine::machine::engine::PassiveRegisters;

/// A model's passive words, by its own index.
#[derive(Debug)]
pub struct Words(Box<[AtomicU64]>);

impl Words {
    /// `count` words, each 0.
    pub fn new(count: usize) -> Arc<Self> {
        Arc::new(Self((0..count).map(|_| AtomicU64::new(0)).collect()))
    }

    pub fn get(&self, index: usize) -> u64 {
        self.0[index].load(Ordering::Acquire)
    }

    pub fn set(&self, index: usize, value: u64) {
        self.0[index].store(value, Ordering::Release);
    }

    /// Word `index` itself, for a model that also serves it elsewhere (a
    /// System register's storage).
    pub fn cell(&self, index: usize) -> &AtomicU64 {
        &self.0[index]
    }
}

/// The board's passive words by physical address, sorted.
#[derive(Clone, Default)]
pub struct PassiveMap(Vec<(u64, Arc<Words>, usize)>);

impl PassiveMap {
    /// A 64-bit read at `physical` loads `words`' word `index`. The bus
    /// mapped `physical` to that word's model; a second entry for it
    /// replaces the first.
    pub fn add(&mut self, physical: u64, words: &Arc<Words>, index: usize) {
        let entry = (physical, Arc::clone(words), index);
        match self.0.binary_search_by_key(&physical, |&(at, ..)| at) {
            Ok(at) => self.0[at] = entry,
            Err(at) => self.0.insert(at, entry),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PassiveRegisters for PassiveMap {
    fn read(&self, physical: u64, bytes: u8) -> Option<u64> {
        if bytes != 8 {
            return None;
        }
        let at = self
            .0
            .binary_search_by_key(&physical, |&(at, ..)| at)
            .ok()?;
        let (_, words, index) = &self.0[at];
        Some(words.get(*index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_64_bit_reads_of_placed_words_are_served() {
        let words = Words::new(2);
        let mut map = PassiveMap::default();
        map.add(0x2000, &words, 1);
        map.add(0x1000, &words, 0);
        words.set(0, 7);
        words.set(1, 9);
        assert_eq!(map.read(0x1000, 8), Some(7));
        assert_eq!(map.read(0x2000, 8), Some(9));
        assert_eq!(map.read(0x2000, 4), None);
        assert_eq!(map.read(0x1008, 8), None);
        assert_eq!(map.read(0x2004, 8), None);
    }
}
