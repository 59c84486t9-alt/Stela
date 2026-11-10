//! The numbers a machine gives what it meets that installed code and block
//! keys hold: block variants, the fetch state in each block key
//! (`chain::block_key`), and the registers of stored cells, whose indices
//! register thunks embed (`Machine::stored_cell`). One [`Numbering`] serves
//! every machine of a board (`WorkerProfile` carries it), so a number means
//! the same on every PE, as code and tables that PEs share need.
//!
//! A [`Registry`] only grows: a number once given keeps its subject. Reads
//! take no lock, as fetches and exits read variants all the time; a new
//! number takes a lock, which only the first meeting of a subject does.

use super::Variant;
use crate::platform::sync::Mutex;
#[cfg(test)]
use alloc::vec::Vec;
use alloc::{boxed::Box, sync::Arc};
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};
use stela_compiler::aarch64::system::registers::Encoding;

/// Entries in one allocation of a [`Registry`], which never moves.
const CHUNK: usize = 64;

/// The most variants a board numbers: far above the few dozen a system
/// meets, and below what a block key's state holds (`chain::KEY_STATES`).
pub(super) const VARIANTS: usize = 1 << 16;
const _: () = assert!(2 * VARIANTS < stela_compiler::x86_64::chain::KEY_STATES as usize);

struct Chunk<T>([UnsafeCell<MaybeUninit<T>>; CHUNK]);

/// Values by number, from 0 in the order they were added, up to a fixed
/// capacity. An entry is written once, before the count that covers it is
/// published with a release store, and never again; readers load the
/// count with acquire and read the entries below it.
pub(super) struct Registry<T: Copy> {
    chunks: Box<[AtomicPtr<Chunk<T>>]>,
    /// The most numbers it gives, which callers size their cells by: not
    /// the chunks' room, which rounds up.
    capacity: usize,
    len: AtomicUsize,
    adding: Mutex<()>,
}

// SAFETY: entries are written only under `adding`, each once before its
// publication, and read only after it; `T` is plain data.
unsafe impl<T: Copy + Send> Send for Registry<T> {}
// SAFETY: as above.
unsafe impl<T: Copy + Send + Sync> Sync for Registry<T> {}

impl<T: Copy + PartialEq> Registry<T> {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            chunks: (0..capacity.div_ceil(CHUNK))
                .map(|_| AtomicPtr::new(core::ptr::null_mut()))
                .collect(),
            capacity,
            len: AtomicUsize::new(0),
            adding: Mutex::new(()),
        }
    }

    /// How many values have numbers.
    pub(super) fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    /// The value numbered `index`, if it has been added.
    pub(super) fn get(&self, index: usize) -> Option<&T> {
        (index < self.len()).then(|| self.entry(index))
    }

    /// Every value, in the order of their numbers.
    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        (0..self.len()).map(|index| self.entry(index))
    }

    /// The number of `value`, if it has one.
    pub(super) fn find(&self, value: &T) -> Option<usize> {
        self.iter().position(|known| known == value)
    }

    /// The number of `value`, given now if it has none, there is room and
    /// `admit` allows it.
    pub(super) fn find_or_add(&self, value: T, admit: impl FnOnce() -> bool) -> Option<usize> {
        if let Some(index) = self.find(&value) {
            return Some(index);
        }
        let _adding = self.adding.lock().unwrap_or_else(|e| e.into_inner());
        // Another machine may have added it meanwhile.
        let len = self.len.load(Ordering::Relaxed);
        if let Some(index) = (0..len).position(|index| *self.entry(index) == value) {
            return Some(index);
        }
        if len == self.capacity || !admit() {
            return None;
        }
        let chunk = &self.chunks[len / CHUNK];
        let mut held = chunk.load(Ordering::Relaxed);
        if held.is_null() {
            let fresh = Box::new(Chunk(core::array::from_fn(|_| {
                UnsafeCell::new(MaybeUninit::uninit())
            })));
            held = Box::into_raw(fresh);
            chunk.store(held, Ordering::Release);
        }
        // SAFETY: the chunk is allocated and only this holder of `adding`
        // writes; the entry at `len` is not published, so nothing reads it.
        unsafe { (*(*held).0[len % CHUNK].get()).write(value) };
        self.len.store(len + 1, Ordering::Release);
        Some(len)
    }

    /// The values, for a test.
    #[cfg(test)]
    pub(super) fn to_vec(&self) -> Vec<T> {
        self.iter().copied().collect()
    }

    fn entry(&self, index: usize) -> &T {
        let chunk = self.chunks[index / CHUNK].load(Ordering::Acquire);
        // SAFETY: `index` is below a count loaded with acquire, which was
        // published after its chunk and its entry were written; neither
        // changes again until the registry drops.
        unsafe { (*(*chunk).0[index % CHUNK].get()).assume_init_ref() }
    }
}

impl<T: Copy + PartialEq> core::ops::Index<usize> for Registry<T> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        self.get(index).expect("a numbered value")
    }
}

impl<T: Copy + PartialEq + core::fmt::Debug> core::fmt::Debug for Registry<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: Copy> Drop for Registry<T> {
    fn drop(&mut self) {
        for chunk in self.chunks.iter_mut() {
            let held = *chunk.get_mut();
            if !held.is_null() {
                // SAFETY: allocated by `find_or_add` with `Box::into_raw`,
                // and no reference outlives the registry.
                drop(unsafe { Box::from_raw(held) });
            }
        }
    }
}

/// The registries every machine of a board numbers through.
#[derive(Clone)]
pub(super) struct Numbering {
    pub(super) variants: Arc<Registry<Variant>>,
    pub(super) stored_reads: Arc<Registry<Encoding>>,
    pub(super) stored_writes: Arc<Registry<Encoding>>,
}

impl Numbering {
    pub(super) fn new() -> Self {
        Self {
            variants: Arc::new(Registry::new(VARIANTS)),
            stored_reads: Arc::new(Registry::new(super::mirrors::STORED_CELLS)),
            stored_writes: Arc::new(Registry::new(super::mirrors::STORED_WRITES)),
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// Numbers stay with their values, whoever asks first; many threads
    /// adding at once give each value one number, and a full registry or a
    /// refusal gives none.
    #[test]
    fn every_machine_gets_one_number_per_value() {
        let registry = Arc::new(Registry::<u64>::new(3 * CHUNK));
        let threads: Vec<_> = (0..8)
            .map(|thread| {
                let registry = registry.clone();
                std::thread::spawn(move || {
                    (0..2 * CHUNK as u64)
                        .map(|value| {
                            let value = (value + thread * 7) % (2 * CHUNK as u64);
                            (value, registry.find_or_add(value, || true).unwrap())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for thread in threads {
            for (value, index) in thread.join().unwrap() {
                assert_eq!(registry[index], value);
            }
        }
        assert_eq!(registry.len(), 2 * CHUNK);
        let mut values = registry.to_vec();
        values.sort_unstable();
        assert_eq!(values, (0..2 * CHUNK as u64).collect::<Vec<_>>());
        assert_eq!(registry.find_or_add(1000, || false), None);
        for value in 0..CHUNK as u64 {
            assert!(registry.find_or_add(1000 + value, || true).is_some());
        }
        assert_eq!(registry.find_or_add(5000, || true), None, "full");
        assert_eq!(registry.find(&1000), Some(2 * CHUNK));
        assert_eq!(registry.get(3 * CHUNK), None);
    }

    /// A worker machine numbers through its home machine's registries, so
    /// a variant either meets first has one number on both; a machine of
    /// another board numbers apart.
    #[test]
    fn a_board_numbers_once_for_every_machine() {
        use super::super::{NoDevices, tests::board};
        use stela_contracts::identity::Identity;
        let identities = (0..2)
            .map(|pe| Identity {
                midr: 0x611f_0320,
                mpidr: 0x8000_0000 | pe << 8,
                clock: None,
                caches: None,
            })
            .collect::<Vec<_>>();
        let mut home = board(&[], NoDevices, identities.clone());
        let prepared = board(&[], NoDevices, identities.clone());
        let mut worker = home
            .worker_profile()
            .start(prepared.cpu, prepared.host, prepared.devices, 1)
            .unwrap();
        assert!(Arc::ptr_eq(&home.variants, &worker.variants));
        assert!(Arc::ptr_eq(&home.stored_reads, &worker.stored_reads));
        assert!(Arc::ptr_eq(&home.stored_writes, &worker.stored_writes));
        let variant = worker.current_variant(true, false);
        let id = worker.variant_id(variant);
        assert_eq!(home.known_variant(variant), Some(id));
        assert_eq!(home.variant_id(variant), id);
        let other = home.current_variant(false, true);
        assert_eq!(worker.known_variant(other), None);
        let next = home.variant_id(other);
        assert_ne!(next, id);
        assert_eq!(worker.known_variant(other), Some(next));
        let apart = board(&[], NoDevices, identities);
        assert_eq!(apart.known_variant(variant), None);
    }

    /// A board gives no more stored-write numbers than each PE has write
    /// cells, though the chunks hold more; a PE that meets a cell another
    /// numbered opens its own, not the other's, on its own write.
    #[test]
    fn a_pe_opens_its_own_cell_of_a_write_another_numbered() {
        use super::super::{
            NoDevices,
            mirrors::{STORED_WRITES, stored_write_cell},
            tests::board,
        };
        use crate::machine::exception::Pstate;
        use stela_contracts::identity::Identity;
        const MSR: u32 = 0xd51c_fdc6; // msr s3_4_c15_c13_6, x6
        let encoding = crate::machine::impdef::THREAD_KEY_0;
        let identities = (0..2)
            .map(|pe| Identity {
                midr: 0x611f_0320,
                mpidr: 0x8000_0000 | pe << 8,
                clock: None,
                caches: None,
            })
            .collect::<Vec<_>>();
        let home = board(&[], NoDevices, identities.clone());
        let prepared = board(&[], NoDevices, identities);
        let mut worker = home
            .worker_profile()
            .start(prepared.cpu, prepared.host, prepared.devices, 1)
            .unwrap();
        // The home PE numbers every write cell, the thread key last.
        for index in 0..STORED_WRITES as u8 - 1 {
            let other = Encoding::new(3, 7, 15, index / 8, index % 8);
            assert_eq!(
                home.stored_writes.find_or_add(other, || true),
                Some(index.into())
            );
        }
        let last = home.stored_writes.find_or_add(encoding, || true);
        assert_eq!(last, Some(STORED_WRITES - 1));
        let beyond = Encoding::new(3, 7, 15, 15, 7);
        assert_eq!(home.stored_writes.find_or_add(beyond, || true), None);
        // The worker's write completes and opens its own cell alone.
        worker.cpu.pstate = Pstate::reset(2);
        worker.derived_changed();
        worker.cpu.state.x[6] = 0x77;
        worker.system_instruction(MSR).unwrap();
        let storage = worker.cpu.impdef(encoding).unwrap();
        let address = worker.cpu.apple.impdef.storage(storage);
        let cell = worker.mirrors[stored_write_cell(STORED_WRITES - 1)];
        assert_eq!((cell.readable, cell.value), (1, address));
        assert_eq!(
            home.mirrors[stored_write_cell(STORED_WRITES - 1)].readable,
            0
        );
    }
}
