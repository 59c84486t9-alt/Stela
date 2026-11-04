//! The host's page window (`stela_boot_core::page_window`): 4 KiB pages in
//! tables hung off the aperture's directory-pointer table. Roots share that
//! table through the aperture's top-level entry, so a mapping made here reaches
//! every host processor with no further work.
//!
//! Filling an empty slot needs no flush, as the processor caches no absent
//! translation. Removing one flushes here and shoots down the rest, as the
//! aperture's retirement does; a processor that does not answer keeps its
//! slots reserved, so nothing can be mapped under a stale translation.
use super::{ADDRESS, PAGE, PRESENT, WRITABLE, capture::Wire, shootdown};
use crate::{layout, native_memory};
use alloc::vec::Vec;
use core::{
    arch::asm,
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_boot_core::page_window::{self, Cache, Free};
use stela_drivers::bus::dma::memory::{CacheAttribute, PageSource, PinnedPages};

const ENTRIES: usize = 512;

struct State {
    free: Free,
    /// The pages of the tables the window grew. They last as long as it does.
    tables: Vec<PinnedPages>,
}

pub(crate) struct Window {
    /// The directory-pointer table the aperture sits in, by its physmap alias.
    pointers: *mut u64,
    tsc_hz: u64,
    held: AtomicBool,
    state: UnsafeCell<State>,
}

// SAFETY: the table pointer is immutable and `state` is reached only under
// `held`.
unsafe impl Send for Window {}
// SAFETY: as above.
unsafe impl Sync for Window {}

/// The physmap alias of the table at `physical`.
fn table(physical: u64) -> *mut u64 {
    layout::physical(physical) as *mut u64
}

fn entry_table(entry: u64) -> *mut u64 {
    table(entry & ADDRESS)
}

/// An index of a virtual address, `shift` bits up.
fn index(address: u64, shift: u32) -> usize {
    (address >> shift) as usize % ENTRIES
}

impl Window {
    /// The window of the aperture `wire` describes, in the root the loader
    /// built. `pat` is the processors' shared IA32_PAT.
    ///
    /// # Safety
    /// `wire` is this boot's sealed capture and its tables are the loader's.
    pub(super) unsafe fn new(wire: &Wire, pat: u64, tsc_hz: u64) -> Option<Self> {
        let selected = pat >> (8 * page_window::WRITE_COMBINING_INDEX) & 0xff;
        if selected != 1 {
            return None;
        }
        let mut level = table(wire.root);
        if wire.levels == 5 {
            // SAFETY: the loader's root, a bounded index.
            let entry = unsafe { level.add(index(wire.virtual_base, 48)).read_volatile() };
            if entry & PRESENT == 0 {
                return None;
            }
            level = entry_table(entry);
        }
        // SAFETY: as above.
        let entry = unsafe { level.add(index(wire.virtual_base, 39)).read_volatile() };
        if entry & PRESENT == 0 {
            return None;
        }
        Some(Self {
            pointers: entry_table(entry),
            tsc_hz,
            held: AtomicBool::new(false),
            state: UnsafeCell::new(State {
                free: Free::new(page_window::span(layout::window())),
                tables: Vec::new(),
            }),
        })
    }

    fn lock(&self) -> Guard<'_> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard(self)
    }

    /// `slot`'s next-level table, grown from the native allocator when absent.
    fn grow(state: &mut State, slot: *mut u64) -> Option<*mut u64> {
        // SAFETY: a slot of a table this window reaches, under its lock.
        let entry = unsafe { slot.read_volatile() };
        if entry & PRESENT != 0 {
            return Some(entry_table(entry));
        }
        state.tables.try_reserve(1).ok()?;
        let bytes = PAGE as usize;
        let pages = native_memory::SOURCE
            .allocate(bytes, bytes, CacheAttribute::WriteBack)
            .ok()?;
        let physical = *pages.physical_pages().first()?;
        // SAFETY: an empty slot; the page is zeroed, so the table maps nothing.
        unsafe { slot.write_volatile(physical | PRESENT | WRITABLE) };
        state.tables.push(pages);
        Some(table(physical))
    }

    fn leaf(&self, state: &mut State, address: u64) -> Option<*mut u64> {
        let [pointer, directory, page] = page_window::indices(address);
        // SAFETY: the aperture's table, a bounded index.
        let directories = Self::grow(state, unsafe { self.pointers.add(pointer) })?;
        // SAFETY: as above, in a table `grow` just reached.
        let leaves = Self::grow(state, unsafe { directories.add(directory) })?;
        // SAFETY: as above.
        Some(unsafe { leaves.add(page) })
    }

    /// Whether `address` is one this window may map.
    pub(crate) fn contains(&self, address: u64) -> bool {
        page_window::span(layout::window()).contains(&address)
    }

    /// `count` free pages' addresses, mapping nothing yet.
    pub(crate) fn reserve(&self, count: usize) -> Option<u64> {
        self.lock().state().free.take(count as u64)
    }

    /// Give back what [`Self::reserve`] returned, with nothing left installed.
    pub(crate) fn release(&self, address: u64, count: usize) {
        self.lock().state().free.give(address, count as u64);
    }

    /// Map `physical` at the reserved, empty `address`.
    pub(crate) fn install(&self, address: u64, physical: u64, cache: Cache) -> bool {
        let mut guard = self.lock();
        let Some(leaf) = self.leaf(guard.state(), address) else {
            return false;
        };
        // SAFETY: a leaf this window owns, under its lock.
        unsafe { leaf.write_volatile(page_window::leaf(physical, cache)) };
        true
    }

    /// Install a data leaf at an address reserved by the Linux client. A repeat
    /// fault on the same page needs no write. Replacement requires retirement.
    pub(crate) fn install_client(&self, address: u64, entry: u64) -> bool {
        if !self.contains(address) || !address.is_multiple_of(PAGE) {
            return false;
        }
        let mut guard = self.lock();
        let Some(leaf) = self.leaf(guard.state(), address) else {
            return false;
        };
        // SAFETY: the window lock protects software access to this owned leaf.
        // Client entries publish the accessed and dirty bits already set.
        unsafe {
            let current = leaf.read_volatile();
            if current == 0 {
                leaf.write_volatile(entry);
                return true;
            }
            current == entry
        }
    }

    /// Map `physical` at the reserved, empty `address`, to run from.
    pub(crate) fn install_code(&self, address: u64, physical: u64) -> bool {
        let mut guard = self.lock();
        let Some(leaf) = self.leaf(guard.state(), address) else {
            return false;
        };
        // SAFETY: a leaf this window owns, under its lock.
        unsafe { leaf.write_volatile(page_window::code_leaf(physical)) };
        true
    }

    /// Unmap `count` reserved pages at `address`, whether installed or not.
    /// False when a processor may still translate through them, which leaves
    /// the caller holding their reservation for good.
    pub(crate) fn remove(&self, address: u64, count: usize) -> bool {
        let mut guard = self.lock();
        for page in 0..count as u64 {
            let at = address + page * PAGE;
            let [pointer, directory, _] = page_window::indices(at);
            // SAFETY: the aperture's table, a bounded index.
            let upper = unsafe { self.pointers.add(pointer).read_volatile() };
            if upper & PRESENT == 0 {
                continue;
            }
            // SAFETY: a table this window grew.
            let middle = unsafe { entry_table(upper).add(directory).read_volatile() };
            if middle & PRESENT == 0 {
                continue;
            }
            if let Some(leaf) = self.leaf(guard.state(), at) {
                // SAFETY: a leaf this window owns, under its lock.
                unsafe { leaf.write_volatile(0) };
            }
        }
        drop(guard);
        // SAFETY: TLB maintenance only; these addresses hold no data access.
        unsafe {
            asm!("mfence", options(nostack, preserves_flags));
            for page in 0..count as u64 {
                let at = address + page * PAGE;
                asm!("invlpg [{}]", in(reg) at, options(nostack, preserves_flags));
            }
            asm!("mfence", options(nostack, preserves_flags));
        }
        shootdown::retire(self.tsc_hz)
    }
}

struct Guard<'a>(&'a Window);

impl Guard<'_> {
    fn state(&mut self) -> &mut State {
        // SAFETY: the held lock; nothing here calls back.
        unsafe { &mut *self.0.state.get() }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}
