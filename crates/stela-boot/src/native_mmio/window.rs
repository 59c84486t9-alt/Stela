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
use stela_boot_core::page_window::{self, Cache, Free, Lazy, Retirements, finish_batch};
use stela_drivers::bus::dma::memory::{CacheAttribute, PageSource, PinnedPages};

const ENTRIES: usize = 512;

struct State {
    free: Free,
    retiring: Retirements,
    /// Removed ranges waiting for one shared shootdown ([`Window::remove_lazily`]).
    lazy: Lazy,
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
                retiring: Retirements::default(),
                lazy: Lazy::default(),
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
            // The holder may be retiring a mapping, which waits for this.
            shootdown::service();
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

    /// `count` free pages' addresses, mapping nothing yet. With none, the
    /// lazily removed ranges are retired first ([`Self::purge`]).
    pub(crate) fn reserve(&self, count: usize) -> Option<u64> {
        if let Some(address) = self.lock().state().free.take(count as u64) {
            return Some(address);
        }
        if self.lock().state().lazy.is_empty() || !self.purge() {
            return None;
        }
        self.lock().state().free.take(count as u64)
    }

    /// Give back what [`Self::reserve`] returned, with nothing left installed.
    pub(crate) fn release(&self, address: u64, count: usize) {
        self.lock().state().free.give(address, count as u64);
    }

    /// Map `physical` at the reserved, empty `address`.
    pub(crate) fn install(&self, address: u64, physical: u64, cache: Cache) -> bool {
        self.install_entry(address, page_window::leaf(physical, cache))
    }

    /// Install a data leaf at an address reserved by the Linux client.
    pub(crate) fn install_client(&self, address: u64, entry: u64) -> bool {
        self.install_entry(address, entry)
    }

    fn install_entry(&self, address: u64, entry: u64) -> bool {
        if !self.contains(address) || !address.is_multiple_of(PAGE) {
            return false;
        }
        let mut guard = self.lock();
        let state = guard.state();
        if state.retiring.overlaps(&(address..address + PAGE)) {
            return false;
        }
        let Some(leaf) = self.leaf(state, address) else {
            return false;
        };
        // SAFETY: the window lock protects this owned leaf. Entries start
        // with the accessed and dirty bits set. A matching install is inert.
        unsafe {
            let current = leaf.read_volatile();
            if current == 0 {
                leaf.write_volatile(entry);
                return true;
            }
            current == entry
        }
    }

    /// The pages `address..address + count` cover, when this window may
    /// map all of them.
    fn span_of(&self, address: u64, count: usize) -> Option<core::ops::Range<u64>> {
        let end = (count as u64)
            .checked_mul(PAGE)
            .and_then(|bytes| address.checked_add(bytes))?;
        (count != 0
            && address.is_multiple_of(PAGE)
            && self.contains(address)
            && self.contains(end - 1))
        .then_some(address..end)
    }

    /// Clears the leaves of `count` pages at `address` and flushes them from
    /// this processor's TLB, under the window's lock.
    fn clear(&self, address: u64, count: usize) {
        for (pointer, directory, slots) in page_window::leaf_runs(address, count) {
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
            let table = entry_table(middle);
            for slot in slots {
                // SAFETY: each slot belongs to this existing leaf table and
                // the held guard excludes other edits.
                unsafe { table.add(slot).write_volatile(0) };
            }
        }
        // SAFETY: TLB maintenance only; these addresses hold no data access.
        unsafe {
            asm!("mfence", options(nostack, preserves_flags));
            for page in 0..count as u64 {
                let at = address + page * PAGE;
                asm!("invlpg [{}]", in(reg) at, options(nostack, preserves_flags));
            }
            asm!("mfence", options(nostack, preserves_flags));
        }
    }

    /// Unmap `count` reserved pages at `address`, whether installed or not.
    /// False when a processor may still translate through them, which leaves
    /// the caller holding their reservation for good.
    pub(crate) fn remove(&self, address: u64, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        let Some(range) = self.span_of(address, count) else {
            return false;
        };
        {
            let mut guard = self.lock();
            if !guard.state().retiring.begin(range.clone()) {
                return false;
            }
            self.clear(address, count);
        }
        if !shootdown::retire(self.tsc_hz, Some(range.clone())) {
            return false;
        }
        self.lock().state().retiring.finish(&range);
        true
    }

    /// Unmap `count` reserved pages at `address` here, and give them back
    /// to the window once a shootdown shared with other removals retired
    /// them: one shootdown per [`Lazy`] batch instead of one each. The
    /// caller does not [`Self::release`] them. False leaves them reserved.
    ///
    /// Only for mappings no processor reads or writes after their owner
    /// unmapped them and whose memory outlives a stale translation: device
    /// memory, which is never handed out as RAM. A stale translation can
    /// only name an address that stays reserved (see [`Lazy`]).
    pub(crate) fn remove_lazily(&self, address: u64, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        let Some(range) = self.span_of(address, count) else {
            return false;
        };
        let due = {
            let mut guard = self.lock();
            if !guard.state().retiring.begin(range.clone()) {
                return false;
            }
            // Flushed here before it joins a batch, as another processor's
            // purge covers only the processors it shoots down.
            self.clear(address, count);
            guard.state().lazy.defer(range)
        };
        match due {
            Ok(false) => true,
            Ok(true) => {
                // A failed purge keeps the batch for the next one.
                self.purge();
                true
            }
            Err(range) => {
                if !shootdown::retire(self.tsc_hz, Some(range.clone())) {
                    return false;
                }
                let mut guard = self.lock();
                let state = guard.state();
                finish_batch(&[range], &mut state.retiring, &mut state.free);
                true
            }
        }
    }

    /// Retire every lazily removed range with one shootdown and free them.
    /// False when a processor did not acknowledge: they wait for the next.
    pub(crate) fn purge(&self) -> bool {
        let batch = self.lock().state().lazy.take();
        if batch.is_empty() {
            return true;
        }
        // Requested after every range in the batch was cleared; peers flush
        // everything, as the batch is not one range.
        if !shootdown::retire(self.tsc_hz, None) {
            self.lock().state().lazy.restore(batch);
            return false;
        }
        let mut guard = self.lock();
        let state = guard.state();
        finish_batch(&batch, &mut state.retiring, &mut state.free);
        true
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
