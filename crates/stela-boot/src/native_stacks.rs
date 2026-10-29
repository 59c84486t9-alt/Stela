//! Dynamic native kernel stacks from real canonical WB RAM pins.
//! Proposal only: inclusion waits for the reviewed RootPublication provider.
//! The metadata budget is the Runtime job/stack resource budget; data
//! pages are allocated fallibly for each new stack, with an absent guard.
use crate::{
    native_memory,
    native_mmio::{QualifiedRam, RootPublication},
};
use alloc::{alloc::alloc, boxed::Box, sync::Arc, vec::Vec};
use core::{
    alloc::Layout,
    cell::UnsafeCell,
    mem::ManuallyDrop,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_drivers::{
    bus::{
        dma::memory::{CacheAttribute as RamCache, PageSource},
        mmio::owned::{AliasId, ExistingAlias, PhysicalSpan},
    },
    platform::work::{Stack, StackBacking, WorkError},
};

const PAGE: usize = 4096;
const STACK_PAGES: usize = 4; // Original THREAD_SIZE for this native profile.
// Original kstack_end/THREAD_SIZE arithmetic also needs a THREAD_SIZE-aligned
// stack base. Reserve eight pages: three unused, one absent guard, four data.
const SLOT_PAGES: usize = STACK_PAGES * 2;
const MAPPED_PAGES: usize = STACK_PAGES + 1;
const GUARD_OFFSET: usize = STACK_PAGES - 1;
const ENTRIES: usize = 512;
const RIGHTS: u64 = 1 | 2 | (1 << 63); // Supervisor RW, NX; WB is checked.
const ACCESSED_DIRTY: u64 = (1 << 5) | (1 << 6);
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

fn failed<T>(_: T) -> WorkError {
    WorkError::Unavailable
}
fn reserve(publication: &Arc<RootPublication>, ram: QualifiedRam) -> Result<Table, WorkError> {
    let mut ids = Vec::new();
    ids.try_reserve_exact(ram.physical_pages().len())
        .map_err(|_| WorkError::Full)?;
    // Own every RAM/root/pin before the FIRST alias effect. On any failure,
    // Table::drop either retires all registered aliases or keeps this entire
    // preallocated bundle; uncertain retirement can never release the RAM.
    let mut table = Table {
        publication: ManuallyDrop::new(publication.clone()),
        ram: ManuallyDrop::new(ram),
        aliases: ManuallyDrop::new(ids),
        reachable: false,
    };
    for &physical in table.ram.physical_pages() {
        // SAFETY: the checked RAM page is owned by this table, which retires every reserved alias
        // before releasing it.
        let result = unsafe {
            publication.authority().reserve_alias(ExistingAlias {
                physical: PhysicalSpan::new(physical, PAGE as u64).map_err(failed)?,
                // Conservative registry reservation matches imported unknown RAM.
                // WB permission is QualifiedRam, never this None value.
                attribute: None,
            })
        };
        match result {
            Ok(id) => table.aliases.push(id),
            Err(error) => return Err(failed(error)),
        }
    }
    Ok(table)
}
struct Table {
    publication: ManuallyDrop<Arc<RootPublication>>,
    ram: ManuallyDrop<QualifiedRam>,
    aliases: ManuallyDrop<Vec<AliasId>>,
    reachable: bool,
}
impl Drop for Table {
    fn drop(&mut self) {
        if self.reachable || self.publication.check_current().is_err() {
            QUARANTINED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        for &id in self.aliases.iter() {
            // This table was never reachable, or complete parent clear/flush
            // was acknowledged by Source::retire before reachable was cleared.
            // SAFETY: the table was never reachable, or `Source::retire` cleared its parent and
            // flushed the root first.
            if unsafe { self.publication.authority().retire_alias(id) }.is_err() {
                QUARANTINED.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // SAFETY: each field is dropped once, after every alias retired.
        unsafe {
            ManuallyDrop::drop(&mut self.aliases);
            ManuallyDrop::drop(&mut self.ram);
            ManuallyDrop::drop(&mut self.publication);
        }
    }
}
#[derive(Clone, Copy)]
struct Allocation {
    id: u64,
    physical: [u64; STACK_PAGES],
}
struct State {
    directory: Table,
    leaves: Vec<Table>,
    slots: Vec<Option<Allocation>>,
    next: u64,
    parent: u64,
    published: bool,
}
pub(crate) struct Source {
    publication: ManuallyDrop<Arc<RootPublication>>,
    state: ManuallyDrop<UnsafeCell<State>>,
    held: AtomicBool,
    retired: AtomicBool,
    poisoned: AtomicBool,
    cache_bits: u64,
}
// SAFETY: only checked same-CPU process code accesses State, under held.
// RootPublication validates kept CPU/scope/root/control permission
// before any mutable read. No exclusive borrow crosses callbacks or suspension.
unsafe impl Send for Source {}
// SAFETY: shared references rely on the same argument as `Send` above.
unsafe impl Sync for Source {}
struct Held<'a>(&'a Source);
impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

impl Source {
    /// Build the table/VA metadata reservation before child admission.
    /// `slots` is the same real Runtime resource budget, not a task catalog cap.
    /// NativeMemory registration/root/cache policy may not be retargeted while
    /// this source or any stack pin/alias/frame remains; Pin alone does not
    /// programmatically exclude unsafe NativeMemory::initialize.
    pub(crate) fn new(publication: RootPublication, slots: usize) -> Result<Arc<Self>, WorkError> {
        publication.check_current().map_err(failed)?;
        let cache_bits = publication.writeback_leaf_bits().map_err(failed)?;
        if cache_bits != 0 {
            return Err(WorkError::Unavailable);
        }
        // Consume the unique publisher once. Only this source's private table
        // cleanup shares this Arc; no second VA/PD/PT suballocator is exposed.
        let publication = Arc::new(publication);
        let window = publication.window();
        let pages = slots.checked_mul(SLOT_PAGES).ok_or(WorkError::Full)?;
        if slots == 0
            || window.end.checked_sub(window.start) != Some(1 << 30)
            || !window.start.is_multiple_of((1 << 30) as u64)
            || pages > ENTRIES * ENTRIES
        {
            return Err(WorkError::InvalidStack);
        }
        let directory = Self::table_page(&publication)?;
        let mut leaves = Vec::new();
        let count = pages.div_ceil(ENTRIES);
        leaves
            .try_reserve_exact(count)
            .map_err(|_| WorkError::Full)?;
        for _ in 0..count {
            leaves.push(Self::table_page(&publication)?);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(slots)
            .map_err(|_| WorkError::Full)?;
        records.resize(slots, None);
        // Root construction keeps the image's ordinary Arc allocation policy.
        // Every per-child data/alias/Box allocation below is fallible BEFORE PID.
        let source = Arc::new(Self {
            publication: ManuallyDrop::new(publication),
            state: ManuallyDrop::new(UnsafeCell::new(State {
                directory,
                leaves,
                slots: records,
                next: 1,
                parent: 0,
                published: false,
            })),
            held: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            cache_bits,
        });
        source.publish()?;
        Ok(source)
    }
    fn table_page(publication: &Arc<RootPublication>) -> Result<Table, WorkError> {
        let pages = native_memory::SOURCE
            .allocate(PAGE, PAGE, RamCache::WriteBack)
            .map_err(failed)?;
        let ram = publication.qualify(&pages).map_err(failed)?;
        reserve(publication, ram)
    }
    fn check(&self) -> Result<(), WorkError> {
        self.publication.check_current().map_err(failed)?;
        if self.retired.load(Ordering::Acquire) || self.poisoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        Ok(())
    }
    fn lock(&self) -> Result<Held<'_>, WorkError> {
        self.check()?;
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| WorkError::Busy)?;
        Ok(Held(self))
    }
    fn publish(&self) -> Result<(), WorkError> {
        let _held = self.lock()?;
        // SAFETY: `held` gives this caller exclusive access to the state.
        let state = unsafe { &mut *self.state.get() };
        let mut guard = self.publication.acquire().map_err(failed)?;
        if guard.parent_value().map_err(failed)? != 0 {
            return Err(WorkError::Busy);
        }
        let directory = guard.table(&state.directory.ram).map_err(failed)?;
        // Validate every owned table BEFORE the shared parent becomes present.
        for index in 0..ENTRIES {
            // SAFETY: `guard.table` maps this owned page table for the guard's lifetime, and the
            // index is below `ENTRIES`.
            if unsafe { directory.as_ptr().add(index).read_volatile() } != 0 {
                return Err(WorkError::CorruptContext);
            }
        }
        for (index, table) in state.leaves.iter().enumerate() {
            let leaf = guard.table(&table.ram).map_err(failed)?;
            for at in 0..ENTRIES {
                // SAFETY: `guard.table` maps this owned page table for the guard's lifetime, and
                // the index is below `ENTRIES`.
                if unsafe { leaf.as_ptr().add(at).read_volatile() } != 0 {
                    return Err(WorkError::CorruptContext);
                }
            }
            let physical = table.ram.physical_pages()[0];
            // SAFETY: `guard.table` maps this unpublished directory for the guard's lifetime, and
            // the index is below `ENTRIES`.
            unsafe { directory.as_ptr().add(index).write_volatile(physical | 3) };
        }
        state.parent =
            // SAFETY: every owned table was checked empty above, so publishing the parent maps
            // nothing yet.
            unsafe { guard.replace_parent(0, Some(&state.directory.ram)) }.map_err(failed)?;
        state.published = true;
        state.directory.reachable = true;
        for table in &mut state.leaves {
            table.reachable = true;
        }
        // SAFETY: the guard holds the current root of this single CPU.
        if unsafe { guard.flush_root() }.is_err() {
            self.poisoned.store(true, Ordering::Release);
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
    /// Process teardown only after all Runtime frames/Backing owners
    /// have ended. All CPU-checking objects must finally Drop BEFORE the outer
    /// Clock Installed::retire. Full global kthreadd/WQ roots are image lifetime.
    pub(crate) fn retire(&self) -> Result<(), WorkError> {
        let _held = self.lock()?;
        // SAFETY: `held` gives this caller exclusive access to the state.
        let state = unsafe { &mut *self.state.get() };
        if state.slots.iter().any(Option::is_some) {
            return Err(WorkError::Pending);
        }
        {
            let mut guard = self.publication.acquire().map_err(failed)?;
            if !state.published
                || guard.parent_value().map_err(failed)? & !0x20 != state.parent & !0x20
            {
                return Err(WorkError::CorruptContext);
            }
            // SAFETY: no stack slot is live, so clearing the parent unmaps no stack in use.
            unsafe { guard.replace_parent(state.parent, None) }.map_err(failed)?;
            // Full current-root reload joins page-walk caches BEFORE any PD/PT
            // pin release. Inactive kept roots flush on their next reload;
            // this provider's single-CPU/PGE0/PCID0 gate is mandatory.
            // SAFETY: the guard holds the current root of this single CPU.
            if unsafe { guard.flush_root() }.is_err() {
                self.poisoned.store(true, Ordering::Release);
                return Err(WorkError::CorruptContext);
            }
        }
        state.published = false;
        state.parent = 0;
        state.directory.reachable = false;
        for table in &mut state.leaves {
            table.reachable = false;
        }
        self.retired.store(true, Ordering::Release);
        Ok(())
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        if self.publication.check_current().is_err() {
            QUARANTINED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // SAFETY: dropping the last reference leaves no other user of the state.
        let state = unsafe { &*self.state.get() };
        if state.published
            || state.slots.iter().any(Option::is_some)
            || self.poisoned.load(Ordering::Acquire)
        {
            QUARANTINED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Real unpublished rollback or successful parent-clear/TLB join only.
        // SAFETY: each field is dropped once, after the parent was cleared or never published.
        unsafe {
            ManuallyDrop::drop(&mut self.state);
            ManuallyDrop::drop(&mut self.publication);
        }
    }
}

struct Backing {
    source: ManuallyDrop<Arc<Source>>,
    allocation: ManuallyDrop<Table>,
    slot: usize,
    id: u64,
    bounds: Range<usize>,
    published: bool,
    uncertain: bool,
}
// SAFETY: checked WB data is mapped supervisor RW+NX in every kept
// root. Exactly the preceding VA page remains absent. The pin, table,
// root, scope and alias owners remain held until complete TLB retirement.
unsafe impl StackBacking for Backing {
    fn bounds(&self) -> Range<usize> {
        self.bounds.clone()
    }
    fn guard(&self) -> Range<usize> {
        self.bounds.start - PAGE..self.bounds.start
    }
}

impl Source {
    /// Real data/alias/metadata allocation happens before any child publication.
    /// Page-table metadata was reserved by new(), so IF0 publication allocates
    /// nothing and cannot resize an IRQ-visible/root-owned collection.
    pub(crate) fn allocate(self: &Arc<Self>) -> Result<Stack, WorkError> {
        let _held = self.lock()?;
        // SAFETY: `held` gives this caller exclusive access to the state.
        let state = unsafe { &mut *self.state.get() };
        let slot = state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(WorkError::Full)?;
        let id = state.next;
        let next = id.checked_add(1).ok_or(WorkError::Exhausted)?;
        let first = slot * SLOT_PAGES + GUARD_OFFSET;
        let start = self.publication.window().start + ((first + 1) * PAGE) as u64;
        let start = usize::try_from(start).map_err(|_| WorkError::InvalidStack)?;
        let bounds = start
            ..start
                .checked_add(STACK_PAGES * PAGE)
                .ok_or(WorkError::InvalidStack)?;
        let pin = native_memory::SOURCE
            .allocate(STACK_PAGES * PAGE, PAGE, RamCache::WriteBack)
            .map_err(failed)?;
        let data = self.publication.qualify(&pin).map_err(failed)?;
        if data.pages().page_shift() != 12 || data.pages().physical_pages().len() != STACK_PAGES {
            return Err(WorkError::InvalidStack);
        }
        let mut physical = [0; STACK_PAGES];
        physical.copy_from_slice(data.pages().physical_pages());
        // Reserve exact fallible backing storage BEFORE owning alias IDs or
        // changing any PTE. This follows NativeMemory's existing Box pattern.
        // SAFETY: `Backing` has a nonzero size.
        let storage = NonNull::new(unsafe { alloc(Layout::new::<Backing>()) })
            .ok_or(WorkError::Full)?
            .cast::<Backing>();
        let allocation = match reserve(&self.publication, data) {
            Ok(allocation) => allocation,
            Err(error) => {
                // SAFETY: `storage` came from `alloc` with this layout and was never written.
                unsafe { alloc::alloc::dealloc(storage.as_ptr().cast(), Layout::new::<Backing>()) };
                return Err(error);
            }
        };
        // SAFETY: `storage` is a fresh allocation for one `Backing`, written once before `Box`
        // takes it.
        let mut backing = unsafe {
            storage.as_ptr().write(Backing {
                source: ManuallyDrop::new(self.clone()),
                allocation: ManuallyDrop::new(allocation),
                slot,
                id,
                bounds,
                published: false,
                uncertain: false,
            });
            Box::from_raw(storage.as_ptr())
        };
        {
            let mut guard = self.publication.acquire().map_err(failed)?;
            if guard.parent_value().map_err(failed)? & !0x20 != state.parent & !0x20 {
                return Err(WorkError::CorruptContext);
            }
            let mut pointers = [NonNull::<u64>::dangling(); STACK_PAGES];
            // Exact preceding guard stays zero; none of its bytes have backing.
            let guard_table = state
                .leaves
                .get(first / ENTRIES)
                .ok_or(WorkError::InvalidStack)?;
            let guard_pointer = guard.table(&guard_table.ram).map_err(failed)?;
            // SAFETY: `guard.table` maps this owned page table for the guard's lifetime, and the
            // index is below `ENTRIES`.
            if unsafe { guard_pointer.as_ptr().add(first % ENTRIES).read_volatile() } != 0 {
                return Err(WorkError::CorruptContext);
            }
            for (offset, pointer) in pointers.iter_mut().enumerate() {
                let page = first + 1 + offset;
                let table = state
                    .leaves
                    .get(page / ENTRIES)
                    .ok_or(WorkError::InvalidStack)?;
                let base = guard.table(&table.ram).map_err(failed)?;
                // SAFETY: `base` maps an owned leaf table and the index is below `ENTRIES`.
                *pointer = unsafe { NonNull::new_unchecked(base.as_ptr().add(page % ENTRIES)) };
                // SAFETY: `guard.table` maps this owned page table for the guard's lifetime, and
                // the index is below `ENTRIES`.
                if unsafe { pointer.as_ptr().read_volatile() } != 0 {
                    return Err(WorkError::CorruptContext);
                }
            }
            // All bounded/owned-pointer checks precede the first publication.
            // No callback, allocation, ref drop or context switch occurs here.
            state.slots[slot] = Some(Allocation { id, physical });
            state.next = next;
            for (pointer, physical) in pointers.into_iter().zip(physical) {
                // SAFETY: these leaf entries are owned, mapped by the guard and were checked empty
                // above.
                unsafe {
                    pointer
                        .as_ptr()
                        .write_volatile(physical | RIGHTS | self.cache_bits)
                };
            }
            backing.published = true;
            // SAFETY: invalidates only this stack's guard and data pages in the current root.
            if unsafe { guard.invalidate(start as u64 - PAGE as u64, (MAPPED_PAGES * PAGE) as u64) }
                .is_err()
            {
                backing.uncertain = true;
                self.poisoned.store(true, Ordering::Release);
                return Err(WorkError::CorruptContext);
            }
        }
        drop(_held);
        Stack::new(backing)
    }

    fn remove(&self, backing: &Backing) -> Result<(), WorkError> {
        let _held = self.lock()?;
        // SAFETY: `held` gives this caller exclusive access to the state.
        let state = unsafe { &mut *self.state.get() };
        let record = state
            .slots
            .get(backing.slot)
            .and_then(|r| *r)
            .ok_or(WorkError::CorruptContext)?;
        if record.id != backing.id || record.physical != backing.allocation.ram.physical_pages() {
            return Err(WorkError::CorruptContext);
        }
        let first = backing.slot * SLOT_PAGES + GUARD_OFFSET;
        {
            let mut guard = self.publication.acquire().map_err(failed)?;
            if guard.parent_value().map_err(failed)? & !0x20 != state.parent & !0x20 {
                return Err(WorkError::CorruptContext);
            }
            let guard_table = state
                .leaves
                .get(first / ENTRIES)
                .ok_or(WorkError::CorruptContext)?;
            let guard_pointer = guard.table(&guard_table.ram).map_err(failed)?;
            // SAFETY: `guard.table` maps this owned page table for the guard's lifetime, and the
            // index is below `ENTRIES`.
            if unsafe { guard_pointer.as_ptr().add(first % ENTRIES).read_volatile() } != 0 {
                return Err(WorkError::CorruptContext);
            }
            let mut pointers = [NonNull::<u64>::dangling(); STACK_PAGES];
            for (offset, pointer) in pointers.iter_mut().enumerate() {
                let page = first + 1 + offset;
                let table = state
                    .leaves
                    .get(page / ENTRIES)
                    .ok_or(WorkError::CorruptContext)?;
                let base = guard.table(&table.ram).map_err(failed)?;
                // SAFETY: `base` maps an owned leaf table and the index is below `ENTRIES`.
                *pointer = unsafe { NonNull::new_unchecked(base.as_ptr().add(page % ENTRIES)) };
                // SAFETY: `guard.table` maps this owned page table for the guard's lifetime, and
                // the index is below `ENTRIES`.
                if unsafe { pointer.as_ptr().read_volatile() } & !ACCESSED_DIRTY
                    != record.physical[offset] | RIGHTS | self.cache_bits
                {
                    return Err(WorkError::CorruptContext);
                }
            }
            for pointer in pointers {
                // SAFETY: the guard maps these owned leaf entries, which were checked to hold this
                // stack.
                unsafe { pointer.as_ptr().write_volatile(0) };
            }
            // SAFETY: invalidates only this stack's guard and data pages in the current root.
            if unsafe {
                guard.invalidate(
                    backing.bounds.start as u64 - PAGE as u64,
                    (MAPPED_PAGES * PAGE) as u64,
                )
            }
            .is_err()
            {
                self.poisoned.store(true, Ordering::Release);
                return Err(WorkError::CorruptContext);
            }
        }
        // Guard dropped and native IF restored BEFORE registry/pin final drops.
        // Root publication and data owner remain held throughout this join.
        state.slots[backing.slot] = None;
        Ok(())
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        if self.uncertain || self.source.publication.check_current().is_err() {
            QUARANTINED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.published && self.source.remove(self).is_err() {
            QUARANTINED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // SAFETY: each field is dropped once, after the leaf entries were cleared and flushed or
        // never published.
        unsafe {
            // Table keeps RAM/root/pin if alias retirement fails, even after
            // successful leaf clear/TLB acknowledgement or preflight refusal.
            ManuallyDrop::drop(&mut self.allocation);
            ManuallyDrop::drop(&mut self.source);
        }
    }
}
