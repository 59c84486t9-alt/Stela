//! Native system-RAM pins backed by the mount's existing reusable heap.
//!
//! Allocation and the final release of any pin/CPU/DMA mapping must occur in
//! process or deferred-work context. Raw heap exclusion is maskable-IRQ safe;
//! that does not qualify pin/cache checks or mapping lifetime transitions in
//! an ISR. This service is not a VRAM allocator or an IOMMU.
use alloc::{boxed::Box, vec::Vec};
use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
use stela_drivers::bus::dma::memory::{
    CacheAttribute, MemoryError, PageBacking, PageGeometry, PageSource, PinnedPages,
};

#[cfg(not(test))]
use crate::ALLOCATOR;
#[cfg(test)]
#[path = "heap.rs"]
#[allow(dead_code)]
mod test_heap;
#[cfg(test)]
static ALLOCATOR: test_heap::Heap = test_heap::Heap::new();

const PAGE_SHIFT: u8 = 12;
const PAGE: usize = 1 << PAGE_SHIFT;

#[cfg_attr(test, path = "native_memory/cache.rs")]
pub(crate) mod cache;

pub static SOURCE: NativeMemory = NativeMemory {
    cpu: AtomicUsize::new(0),
    physical: AtomicU64::new(0),
    bytes: AtomicUsize::new(0),
    table_offset: AtomicU64::new(0),
    generation: AtomicU64::new(0),
    catalogs: AtomicUsize::new(0),
};

pub struct NativeMemory {
    cpu: AtomicUsize,
    physical: AtomicU64,
    bytes: AtomicUsize,
    table_offset: AtomicU64,
    generation: AtomicU64,
    catalogs: AtomicUsize,
}

/// Register the existing heap's true CPU/physical mapping once in each phase.
///
/// # Safety
/// The heap has just been initialized over exactly this firmware-reserved,
/// exclusively owned, page-aligned RAM extent. It is excluded from every guest
/// and free-memory inventory. Its writable WB mapping and all aliases remain
/// valid and compatible across every root change until the final allocation
/// release. There are no allocations from a previous registered heap still
/// alive, nor concurrent users of this registration. Only process/deferred
/// context may register/retire a Linux page catalog; every catalog must be
/// retired first. A quarantined catalog forbids retargeting this source.
/// Only process/deferred context may allocate or perform the last release,
/// including Arc/lease Drop.
/// Adding `table_offset` to each current CR3-reachable table PA must yield a
/// readable retained mapping of that complete page (zero for identity, the
/// explicit physmap offset in the engine). Root changes, migration and cache
/// policy changes are excluded during allocation/cache qualification.
pub unsafe fn initialize(cpu: usize, physical: u64, bytes: usize, table_offset: u64) {
    assert_eq!(SOURCE.catalogs.load(Ordering::Acquire), 0);
    let generation = SOURCE
        .generation
        .load(Ordering::Relaxed)
        .checked_add(1)
        .expect("native memory generation exhausted");
    assert!(cpu != 0 && cpu.is_multiple_of(PAGE));
    assert!(physical.is_multiple_of(PAGE as u64));
    assert!(bytes != 0 && bytes.is_multiple_of(PAGE));
    assert!(cpu.checked_add(bytes).is_some());
    assert!(physical.checked_add(bytes as u64).is_some());
    SOURCE.cpu.store(cpu, Ordering::Relaxed);
    SOURCE.physical.store(physical, Ordering::Relaxed);
    SOURCE.table_offset.store(table_offset, Ordering::Relaxed);
    SOURCE.bytes.store(bytes, Ordering::Release);
    SOURCE.generation.store(generation, Ordering::Release);
}

/// Retains this native source generation while Linux descriptors can refer to
/// it. Registration does not import ordinary heap bytes as Linux payload pages.
#[cfg(not(test))]
pub struct LinuxPages {
    generation: u64,
}

#[cfg(not(test))]
impl Drop for LinuxPages {
    fn drop(&mut self) {
        let previous = SOURCE.catalogs.fetch_sub(1, Ordering::AcqRel);
        assert!(previous != 0);
    }
}

// SAFETY: initialize owns the exact native heap and retained WB mapping. The
// catalog count prevents generation retargeting; each allocation goes through
// the same real zeroed PageSource and retains its backing until quiescent Drop.
// Preflight refuses unsupported flags and contexts before any heap/cache work.
#[cfg(not(test))]
unsafe impl stela_drivers::gpu::linux::pages::Provider for LinuxPages {
    fn validate(
        &self,
        request: stela_drivers::gpu::linux::pages::Request,
    ) -> Result<(), MemoryError> {
        if SOURCE.generation.load(Ordering::Acquire) != self.generation
            || request.atomic
            || !request.basic_ram()
            || !request.may_block()
        {
            return Err(MemoryError::Unavailable);
        }
        request.bytes().ok_or(MemoryError::InvalidSize)?;
        Ok(())
    }

    fn allocate(
        &self,
        request: stela_drivers::gpu::linux::pages::Request,
    ) -> Result<PinnedPages, MemoryError> {
        self.validate(request)?;
        let bytes = request.bytes().ok_or(MemoryError::InvalidSize)?;
        SOURCE.allocate(bytes, bytes, CacheAttribute::WriteBack)
    }
}

/// Bind the actual registered heap to Linux's native page service.
///
/// # Safety
/// Process/deferred context excludes migration, root/cache writers and native
/// IRQ/reentry for registration, use and retirement. The registered heap and
/// mapping remain owned through every pin and any quarantined catalog. The
/// caller retires the catalog before switching allocator/source generations.
#[cfg(not(test))]
pub unsafe fn linux_pages() -> Result<
    stela_drivers::gpu::linux::pages::Catalog<LinuxPages>,
    stela_drivers::gpu::linux::pages::Error,
> {
    use stela_drivers::gpu::linux::pages::{Catalog, Error, Reservation};
    let generation = SOURCE.generation.load(Ordering::Acquire);
    let bytes = SOURCE.bytes.load(Ordering::Acquire);
    if generation == 0 || bytes == 0 {
        return Err(Error::InvalidReservation);
    }
    let cpu = NonNull::new(SOURCE.cpu.load(Ordering::Relaxed) as *mut u8)
        .ok_or(Error::InvalidReservation)?;
    let physical = SOURCE.physical.load(Ordering::Relaxed);
    // SAFETY: the live native registration proves this exact retained mapping.
    let reservation = unsafe { Reservation::new(physical, cpu, bytes / PAGE)? };
    SOURCE
        .catalogs
        .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            count.checked_add(1)
        })
        .map_err(|_| Error::OutOfMemory)?;
    let provider = LinuxPages { generation };
    // SAFETY: inherited exclusive context/mapping contract; provider owns the
    // source-generation count through success, failure and quarantine.
    unsafe { Catalog::register(provider, reservation) }
}

/// Qualify an existing loader reservation through the SAME current mapping
/// and vendor-specific effective-memory-type decoder used by native pages.
/// This does not allocate/copy RAM or authorize a new physical alias.
///
/// # Safety
/// The exact reservation/CPU mapping is retained for the boot lifetime; root,
/// cache controls and physical ownership cannot change during this check.
#[cfg(not(test))]
pub(crate) unsafe fn qualify_reserved_writeback(
    cpu: u64,
    physical: u64,
    bytes: usize,
) -> Result<(), MemoryError> {
    cache::verify_writeback(
        cpu,
        physical,
        bytes,
        SOURCE.table_offset.load(Ordering::Acquire),
    )
}

/// Exercise the actual registered mapping and allocator, including retained
/// CPU lifetime and zeroed page-tail access. Called by the mount's host check.
pub fn verify() -> Result<(), MemoryError> {
    let before = ALLOCATOR.usage().live;
    #[cfg(not(test))]
    {
        // SAFETY: the existing native diagnostic runs in the registered
        // process/deferred context, with root/cache writers excluded.
        let mut catalog = unsafe { linux_pages() }.map_err(|_| MemoryError::Unavailable)?;
        catalog.verify().map_err(|error| {
            crate::output::arguments(format_args!("CHECK Linux page catalog FAIL {error:?}\n"));
            MemoryError::InvalidPageList
        })?;
        catalog.try_retire().map_err(|_| MemoryError::Unavailable)?;
    }
    if !matches!(
        SOURCE.allocate(PAGE, PAGE, CacheAttribute::WriteCombining),
        Err(MemoryError::CacheAttributeUnavailable)
    ) || !matches!(
        SOURCE.allocate(PAGE, 3, CacheAttribute::WriteBack),
        Err(MemoryError::InvalidAlignment)
    ) {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    let pages = SOURCE.allocate(PAGE + 1, PAGE, CacheAttribute::WriteBack)?;
    if pages.logical_bytes() != PAGE + 1 || pages.bytes() != 2 * PAGE {
        return Err(MemoryError::InvalidSize);
    }
    let mapping = pages.cpu_mapping(CacheAttribute::WriteBack)?;
    if !matches!(
        pages.cpu_mapping(CacheAttribute::Uncached),
        Err(MemoryError::CacheAttributeUnavailable)
    ) || mapping.address(usize::MAX, 1) != Err(MemoryError::InvalidSize)
        || mapping.address(mapping.bytes(), 1) != Err(MemoryError::InvalidSize)
    {
        return Err(MemoryError::InvalidSize);
    }
    let pointer = mapping.address(0, mapping.bytes())?.as_ptr();
    let offset = (pointer as usize)
        .checked_sub(SOURCE.cpu.load(Ordering::Relaxed))
        .ok_or(MemoryError::OutsideReservation)?;
    let physical = SOURCE.physical.load(Ordering::Relaxed) + offset as u64;
    if pages.physical_pages() != [physical, physical + PAGE as u64] {
        return Err(MemoryError::InvalidPageList);
    }
    drop(pages);
    for index in 0..mapping.bytes() {
        // SAFETY: CPU-exclusive owned RAM with the retained mapping live.
        if unsafe { pointer.add(index).read_volatile() } != 0 {
            return Err(MemoryError::InvalidPageList);
        }
    }
    // SAFETY: this exclusive CPU mapping includes its full last-page tail.
    unsafe {
        pointer.add(2 * PAGE - 1).write_volatile(0x5a);
        if pointer.add(2 * PAGE - 1).read_volatile() != 0x5a {
            return Err(MemoryError::OutsideReservation);
        }
    }
    drop(mapping);
    if ALLOCATOR.usage().live != before {
        return Err(MemoryError::OutsideReservation);
    }
    Ok(())
}

impl PageSource for NativeMemory {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        if self.bytes.load(Ordering::Acquire) == 0 {
            return Err(MemoryError::Unavailable);
        }
        // This allocator records PAGE_SHIFT for every real returned backing.
        // A large byte capacity/alignment does not establish a larger granule.
        PageGeometry::base_only(PAGE_SHIFT)
    }

    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        if attribute != CacheAttribute::WriteBack {
            return Err(MemoryError::CacheAttributeUnavailable);
        }
        if !alignment.is_power_of_two() {
            return Err(MemoryError::InvalidAlignment);
        }
        if bytes == 0 {
            return Err(MemoryError::InvalidSize);
        }
        let capacity = self.bytes.load(Ordering::Acquire);
        if capacity == 0 {
            return Err(MemoryError::Unavailable);
        }
        let logical_bytes = bytes;
        let bytes = bytes
            .checked_next_multiple_of(PAGE)
            .ok_or(MemoryError::InvalidSize)?;
        let layout = Layout::from_size_align(bytes, alignment.max(PAGE))
            .map_err(|_| MemoryError::InvalidAlignment)?;
        let cpu = self.cpu.load(Ordering::Relaxed);
        let physical_base = self.physical.load(Ordering::Relaxed);
        // A linear heap cannot satisfy simultaneous CPU/PA alignment when
        // their registered bases have incompatible residues. Refuse it.
        if ((cpu as u64) ^ physical_base) & (layout.align() as u64 - 1) != 0 {
            return Err(MemoryError::InvalidAlignment);
        }
        // SAFETY: initialize registered the live heap. Pin/cache operations
        // remain in process/deferred context even though the raw heap is IRQ-safe.
        let pointer = NonNull::new(unsafe { ALLOCATOR.alloc_zeroed(layout) })
            .ok_or(MemoryError::OutOfMemory)?;
        // Own the payload before any validation or metadata allocation can fail.
        let mut backing = HeapAllocation {
            pointer,
            layout,
            pages: Vec::new(),
        };
        let start = pointer.as_ptr() as usize;
        let offset = start
            .checked_sub(cpu)
            .filter(|offset| offset.checked_add(bytes).is_some_and(|end| end <= capacity));
        let Some(offset) = offset else {
            return Err(MemoryError::OutsideReservation);
        };
        let physical = physical_base + offset as u64;
        #[cfg(not(test))]
        cache::verify_writeback(
            start as u64,
            physical,
            bytes,
            self.table_offset.load(Ordering::Relaxed),
        )?;
        backing
            .pages
            .try_reserve_exact(bytes / PAGE)
            .map_err(|_| MemoryError::OutOfMemory)?;
        backing
            .pages
            .extend((0..bytes / PAGE).map(|index| physical + (index * PAGE) as u64));
        // The stable Box constructor aborts on OOM. Reserve its exact nonzero
        // storage fallibly before transferring this unique payload owner.
        // SAFETY: a valid nonzero layout for a fully initialized backing.
        let storage = NonNull::new(unsafe { alloc::alloc::alloc(Layout::new::<HeapAllocation>()) })
            .ok_or(MemoryError::OutOfMemory)?
            .cast::<HeapAllocation>();
        // SAFETY: fresh aligned global allocation, initialized once. Box takes
        // that exact allocation/layout and owns the backing on every later path.
        let backing = unsafe {
            storage.as_ptr().write(backing);
            Box::from_raw(storage.as_ptr())
        };
        PinnedPages::new(backing, logical_bytes, layout.align())
    }
}

struct HeapAllocation {
    pointer: NonNull<u8>,
    layout: Layout,
    pages: Vec<u64>,
}

// SAFETY: the pointer is an owned, immovable allocation. No safe CPU data
// references are exposed. Consumers synchronize raw CPU/device accesses and
// never do final release in hard IRQ context; metadata is immutable.
unsafe impl Send for HeapAllocation {}
// SAFETY: shared access exposes immutable metadata and raw pointers only.
unsafe impl Sync for HeapAllocation {}

// SAFETY: initialize proves the native heap's actual contiguous PA mapping;
// allocate retains a full aligned/zeroed extent and records every real page.
// Drop returns it to the same allocator only after the last Arc-backed lease.
unsafe impl PageBacking for HeapAllocation {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pointer
    }

    fn physical_pages(&self) -> &[u64] {
        &self.pages
    }

    fn page_shift(&self) -> u8 {
        PAGE_SHIFT
    }

    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}

impl Drop for HeapAllocation {
    fn drop(&mut self) {
        // SAFETY: this owner is released only after every pin/mapping ends,
        // using the exact allocation and layout, in process/deferred context.
        unsafe { ALLOCATOR.dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::alloc::Layout;

    // Only the hosted test executable uses this allocator. Each armed window
    // is thread-local and contains no harness/assertion work. The production
    // provider has no fault hook or alternate allocation path.
    pub(super) mod allocation_failure {
        use std::{
            alloc::{GlobalAlloc, Layout, System},
            cell::Cell,
        };

        #[derive(Clone, Copy, Default)]
        pub struct Observation {
            active: bool,
            remaining: Option<usize>,
            pub attempts: usize,
            pub denied: usize,
            pointers: [usize; 8],
            pub overflow: bool,
        }

        std::thread_local! {
            static STATE: Cell<Observation> = const { Cell::new(Observation {
                active: false, remaining: None, attempts: 0, denied: 0,
                pointers: [0; 8], overflow: false,
            }) };
        }

        pub struct Allocator;
        // SAFETY: all storage uses System with unchanged layouts. An armed
        // request may return null as GlobalAlloc permits; successful pointer
        // provenance and deallocation are unchanged.
        unsafe impl GlobalAlloc for Allocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                let deny = STATE
                    .try_with(|state| {
                        let mut value = state.get();
                        if !value.active {
                            return false;
                        }
                        value.attempts += 1;
                        let denied = value.remaining == Some(0);
                        value.remaining = value.remaining.and_then(|left| left.checked_sub(1));
                        value.denied += usize::from(denied);
                        state.set(value);
                        denied
                    })
                    .unwrap_or(false);
                if deny {
                    return core::ptr::null_mut();
                }
                // SAFETY: original caller's valid allocation layout.
                let pointer = unsafe { System.alloc(layout) };
                if !pointer.is_null() {
                    let _ = STATE.try_with(|state| {
                        let mut value = state.get();
                        if value.active {
                            if let Some(slot) = value.pointers.iter_mut().find(|slot| **slot == 0) {
                                *slot = pointer as usize;
                            } else {
                                value.overflow = true;
                            }
                            state.set(value);
                        }
                    });
                }
                pointer
            }

            unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
                let _ = STATE.try_with(|state| {
                    let mut value = state.get();
                    if value.active {
                        if let Some(slot) = value
                            .pointers
                            .iter_mut()
                            .find(|slot| **slot == pointer as usize)
                        {
                            *slot = 0;
                        }
                        state.set(value);
                    }
                });
                // SAFETY: original successful System allocation and layout.
                unsafe { System.dealloc(pointer, layout) };
            }
        }

        pub fn arm(successes: usize) {
            STATE.with(|state| {
                state.set(Observation {
                    active: true,
                    remaining: Some(successes),
                    ..Observation::default()
                });
            });
        }

        pub fn disarm() -> Observation {
            STATE.with(|state| state.replace(Observation::default()))
        }

        impl Observation {
            pub fn outstanding(self) -> usize {
                self.pointers
                    .iter()
                    .filter(|pointer| **pointer != 0)
                    .count()
            }
        }
    }

    #[global_allocator]
    static GLOBAL: allocation_failure::Allocator = allocation_failure::Allocator;

    fn metadata_failures_reclaim_payload(source: &NativeMemory) {
        let before = ALLOCATOR.usage().live;
        // Fail each real allocation in turn: page vector, unique backing box,
        // then shared owner. No application-visible pin exists on these paths.
        for index in 0..3 {
            allocation_failure::arm(index);
            let result = source.allocate(PAGE + 1, PAGE, CacheAttribute::WriteBack);
            let observation = allocation_failure::disarm();
            assert!(matches!(result, Err(MemoryError::OutOfMemory)));
            assert_eq!(observation.attempts, index + 1);
            assert_eq!(observation.denied, 1);
            assert_eq!(observation.outstanding(), 0);
            assert!(!observation.overflow);
            assert_eq!(ALLOCATOR.usage().live, before);
        }
        let pin = source
            .allocate(PAGE, PAGE, CacheAttribute::WriteBack)
            .unwrap();
        allocation_failure::arm(0);
        let cloned = pin.clone();
        let mapping = cloned.cpu_mapping(CacheAttribute::WriteBack);
        drop(cloned);
        drop(pin);
        let observation = allocation_failure::disarm();
        assert_eq!(observation.attempts, 0);
        assert_eq!(ALLOCATOR.usage().live, before + PAGE);
        drop(mapping.unwrap());
        assert_eq!(ALLOCATOR.usage().live, before);
    }

    fn scatter_metadata_failures_reclaim_every_original_pin(source: &NativeMemory) {
        use stela_drivers::bus::dma::pages::{DmaPages, PageRange};
        let before = ALLOCATOR.usage().live;
        // Fail the real physical-sequence vector and then shared scatter owner.
        // Input pins and range metadata exist before allocation denial begins.
        for index in 0..2 {
            let ranges = vec![
                PageRange::new(
                    source
                        .allocate(2 * PAGE, PAGE, CacheAttribute::WriteBack)
                        .unwrap(),
                    PAGE..2 * PAGE,
                )
                .unwrap(),
                PageRange::new(
                    source
                        .allocate(PAGE, PAGE, CacheAttribute::WriteBack)
                        .unwrap(),
                    0..PAGE,
                )
                .unwrap(),
            ];
            assert_eq!(ALLOCATOR.usage().live, before + 3 * PAGE);
            allocation_failure::arm(index);
            let result = DmaPages::from_ranges(ranges);
            let observation = allocation_failure::disarm();
            assert!(matches!(result, Err(MemoryError::OutOfMemory)));
            assert_eq!(observation.attempts, index + 1);
            assert_eq!(observation.denied, 1);
            assert_eq!(observation.outstanding(), 0);
            assert!(!observation.overflow);
            assert_eq!(ALLOCATOR.usage().live, before);
        }
        let pin = source
            .allocate(PAGE, PAGE, CacheAttribute::WriteBack)
            .unwrap();
        allocation_failure::arm(0);
        let single = DmaPages::from(pin);
        let cloned = single.clone();
        drop(single);
        let observation = allocation_failure::disarm();
        assert_eq!(observation.attempts, 0);
        assert!(cloned.as_single().is_some());
        assert_eq!(ALLOCATOR.usage().live, before + PAGE);
        drop(cloned);
        assert_eq!(ALLOCATOR.usage().live, before);
    }

    #[test]
    fn unsorted_pin_metadata_failures_drop_the_consumed_backing() {
        use std::sync::Arc;
        #[repr(align(4096))]
        struct Buffer([u8; 3 * PAGE]);
        struct Backing {
            buffer: Box<Buffer>,
            pages: [u64; 3],
            drops: Arc<AtomicUsize>,
        }
        impl Drop for Backing {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }
        // SAFETY: hosted ownership fixture with an aligned zeroed CPU buffer.
        // Physical labels model three distinct pages and are never dereferenced.
        unsafe impl PageBacking for Backing {
            fn cpu_base(&self) -> NonNull<u8> {
                NonNull::from(&self.buffer.0[0])
            }
            fn physical_pages(&self) -> &[u64] {
                &self.pages
            }
            fn page_shift(&self) -> u8 {
                PAGE_SHIFT
            }
            fn cache_attribute(&self) -> CacheAttribute {
                CacheAttribute::WriteBack
            }
        }
        for index in 0..2 {
            let drops = Arc::new(AtomicUsize::new(0));
            let backing = Box::new(Backing {
                buffer: Box::new(Buffer([0; 3 * PAGE])),
                pages: [0x1000, 0x3000, 0x2000],
                drops: drops.clone(),
            });
            allocation_failure::arm(index);
            let result = PinnedPages::new(backing, 3 * PAGE, PAGE);
            let observation = allocation_failure::disarm();
            assert!(matches!(result, Err(MemoryError::OutOfMemory)));
            assert_eq!(observation.attempts, index + 1);
            assert_eq!(observation.denied, 1);
            assert_eq!(observation.outstanding(), 0);
            assert!(!observation.overflow);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn unregistered_native_memory_does_not_attest_a_provider() {
        let source = NativeMemory {
            cpu: AtomicUsize::new(0),
            physical: AtomicU64::new(0),
            bytes: AtomicUsize::new(0),
            table_offset: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            catalogs: AtomicUsize::new(0),
        };
        assert_eq!(source.page_geometry(), Err(MemoryError::Unavailable));
    }

    #[test]
    fn actual_heap_pages_stay_pinned_through_cpu_mapping_and_reclaim() {
        let layout = Layout::from_size_align(128 * PAGE, 128 * PAGE).unwrap();
        // SAFETY: this separate RAM allocation is kept alive until every test pin
        // ends. Its PA relation is a model; privileged CPU mappings run in QEMU.
        let ram = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ram.is_null());
        // SAFETY: one dedicated extent, no users before initialization.
        unsafe {
            ALLOCATOR.initialize(ram, layout.size());
            initialize(ram as usize, 0x4000_0000, layout.size(), 0);
        }
        let source = &SOURCE;
        assert!(matches!(
            source.allocate(layout.size(), PAGE, CacheAttribute::WriteBack),
            Err(MemoryError::OutOfMemory)
        ));
        assert_eq!(ALLOCATOR.usage().live, 0);
        metadata_failures_reclaim_payload(source);
        scatter_metadata_failures_reclaim_every_original_pin(source);
        let geometry = source.page_geometry().unwrap();
        assert_eq!(geometry, PageGeometry::base_only(PAGE_SHIFT).unwrap());
        assert!(!geometry.supports(PAGE_SHIFT + 1));
        verify().unwrap();
        assert!(matches!(
            source.allocate(0, 4096, CacheAttribute::WriteBack),
            Err(MemoryError::InvalidSize)
        ));
        assert!(matches!(
            source.allocate(1, 3, CacheAttribute::WriteBack),
            Err(MemoryError::InvalidAlignment)
        ));
        assert!(matches!(
            source.allocate(4096, 4096, CacheAttribute::WriteCombining),
            Err(MemoryError::CacheAttributeUnavailable)
        ));
        let before = ALLOCATOR.usage().live;
        let pin = source
            .allocate(4097, 8192, CacheAttribute::WriteBack)
            .unwrap();
        assert_eq!(pin.bytes(), 8192);
        assert_eq!(pin.logical_bytes(), 4097);
        assert_eq!(pin.alignment(), 8192);
        assert_eq!(pin.page_shift(), 12);
        assert!(geometry.supports(pin.page_shift()));
        assert!(matches!(
            pin.cpu_mapping(CacheAttribute::Uncached),
            Err(MemoryError::CacheAttributeUnavailable)
        ));
        let mapping = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        let tail = pin
            .cpu_mapping_range(CacheAttribute::WriteBack, 4097..8192)
            .unwrap();
        assert_eq!(tail.bytes(), 4095);
        assert_eq!(tail.range(), 4097..8192);
        assert_eq!(tail.address(4095, 1), Err(MemoryError::InvalidSize));
        assert!(matches!(
            pin.cpu_mapping_range(CacheAttribute::WriteBack, 8191..8193),
            Err(MemoryError::InvalidSize)
        ));
        drop(tail);
        let pointer = mapping.address(0, mapping.bytes()).unwrap().as_ptr();
        assert!((pointer as usize).is_multiple_of(8192));
        let physical = 0x4000_0000 + (pointer as usize - ram as usize) as u64;
        assert_eq!(pin.physical_pages(), &[physical, physical + 4096]);
        // SAFETY: CPU-exclusive test memory; the mapping retains the whole pin.
        assert!(
            unsafe { core::slice::from_raw_parts(pointer, mapping.bytes()) }
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            mapping.address(usize::MAX, 1),
            Err(MemoryError::InvalidSize)
        );
        assert_eq!(mapping.address(8192, 1), Err(MemoryError::InvalidSize));
        let clone = pin.clone();
        drop(pin);
        drop(clone);
        assert_eq!(ALLOCATOR.usage().live, before + 8192);
        // SAFETY: the retained CPU mapping still owns these pages.
        unsafe { pointer.add(8191).write_volatile(0x5a) };
        drop(mapping);
        assert_eq!(ALLOCATOR.usage().live, before);
        // Exercise a domain's failure ordering while the real native allocation
        // stays pinned. The IOMMU/register transport here is explicitly a model.
        use std::sync::{Arc, Mutex};
        use stela_drivers::bus::dma::mapping::{
            Direction, DmaDomain, DmaError, DmaMapping, DomainMapping,
        };
        #[derive(Default)]
        struct ModelDomain(Mutex<(bool, Vec<&'static str>)>);
        // SAFETY: deterministic model of a single translation with no device;
        // native hardware invalidation is a separate QEMU/platform requirement.
        unsafe impl DmaDomain for ModelDomain {
            unsafe fn map(
                &self,
                pages: &stela_drivers::bus::dma::pages::DmaPages,
                _: Direction,
                _: u64,
            ) -> Result<DomainMapping, DmaError> {
                self.0.lock().unwrap().1.push("map-publish-iotlb-ack");
                Ok(DomainMapping {
                    id: 1,
                    address: 0x8_0000_0000,
                    bytes: pages.bytes(),
                })
            }
            unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
                let mut state = self.0.lock().unwrap();
                state.1.push("unmap-iotlb-ack");
                if state.0 {
                    Err(DmaError::InvalidationFailed)
                } else {
                    Ok(())
                }
            }
            unsafe fn sync_for_device(
                &self,
                _: DomainMapping,
                _: core::ops::Range<usize>,
                _: Direction,
            ) -> Result<(), DmaError> {
                self.0.lock().unwrap().1.push("device-visible");
                Ok(())
            }
            unsafe fn sync_for_cpu(
                &self,
                _: DomainMapping,
                _: core::ops::Range<usize>,
                _: Direction,
            ) -> Result<(), DmaError> {
                self.0.lock().unwrap().1.push("cpu-visible");
                Ok(())
            }
        }
        let domain = Arc::new(ModelDomain::default());
        let pin = source
            .allocate(4096, 4096, CacheAttribute::WriteBack)
            .unwrap();
        let keep = pin.clone();
        let mut dma =
            DmaMapping::map(domain.clone(), pin, Direction::Bidirectional, u64::MAX).unwrap();
        assert_ne!(dma.address().unwrap(), keep.physical_pages()[0]);
        assert_eq!(dma.sync_for_device(0..4097), Err(DmaError::InvalidRange));
        assert_eq!(
            dma.sync_for_device(core::ops::Range {
                start: 4096,
                end: 4095
            }),
            Err(DmaError::InvalidRange)
        );
        dma.sync_for_device(0..4096).unwrap();
        // SAFETY: the model has no asynchronous DMA; completion is quiescent.
        unsafe { dma.sync_for_cpu(0..4096) }.unwrap();
        drop(keep);
        domain.0.lock().unwrap().0 = true;
        // SAFETY: same quiescent model; failed invalidation must retain real pins.
        assert_eq!(unsafe { dma.unmap() }, Err(DmaError::InvalidationFailed));
        assert_eq!(ALLOCATOR.usage().live, before + 4096);
        domain.0.lock().unwrap().0 = false;
        // SAFETY: retry has the same stopped model and unreused mapping.
        unsafe { dma.unmap() }.unwrap();
        assert_eq!(dma.address(), Err(DmaError::Unmapped));
        assert_eq!(dma.sync_for_device(0..4096), Err(DmaError::Unmapped));
        // SAFETY: hardware remains quiescent, but the retired token must be
        // rejected by the wrapper before any backend cache operation.
        assert_eq!(
            unsafe { dma.sync_for_cpu(0..4096) },
            Err(DmaError::Unmapped)
        );
        assert_eq!(ALLOCATOR.usage().live, before);
        assert_eq!(
            domain.0.lock().unwrap().1,
            [
                "map-publish-iotlb-ack",
                "device-visible",
                "cpu-visible",
                "unmap-iotlb-ack",
                "unmap-iotlb-ack"
            ]
        );
        let pin = source
            .allocate(4096, 4096, CacheAttribute::WriteBack)
            .unwrap();
        assert!(matches!(
            DmaMapping::map(domain, pin, Direction::ToDevice, u32::MAX as u64),
            Err(DmaError::AddressLimit)
        ));
        assert_eq!(ALLOCATOR.usage().live, before);
        let second = source
            .allocate(8192, 8192, CacheAttribute::WriteBack)
            .unwrap();
        let second_mapping = second.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        assert_eq!(second_mapping.address(0, 8192).unwrap().as_ptr(), pointer);
        // SAFETY: CPU-exclusive mapping; reclaimed RAM was actually zeroed again.
        assert_eq!(unsafe { pointer.add(8191).read_volatile() }, 0);
        drop(second_mapping);
        drop(second);
        assert_eq!(ALLOCATOR.usage().live, before);
        // A separately placed CPU alias can disagree with the physical
        // alignment phase even though both bases are page-aligned. Moving an
        // allocation within that alias cannot repair it.
        // SAFETY: all prior pins/catalogs are retired; the changed PA relation
        // is a hosted model and will be refused before payload allocation.
        unsafe { initialize(ram as usize, 0x4000_0000 + PAGE as u64, layout.size(), 0) };
        assert!(matches!(
            source.allocate(4 * PAGE, 4 * PAGE, CacheAttribute::WriteBack),
            Err(MemoryError::InvalidAlignment)
        ));
        assert_eq!(ALLOCATOR.usage().live, before);
        // A physmap-style congruent alias supports every order fitting this
        // reservation, with actual zeroed data and exact final reclamation.
        // SAFETY: no live allocation remains; restore the retained model mapping.
        unsafe { initialize(ram as usize, 0x4000_0000, layout.size(), 0) };
        for order in 0..7 {
            let bytes = PAGE << order;
            let pin = source
                .allocate(bytes, bytes, CacheAttribute::WriteBack)
                .unwrap();
            let mapping = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
            let pointer = mapping.address(0, bytes).unwrap().as_ptr();
            assert!((pointer as usize).is_multiple_of(bytes));
            assert!(pin.physical_pages()[0].is_multiple_of(bytes as u64));
            assert_eq!(
                pin.physical_pages()[0],
                0x4000_0000 + (pointer as usize - ram as usize) as u64
            );
            // SAFETY: the CPU mapping owns this complete exclusive test extent.
            assert!(
                unsafe { core::slice::from_raw_parts(pointer, bytes) }
                    .iter()
                    .all(|byte| *byte == 0)
            );
            drop(pin);
            assert_eq!(ALLOCATOR.usage().live, before + bytes);
            drop(mapping);
            assert_eq!(ALLOCATOR.usage().live, before);
        }
        // SAFETY: no allocation remains from the test RAM.
        unsafe { std::alloc::dealloc(ram, layout) };
    }
}
