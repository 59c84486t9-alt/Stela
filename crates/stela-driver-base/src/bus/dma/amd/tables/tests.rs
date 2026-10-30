//! AMD DMA table model, backing provider and shared fixtures.
extern crate std;
use super::*;
use crate::bus::dma::{
    memory::{CacheAttribute, PageBacking, PageGeometry, PinnedPages},
    pages::PageRange,
};
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    boxed::Box,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    alloc::Layout,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Mutex,
};

// Fixture policy: root plus eight independent deepest-mode paths. This is
// a generous software-test budget, not a native platform resource limit.
const TEST_TABLE_BUDGET: usize = 1 + 8 * 5;
const PRESENT: u64 = 1;
const PA_MASK: u64 = 0x000f_ffff_ffff_f000;
const READ: u64 = 1 << 61;
const WRITE: u64 = 1 << 62;
const FC: u64 = 1 << 60;

#[derive(Clone, Debug)]
enum Event {
    Admit(Vec<u64>, Direction),
    Publish {
        physical: u64,
        words: Vec<u64>,
        success: bool,
    },
    Invalidate(u64, usize, bool),
    SimulatedRetirement,
}
struct Allocation {
    physical: u64,
    cpu: usize,
    bytes: usize,
}
struct ModelState {
    next: u64,
    allocations: Vec<Allocation>,
    allocation_calls: usize,
    returned_granules: usize,
    publications: usize,
    fail_allocate: Option<usize>,
    fail_publish: Option<usize>,
    panic_publish: Option<usize>,
    fail_invalidate: bool,
    panic_invalidate: bool,
    fail_admit: bool,
    coherent: bool,
    watch_payload: Option<Arc<AtomicUsize>>,
    events: Vec<Event>,
}
struct Monitor {
    state: Mutex<ModelState>,
    table_drops: Arc<AtomicUsize>,
    hardware_drops: AtomicUsize,
}
impl Monitor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ModelState {
                next: 0x0100_0000,
                allocations: Vec::new(),
                allocation_calls: 0,
                returned_granules: 1,
                publications: 0,
                fail_allocate: None,
                fail_publish: None,
                panic_publish: None,
                fail_invalidate: false,
                panic_invalidate: false,
                fail_admit: false,
                coherent: true,
                watch_payload: None,
                events: Vec::new(),
            }),
            table_drops: Arc::new(AtomicUsize::new(0)),
            hardware_drops: AtomicUsize::new(0),
        })
    }

    fn live_tables(&self) -> usize {
        self.state.lock().unwrap().allocations.len()
    }

    /// Snapshot every byte-backed word, including unused native-granule
    /// tails. A matching counter alone cannot prove rollback preserved RAM.
    fn words(&self) -> Vec<(u64, Vec<u64>)> {
        let state = self.state.lock().unwrap();
        state
            .allocations
            .iter()
            .map(|allocation| {
                let words = (0..allocation.bytes / 8)
                    .map(|index| {
                        // SAFETY: aligned CPU allocation;
                        // the synchronous observer excludes table writers.
                        u64::from_le(unsafe {
                            (allocation.cpu as *const u64).add(index).read_volatile()
                        })
                    })
                    .collect();
                (allocation.physical, words)
            })
            .collect()
    }

    /// Literal AMDv1 software walk of kept CPU words. This does
    /// not call PageEntry/TableLevel decoding or claim a hardware walker.
    fn walk(&self, root: u64, mode: u8, address: u64) -> Option<Walk> {
        let state = self.state.lock().unwrap();
        let mut physical = root;
        for level in (1..=mode).rev() {
            let allocation = state
                .allocations
                .iter()
                .find(|item| item.physical == physical)
                .expect("walker reached unowned table memory");
            let shift = 12 + 9 * u32::from(level - 1);
            let index = ((address >> shift) & if level == 6 { 127 } else { 511 }) as usize;
            // SAFETY: the model's live table allocation; writers
            // and table retirement are excluded while this synchronous walk runs.
            let word =
                u64::from_le(unsafe { (allocation.cpu as *const u64).add(index).read_volatile() });
            if word & PRESENT == 0 {
                return None;
            }
            let next = ((word >> 9) & 7) as u8;
            if level == 1 {
                assert_eq!(next, 0, "4K leaf bypasses no intermediate level");
                return Some(Walk {
                    physical: (word & PA_MASK) | (address & 4095),
                    read: word & READ != 0,
                    write: word & WRITE != 0,
                    coherent: word & FC != 0,
                });
            }
            assert_eq!(next, level - 1, "parent traverses one adjacent level");
            assert_eq!(word & (READ | WRITE), READ | WRITE);
            physical = word & PA_MASK;
        }
        unreachable!("nonzero admitted host mode")
    }
}
#[derive(Debug, Eq, PartialEq)]
struct Walk {
    physical: u64,
    read: bool,
    write: bool,
    coherent: bool,
}

struct Backing {
    cpu: NonNull<u8>,
    layout: Layout,
    physical: Vec<u64>,
    shift: u8,
    drops: Arc<AtomicUsize>,
    table_owner: Option<Arc<Monitor>>,
}
// SAFETY: owned zeroed CPU allocation, immutable metadata and raw
// pointers only. This model has no asynchronous writer or physical DMA.
unsafe impl Send for Backing {}
// SAFETY: access and release are synchronous; metadata uses the model mutex.
unsafe impl Sync for Backing {}
// SAFETY: each backing owns its live CPU storage and immutable symbolic
// PA list. Labels are distinct from CPU addresses and never reach hardware.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        self.cpu
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        self.shift
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        if let Some(owner) = &self.table_owner {
            let mut state = owner.state.lock().unwrap();
            let position = state
                .allocations
                .iter()
                .position(|item| item.cpu == self.cpu.as_ptr() as usize)
                .unwrap();
            state.allocations.remove(position);
        }
        self.drops.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the unique original allocation after all pins end.
        unsafe { dealloc(self.cpu.as_ptr(), self.layout) };
    }
}
fn pin(
    physical: Vec<u64>,
    shift: u8,
    drops: Arc<AtomicUsize>,
    owner: Option<Arc<Monitor>>,
) -> PinnedPages {
    let logical_bytes = physical.len() * (1usize << shift);
    pin_with_logical(physical, shift, drops, owner, logical_bytes)
}
fn pin_with_logical(
    physical: Vec<u64>,
    shift: u8,
    drops: Arc<AtomicUsize>,
    owner: Option<Arc<Monitor>>,
    logical_bytes: usize,
) -> PinnedPages {
    let granule = 1usize << shift;
    let bytes = physical.len() * granule;
    assert!(logical_bytes > 0 && logical_bytes <= bytes);
    let layout = Layout::from_size_align(bytes, granule).unwrap();
    // SAFETY: fresh zeroed storage, owned by exactly this backing.
    let cpu = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    assert!(!physical.contains(&(cpu.as_ptr() as usize as u64)));
    if let Some(owner) = &owner {
        owner.state.lock().unwrap().allocations.push(Allocation {
            physical: physical[0],
            cpu: cpu.as_ptr() as usize,
            bytes,
        });
    }
    PinnedPages::new(
        Box::new(Backing {
            cpu,
            layout,
            physical,
            shift,
            drops,
            table_owner: owner,
        }),
        logical_bytes,
        granule,
    )
    .unwrap()
}
fn payload(physical: u64, drops: &Arc<AtomicUsize>) -> DmaPages {
    pin(vec![physical], 12, drops.clone(), None).into()
}

struct Hardware {
    monitor: Arc<Monitor>,
    native_shift: u8,
}
impl Drop for Hardware {
    fn drop(&mut self) {
        self.monitor.hardware_drops.fetch_add(1, Ordering::Relaxed);
    }
}
impl PageSource for Hardware {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(self.native_shift)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        let granule = 1usize << self.native_shift;
        assert_eq!(
            (bytes, alignment, attribute),
            (granule, granule, CacheAttribute::WriteBack)
        );
        let (physical, returned_granules) = {
            let mut state = self.monitor.state.lock().unwrap();
            state.allocation_calls += 1;
            if state.fail_allocate == Some(state.allocation_calls) {
                return Err(MemoryError::OutOfMemory);
            }
            let physical = state.next;
            let returned_granules = state.returned_granules;
            state.next += (granule * returned_granules) as u64;
            (physical, returned_granules)
        };
        let pages = pin_with_logical(
            (0..returned_granules)
                .map(|index| physical + (index * granule) as u64)
                .collect(),
            self.native_shift,
            self.monitor.table_drops.clone(),
            Some(self.monitor.clone()),
            bytes,
        );
        assert_eq!(pages.logical_bytes(), bytes);
        assert_eq!(pages.bytes(), granule * returned_granules);
        Ok(pages)
    }
}
// SAFETY: software-only visibility model snapshots preceding stores
// synchronously, with no native coherency, IOTLB or completion claim. The
// model never mutates table words or keeps the callback's borrowed pointer.
unsafe impl TableVisibility for Hardware {
    unsafe fn publish(&self, cpu: NonNull<u8>, bytes: usize) -> Result<(), MemoryError> {
        assert_eq!(bytes, 4096);
        assert!((cpu.as_ptr() as usize).is_multiple_of(4096));
        let (fail, panic) = {
            let mut state = self.monitor.state.lock().unwrap();
            let physical = state
                .allocations
                .iter()
                .find(|item| item.cpu == cpu.as_ptr() as usize)
                .expect("publication requires a live table pin")
                .physical;
            if let Some(drops) = &state.watch_payload {
                assert_eq!(drops.load(Ordering::Relaxed), 0);
            }
            let mut words = Vec::new();
            for index in 0..512 {
                // SAFETY: the callback borrows exactly this aligned
                // table; software writers are excluded until return/unwind.
                words.push(u64::from_le(unsafe {
                    cpu.as_ptr().cast::<u64>().add(index).read_volatile()
                }));
            }
            state.publications += 1;
            let fail = state.fail_publish == Some(state.publications);
            let panic = state.panic_publish == Some(state.publications);
            state.events.push(Event::Publish {
                physical,
                words,
                success: !fail && !panic,
            });
            (fail, panic)
        };
        // Unwind outside the mutex so the observer remains usable afterward.
        assert!(!panic, "injected publication unwind");
        if fail {
            Err(MemoryError::Unavailable)
        } else {
            Ok(())
        }
    }
}
// SAFETY: isolated synchronous software domain model, not native hardware.
// Every table is a fresh exclusive pin. The walker performs no A/D writes.
// Injected failures/panics establish uncertainty, never invented success.
unsafe impl TableHardware for Hardware {
    fn admit_payload(&self, pages: &DmaPages, direction: Direction) -> Result<bool, DmaError> {
        let mut state = self.monitor.state.lock().unwrap();
        state
            .events
            .push(Event::Admit(pages.physical_pages().to_vec(), direction));
        if state.fail_admit {
            Err(DmaError::VisibilityFailed)
        } else {
            Ok(state.coherent)
        }
    }
    fn invalidate(&self, address: u64, bytes: usize) -> Result<(), DmaError> {
        let (fail, panic) = {
            let mut state = self.monitor.state.lock().unwrap();
            if let Some(drops) = &state.watch_payload {
                assert_eq!(drops.load(Ordering::Relaxed), 0);
            }
            let (fail, panic) = (state.fail_invalidate, state.panic_invalidate);
            state
                .events
                .push(Event::Invalidate(address, bytes, !fail && !panic));
            (fail, panic)
        };
        assert!(!panic, "injected invalidation unwind");
        if fail {
            Err(DmaError::InvalidationFailed)
        } else {
            Ok(())
        }
    }
}
fn new_tree(mode: u8, native_shift: u8) -> (PageTables<Hardware>, Arc<Monitor>) {
    new_tree_with_budget(mode, native_shift, TEST_TABLE_BUDGET)
}
fn new_tree_with_budget(
    mode: u8,
    native_shift: u8,
    maximum_table_pages: usize,
) -> (PageTables<Hardware>, Arc<Monitor>) {
    new_tree_with_limits(
        mode,
        native_shift,
        maximum_table_pages,
        maximum_table_pages * (1usize << native_shift),
    )
}
fn new_tree_with_limits(
    mode: u8,
    native_shift: u8,
    maximum_table_pages: usize,
    maximum_backing_bytes: usize,
) -> (PageTables<Hardware>, Arc<Monitor>) {
    let monitor = Monitor::new();
    let hardware = Hardware {
        monitor: monitor.clone(),
        native_shift,
    };
    let level = TableLevel::new(mode).unwrap();
    let virtual_bits = level.address_bits().try_into().unwrap();
    // SAFETY: this isolated software model admits the selected literal host
    // mode and 48-bit symbolic physical inventory; no hardware is attached.
    let tree = unsafe {
        PageTables::new(
            hardware,
            level,
            48,
            virtual_bits,
            maximum_table_pages,
            maximum_backing_bytes,
        )
    }
    .unwrap();
    (tree, monitor)
}
fn retired(mut tree: PageTables<Hardware>, monitor: &Monitor) {
    monitor
        .state
        .lock()
        .unwrap()
        .events
        .push(Event::SimulatedRetirement);
    // SAFETY: simulated root detachment/reset in a model without a device,
    // worker or asynchronous walker. This is not a native completion witness.
    unsafe { tree.retire() };
    drop(tree);
    assert_eq!(monitor.live_tables(), 0);
    assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
}

mod admission;
mod backing_budget;
mod construction;
mod geometry;
mod mapping;
mod node_budget;
mod poisoning;
mod staging;
