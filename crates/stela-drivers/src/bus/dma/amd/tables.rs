//! Retained AMDv1 host translations. Unit routing, IOVA allocation and the
//! device's submission/completion lifetime remain the live domain's owners.
use super::{
    format::{FormatError, PageEntry, PhysicalAddress, TableLevel},
    memory::{TABLE_BYTES, TABLE_ENTRIES, TableError, TablePage, TableVisibility},
};
use crate::bus::dma::{
    mapping::{Direction, DmaError},
    memory::{MemoryError, PageSource},
    pages::DmaPages,
};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static QUARANTINED_TREES: AtomicU64 = AtomicU64::new(0);
static QUARANTINED_TABLES: AtomicU64 = AtomicU64::new(0);
static QUARANTINED_PAYLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

/// Cumulative resources retained by exposed-tree Drop, never proof of reset or
/// reclamation. The retained hardware context is included in each tree owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuarantineStatus {
    pub trees: u64,
    pub tables: u64,
    pub payload_bytes: u64,
}

pub fn quarantine_status() -> QuarantineStatus {
    QuarantineStatus {
        trees: QUARANTINED_TREES.load(Ordering::Relaxed),
        tables: QUARANTINED_TABLES.load(Ordering::Relaxed),
        payload_bytes: QUARANTINED_PAYLOAD_BYTES.load(Ordering::Relaxed),
    }
}

fn count_quarantine(counter: &AtomicU64, amount: u64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

/// The fixed allocation, visibility and completion context of one domain.
///
/// # Safety
/// Every successful PageSource allocation must provide fresh, currently zeroed,
/// CPU-exclusive table RAM for its entire returned pin lifetime. The inherited
/// visibility service must qualify this actual remapper's table coherency.
/// `invalidate` must invalidate all page and PDE caches covering the complete
/// nonempty span in this exact domain and acknowledge actual hardware completion
/// before success. A span whose exclusive end is unrepresentable requires a
/// full-domain flush. A queue head, timeout or compiler fence is not completion.
/// Faults, timeouts and unsupported operations must return failure. The context
/// retains its real unit/domain, command/completion resources and IRQ ownership;
/// it cannot tear them down underneath this tree or another retained owner.
/// Hardware table access/dirty updates must be disabled: the walker only reads
/// these tables. `admit_payload` must validate the actual payload's cache and
/// encryption policy and return the qualified FC selection before mutation.
pub unsafe trait TableHardware: PageSource + TableVisibility {
    fn invalidate(&self, address: u64, bytes: usize) -> Result<(), DmaError>;
    fn admit_payload(&self, pages: &DmaPages, direction: Direction) -> Result<bool, DmaError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranslationError {
    Memory(MemoryError),
    Table(TableError),
    Format(FormatError),
    Invalidation(DmaError),
    Payload(DmaError),
    InvalidRange,
    VirtualWidth,
    AddressLimit,
    Overlap,
    NotMapped,
    Corrupt,
    Poisoned,
}

struct Node {
    table: TablePage,
    level: TableLevel,
    // Zero means absent. Only the root has index zero; children always have
    // nonzero u32 indices into State::nodes, which never removes/reorders nodes.
    children: Vec<u32>,
}

impl Node {
    fn new(
        hardware: &impl TableHardware,
        level: TableLevel,
        bits: u8,
    ) -> Result<Self, TranslationError> {
        let mut children = Vec::new();
        if level.child().is_some() {
            children
                .try_reserve_exact(TABLE_ENTRIES)
                .map_err(|_| TranslationError::Memory(MemoryError::OutOfMemory))?;
            children.resize(TABLE_ENTRIES, 0);
        }
        // SAFETY: TableHardware's implementation grants fresh, currently zeroed
        // exclusive storage for every table allocation, not just the root.
        let table =
            unsafe { TablePage::allocate(hardware, bits) }.map_err(TranslationError::Table)?;
        Ok(Self {
            table,
            level,
            children,
        })
    }
}

struct Binding {
    address: u64,
    last: u64,
    pages: DmaPages,
    direction: Direction,
    coherent: bool,
}

impl Binding {
    fn physical(&self, offset: usize) -> u64 {
        let shift = self.pages.page_shift();
        self.pages.physical_pages()[offset >> shift] + (offset & ((1usize << shift) - 1)) as u64
    }

    fn entry(&self, offset: usize, bits: u8) -> Result<PageEntry, TranslationError> {
        let physical =
            PhysicalAddress::new(self.physical(offset), bits).map_err(TranslationError::Format)?;
        PageEntry::page(physical, self.direction, self.coherent).map_err(TranslationError::Format)
    }
}

struct State<H> {
    hardware: H,
    nodes: Vec<Node>,
    // Sorted by start IOVA. Includes any failed partially published mapping.
    bindings: Vec<Binding>,
    physical_bits: u8,
    virtual_bits: u8,
}

/// Host translation memory, including the original pins and fixed real domain
/// context. No method allocates an IOVA or authorizes a requester/unit takeover.
///
/// Exposing the root arms Drop quarantine before its PA escapes. Explicit
/// acknowledged root retirement is required even when no payload is mapped.
pub struct PageTables<H: TableHardware> {
    state: Option<State<H>>,
    exposed: bool,
    poisoned: bool,
}

impl<H: TableHardware> PageTables<H> {
    /// # Safety
    /// `level`, `physical_bits` and `virtual_bits` are admitted for this exact
    /// hardware/domain, including HATS/IVINFO limits, encryption and host mode. No
    /// other software owner may mutate or publish these newly allocated tables.
    pub unsafe fn new(
        hardware: H,
        level: TableLevel,
        physical_bits: u8,
        virtual_bits: u8,
    ) -> Result<Self, TranslationError> {
        PhysicalAddress::new(0, physical_bits).map_err(TranslationError::Format)?;
        if !(12..=64).contains(&virtual_bits) || u32::from(virtual_bits) > level.address_bits() {
            return Err(TranslationError::VirtualWidth);
        }
        let mut nodes = Vec::new();
        nodes
            .try_reserve(1)
            .map_err(|_| TranslationError::Memory(MemoryError::OutOfMemory))?;
        let root = Node::new(&hardware, level, physical_bits)?;
        root.table
            .publish(&hardware)
            .map_err(TranslationError::Table)?;
        nodes.push(root);
        Ok(Self {
            state: Some(State {
                hardware,
                nodes,
                bindings: Vec::new(),
                physical_bits,
                virtual_bits,
            }),
            exposed: false,
            poisoned: false,
        })
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Arm conservative ownership retention before returning a publishable PA.
    /// This is not a DTE store, a visibility barrier or domain attachment.
    pub fn root_for_publication(&mut self) -> Result<PhysicalAddress, TranslationError> {
        if self.poisoned {
            return Err(TranslationError::Poisoned);
        }
        self.exposed = true;
        Ok(self.state.as_ref().expect("retained tree").nodes[0]
            .table
            .physical())
    }

    /// # Safety
    /// This root has been detached from every actual DTE/alias, every requester
    /// and walker is stopped, and required invalidations/reset have completed.
    /// No hardware can access any of these tables or payloads again. A timeout
    /// or an empty mapping list cannot establish this retirement.
    pub unsafe fn retire(&mut self) {
        self.exposed = false;
    }

    /// Install the exact ordered native pages and retain them before any store.
    ///
    /// # Safety
    /// The live domain owns this IOVA span exclusively; no device/worker may
    /// access it until this call succeeds and the submission owner separately
    /// performs payload visibility and descriptor/doorbell ordering. The root
    /// must be exposed through root_for_publication before any hardware use.
    pub unsafe fn map(
        &mut self,
        address: u64,
        pages: DmaPages,
        direction: Direction,
    ) -> Result<(), TranslationError> {
        if self.poisoned {
            return Err(TranslationError::Poisoned);
        }
        let state = self.state.as_mut().expect("retained tree");
        let last = state.validate(address, &pages)?;
        let position = state
            .bindings
            .partition_point(|binding| binding.address < address);
        if position > 0 && state.bindings[position - 1].last >= address
            || state
                .bindings
                .get(position)
                .is_some_and(|next| next.address <= last)
        {
            return Err(TranslationError::Overlap);
        }
        state
            .bindings
            .try_reserve(1)
            .map_err(|_| TranslationError::Memory(MemoryError::OutOfMemory))?;
        let coherent = state
            .hardware
            .admit_payload(&pages, direction)
            .map_err(TranslationError::Payload)?;
        state.bindings.insert(
            position,
            Binding {
                address,
                last,
                pages,
                direction,
                coherent,
            },
        );
        let mut mutated = false;
        // Arm before the first mutation-capable callback. Even when a hosted
        // caller catches provider unwinding, unknown publication stays poisoned.
        self.poisoned = true;
        let result = state.install(position, &mut mutated);
        if result.is_ok() {
            self.poisoned = false;
        } else if !mutated && result != Err(TranslationError::Corrupt) {
            self.poisoned = false;
            state.bindings.remove(position);
        }
        result
    }

    /// Remove exactly one complete installed range. On uncertainty the complete
    /// tree/payload/context remain owned, poisoned and unavailable for reuse.
    ///
    /// # Safety
    /// All device accesses, submissions and IRQ/deferred workers referencing
    /// this mapping have completed and are stopped/drained. No new access may
    /// start. This does not establish root retirement or allow unit teardown.
    pub unsafe fn unmap(&mut self, address: u64) -> Result<(), TranslationError> {
        if self.poisoned {
            return Err(TranslationError::Poisoned);
        }
        let state = self.state.as_mut().expect("retained tree");
        let position = state
            .bindings
            .binary_search_by_key(&address, |binding| binding.address)
            .map_err(|_| TranslationError::NotMapped)?;
        self.poisoned = true;
        state.remove(position)?;
        state.bindings.remove(position);
        self.poisoned = false;
        Ok(())
    }
}

impl<H: TableHardware> Drop for PageTables<H> {
    fn drop(&mut self) {
        if self.exposed {
            if let Some(state) = &self.state {
                count_quarantine(&QUARANTINED_TREES, 1);
                count_quarantine(&QUARANTINED_TABLES, state.nodes.len() as u64);
                let bytes = state.bindings.iter().fold(0u64, |bytes, binding| {
                    bytes.saturating_add(binding.pages.bytes() as u64)
                });
                count_quarantine(&QUARANTINED_PAYLOAD_BYTES, bytes);
            }
            // Retain the actual unit/IRQ/completion context as well as every
            // table and payload. Dropping a context could otherwise disable or
            // reassign the domain while hardware still holds this root.
            core::mem::forget(self.state.take());
        }
    }
}

impl<H: TableHardware> State<H> {
    fn validate(&self, address: u64, pages: &DmaPages) -> Result<u64, TranslationError> {
        if !address.is_multiple_of(TABLE_BYTES as u64) || pages.bytes() == 0 {
            return Err(TranslationError::InvalidRange);
        }
        let last = address
            .checked_add(pages.bytes() as u64 - 1)
            .ok_or(TranslationError::AddressLimit)?;
        let address_bits = self.virtual_bits;
        if address_bits < 64 && last >= 1u64 << address_bits {
            return Err(TranslationError::AddressLimit);
        }
        let native_bytes = 1u64 << pages.page_shift();
        let physical_limit = 1u64 << self.physical_bits;
        for &physical in pages.physical_pages() {
            if physical
                .checked_add(native_bytes)
                .is_none_or(|end| end > physical_limit)
            {
                return Err(TranslationError::AddressLimit);
            }
        }
        Ok(last)
    }

    fn leaf(&self, address: u64) -> Result<usize, TranslationError> {
        let mut node = 0;
        while self.nodes[node].level.child().is_some() {
            let slot = self.nodes[node].level.index(address);
            let child = self.nodes[node].children[slot] as usize;
            if child == 0 || child >= self.nodes.len() {
                return Err(TranslationError::Corrupt);
            }
            node = child;
        }
        Ok(node)
    }

    fn ensure_path(&mut self, address: u64, mutated: &mut bool) -> Result<(), TranslationError> {
        let mut node = 0;
        while let Some(level) = self.nodes[node].level.child() {
            let slot = self.nodes[node].level.index(address);
            let mut child = self.nodes[node].children[slot] as usize;
            if child == 0 {
                let index = u32::try_from(self.nodes.len())
                    .map_err(|_| TranslationError::Memory(MemoryError::OutOfMemory))?;
                self.nodes
                    .try_reserve(1)
                    .map_err(|_| TranslationError::Memory(MemoryError::OutOfMemory))?;
                let new = Node::new(&self.hardware, level, self.physical_bits)?;
                // A walker must never observe a parent pointing at an unpublished
                // child, including speculative/negative page-walk caches.
                new.table
                    .publish(&self.hardware)
                    .map_err(TranslationError::Table)?;
                let entry = PageEntry::table(new.table.physical(), self.nodes[node].level)
                    .map_err(TranslationError::Format)?;
                child = index as usize;
                self.nodes.push(new);
                self.nodes[node].children[slot] = index;
                *mutated = true; // Coherent hardware may observe the next store immediately.
                self.nodes[node]
                    .table
                    .write(slot, entry)
                    .map_err(TranslationError::Table)?;
                self.nodes[node]
                    .table
                    .publish(&self.hardware)
                    .map_err(TranslationError::Table)?;
            }
            node = child;
        }
        Ok(())
    }

    fn check_leaves(&self, position: usize, installed: bool) -> Result<(), TranslationError> {
        let binding = &self.bindings[position];
        for offset in (0..binding.pages.bytes()).step_by(TABLE_BYTES) {
            let address = binding.address + offset as u64;
            let node = self.leaf(address)?;
            let slot = self.nodes[node].level.index(address);
            let expected = if installed {
                binding.entry(offset, self.physical_bits)?
            } else {
                PageEntry::EMPTY
            };
            if self.nodes[node]
                .table
                .read(slot)
                .map_err(TranslationError::Table)?
                != expected.bits()
            {
                return Err(TranslationError::Corrupt);
            }
        }
        Ok(())
    }

    fn write_leaves(
        &mut self,
        position: usize,
        install: bool,
        mutated: &mut bool,
    ) -> Result<(), TranslationError> {
        let binding = &self.bindings[position];
        let mut previous: Option<usize> = None;
        for offset in (0..binding.pages.bytes()).step_by(TABLE_BYTES) {
            let address = binding.address + offset as u64;
            let node = self.leaf(address)?;
            if previous.is_some_and(|previous| previous != node) {
                self.nodes[previous.expect("present")]
                    .table
                    .publish(&self.hardware)
                    .map_err(TranslationError::Table)?;
            }
            let slot = self.nodes[node].level.index(address);
            let entry = if install {
                binding.entry(offset, self.physical_bits)?
            } else {
                PageEntry::EMPTY
            };
            *mutated = true;
            self.nodes[node]
                .table
                .write(slot, entry)
                .map_err(TranslationError::Table)?;
            previous = Some(node);
        }
        if let Some(node) = previous {
            self.nodes[node]
                .table
                .publish(&self.hardware)
                .map_err(TranslationError::Table)?;
        }
        self.hardware
            .invalidate(binding.address, binding.pages.bytes())
            .map_err(TranslationError::Invalidation)
    }

    fn install(&mut self, position: usize, mutated: &mut bool) -> Result<(), TranslationError> {
        let address = self.bindings[position].address;
        let bytes = self.bindings[position].pages.bytes();
        for offset in (0..bytes).step_by(TABLE_BYTES) {
            self.ensure_path(address + offset as u64, mutated)?;
        }
        self.check_leaves(position, false)?;
        self.write_leaves(position, true, mutated)
    }

    fn remove(&mut self, position: usize) -> Result<(), TranslationError> {
        self.check_leaves(position, true)?;
        let mut mutated = false;
        self.write_leaves(position, false, &mut mutated)
    }
}

#[cfg(test)]
mod tests {
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
    }
    struct ModelState {
        next: u64,
        allocations: Vec<Allocation>,
        allocation_calls: usize,
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

        /// Literal AMDv1 software walk of actual retained CPU words. This does
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
                // SAFETY: the model's actual live table allocation; writers
                // and table retirement are excluded while this synchronous walk runs.
                let word = u64::from_le(unsafe {
                    (allocation.cpu as *const u64).add(index).read_volatile()
                });
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
    // SAFETY: actual owned zeroed CPU allocation, immutable metadata and raw
    // pointers only. This model has no asynchronous writer or physical DMA.
    unsafe impl Send for Backing {}
    // SAFETY: access and release are synchronous; metadata uses the model mutex.
    unsafe impl Sync for Backing {}
    // SAFETY: each backing owns its exact live CPU storage and immutable symbolic
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
        let granule = 1usize << shift;
        let bytes = physical.len() * granule;
        let layout = Layout::from_size_align(bytes, granule).unwrap();
        // SAFETY: actual fresh zeroed storage, owned by exactly this backing.
        let cpu = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        assert!(!physical.contains(&(cpu.as_ptr() as usize as u64)));
        if let Some(owner) = &owner {
            owner.state.lock().unwrap().allocations.push(Allocation {
                physical: physical[0],
                cpu: cpu.as_ptr() as usize,
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
            bytes,
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
            let physical = {
                let mut state = self.monitor.state.lock().unwrap();
                state.allocation_calls += 1;
                if state.fail_allocate == Some(state.allocation_calls) {
                    return Err(MemoryError::OutOfMemory);
                }
                let physical = state.next;
                state.next += granule as u64;
                physical
            };
            Ok(pin(
                vec![physical],
                self.native_shift,
                self.monitor.table_drops.clone(),
                Some(self.monitor.clone()),
            ))
        }
    }
    // SAFETY: software-only visibility model snapshots actual preceding stores
    // synchronously, with no native coherency, IOTLB or completion claim. The
    // model never mutates table words or retains the callback's borrowed pointer.
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
                    // SAFETY: the callback borrows exactly this retained aligned
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
    // Injected failures/panics establish uncertainty, never fabricated success.
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
        let monitor = Monitor::new();
        let hardware = Hardware {
            monitor: monitor.clone(),
            native_shift,
        };
        let level = TableLevel::new(mode).unwrap();
        let virtual_bits = level.address_bits().try_into().unwrap();
        // SAFETY: this isolated software model admits the selected literal host
        // mode and 48-bit symbolic physical inventory; no hardware is attached.
        let tree = unsafe { PageTables::new(hardware, level, 48, virtual_bits) }.unwrap();
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

    #[test]
    fn all_modes_walk_last_page_and_mode_six_uses_only_top_128_slots() {
        for mode in 1..=6 {
            let (mut tree, monitor) = new_tree(mode, 12);
            let root = tree.root_for_publication().unwrap().value();
            let bits = 12 + 9 * u32::from(mode);
            let address = if bits >= 64 {
                u64::MAX - 4095
            } else {
                (1u64 << bits) - 4096
            };
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: the synchronous model exclusively reserves this final page.
            unsafe {
                tree.map(
                    address,
                    payload(0x2345_6000, &drops),
                    Direction::Bidirectional,
                )
            }
            .unwrap();
            assert_eq!(
                monitor.walk(root, mode, address + 4095),
                Some(Walk {
                    physical: 0x2345_6fff,
                    read: true,
                    write: true,
                    coherent: true,
                })
            );
            assert_eq!(monitor.walk(root, mode, address - 4096), None);
            if mode == 6 {
                let state = monitor.state.lock().unwrap();
                let root = state
                    .allocations
                    .iter()
                    .find(|item| item.physical == root)
                    .unwrap();
                for slot in 128..512 {
                    // SAFETY: the exact retained root allocation, read-only model.
                    assert_eq!(
                        unsafe { (root.cpu as *const u64).add(slot).read_volatile() },
                        0
                    );
                }
            }
            // SAFETY: no asynchronous requester exists in this fixture.
            unsafe { tree.unmap(address) }.unwrap();
            assert_eq!(monitor.walk(root, mode, address), None);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            let state = monitor.state.lock().unwrap();
            assert!(state.events.iter().any(
                |event| matches!(event, Event::Invalidate(start, 4096, true) if *start == address)
            ));
            drop(state);
            retired(tree, &monitor);
        }
    }

    #[test]
    fn expanded_unsorted_eight_k_scatter_aliases_publish_children_before_parents() {
        let (mut tree, monitor) = new_tree(2, 13);
        let root = tree.root_for_publication().unwrap().value();
        let drops = Arc::new(AtomicUsize::new(0));
        let first = pin(vec![0x900000, 0x700000], 13, drops.clone(), None);
        let second = pin(vec![0x300000], 13, drops.clone(), None);
        let pages = DmaPages::from_ranges(vec![
            PageRange::new(first.clone(), 8192..16384).unwrap(),
            PageRange::new(second, 0..8192).unwrap(),
            PageRange::new(first, 8192..16384).unwrap(),
        ])
        .unwrap();
        monitor.state.lock().unwrap().watch_payload = Some(drops.clone());
        let address = 0x1ff000;
        // SAFETY: the complete crossing span is exclusive and the model is idle.
        unsafe { tree.map(address, pages, Direction::ToDevice) }.unwrap();
        for (index, physical) in [0x700000, 0x701000, 0x300000, 0x301000, 0x700000, 0x701000]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                monitor.walk(root, 2, address + index as u64 * 4096),
                Some(Walk {
                    physical,
                    read: true,
                    write: false,
                    coherent: true,
                })
            );
        }
        assert_eq!(monitor.walk(root, 2, address + 6 * 4096), None);
        let events = monitor.state.lock().unwrap().events.clone();
        let published: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Publish {
                    physical,
                    words,
                    success,
                } => {
                    assert!(*success);
                    Some((*physical, words))
                }
                _ => None,
            })
            .collect();
        assert_eq!(published.len(), 7);
        assert!(published[0].1.iter().all(|word| *word == 0));
        assert!(published[1].1.iter().all(|word| *word == 0));
        assert_eq!(published[2].0, root);
        assert_eq!(published[2].1[0] & PA_MASK, published[1].0);
        assert!(published[3].1.iter().all(|word| *word == 0));
        assert_eq!(published[4].0, root);
        assert_eq!(published[4].1[1] & PA_MASK, published[3].0);
        assert_eq!(published[5].0, published[1].0);
        assert_eq!(published[6].0, published[3].0);
        assert!(matches!(
            events.last(),
            Some(Event::Invalidate(0x1ff000, 24576, true))
        ));
        assert!(events.iter().any(|event| matches!(event, Event::Admit(pages, Direction::ToDevice) if pages.as_slice() == [0x700000, 0x300000, 0x700000])));
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        let allocated = monitor.live_tables();
        // SAFETY: every modeled access is synchronous and stopped.
        unsafe { tree.unmap(address) }.unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert_eq!(
            monitor.live_tables(),
            allocated,
            "child pins wait for root retirement"
        );
        retired(tree, &monitor);
    }

    #[test]
    fn leaf_permissions_follow_direction_and_fixed_payload_policy() {
        for (direction, read, write, coherent) in [
            (Direction::ToDevice, true, false, false),
            (Direction::FromDevice, false, true, true),
            (Direction::Bidirectional, true, true, true),
        ] {
            let (mut tree, monitor) = new_tree(3, 12);
            monitor.state.lock().unwrap().coherent = coherent;
            let root = tree.root_for_publication().unwrap().value();
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: exact isolated span; no device/worker can submit.
            unsafe { tree.map(0x1234_5000, payload(0x4567_8000, &drops), direction) }.unwrap();
            assert_eq!(
                monitor.walk(root, 3, 0x1234_5678),
                Some(Walk {
                    physical: 0x4567_8678,
                    read,
                    write,
                    coherent,
                })
            );
            // SAFETY: exact synchronous software mapping has finished all accesses.
            unsafe { tree.unmap(0x1234_5000) }.unwrap();
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            retired(tree, &monitor);
        }
    }

    #[test]
    fn range_overlap_width_and_payload_admission_refuse_before_mutation() {
        let (mut tree, monitor) = new_tree(1, 12);
        let root = tree.root_for_publication().unwrap().value();
        let retained = Arc::new(AtomicUsize::new(0));
        // SAFETY: exact exclusive idle model span.
        unsafe {
            tree.map(
                0x2000,
                payload(0x300000, &retained),
                Direction::Bidirectional,
            )
        }
        .unwrap();
        for (address, pa, expected) in [
            (1, 0x400000, TranslationError::InvalidRange),
            (0x2000, 0x400000, TranslationError::Overlap),
            (0x200000, 0x400000, TranslationError::AddressLimit),
            (
                0xffff_ffff_ffff_f000,
                0x400000,
                TranslationError::AddressLimit,
            ),
            (0x4000, 1u64 << 48, TranslationError::AddressLimit),
        ] {
            let before = monitor.state.lock().unwrap().events.len();
            let rejected = Arc::new(AtomicUsize::new(0));
            // SAFETY: only numeric metadata is intentionally inadmissible.
            assert_eq!(
                unsafe { tree.map(address, payload(pa, &rejected), Direction::ToDevice) },
                Err(expected)
            );
            assert_eq!(rejected.load(Ordering::Relaxed), 1);
            assert_eq!(monitor.state.lock().unwrap().events.len(), before);
            assert!(!tree.is_poisoned());
        }
        // A multi-page range that overlaps at either edge is refused in full.
        for address in [0x1000, 0x2000] {
            let rejected = Arc::new(AtomicUsize::new(0));
            let pages = pin(vec![0x500000, 0x501000], 12, rejected.clone(), None).into();
            // SAFETY: model deliberately probes an overlapping reserved interval.
            assert_eq!(
                unsafe { tree.map(address, pages, Direction::ToDevice) },
                Err(TranslationError::Overlap)
            );
            assert_eq!(rejected.load(Ordering::Relaxed), 1);
        }
        monitor.state.lock().unwrap().fail_admit = true;
        let rejected = Arc::new(AtomicUsize::new(0));
        let before = monitor.state.lock().unwrap().publications;
        // SAFETY: the fixed model context explicitly refuses this payload policy.
        assert_eq!(
            unsafe { tree.map(0x4000, payload(0x600000, &rejected), Direction::ToDevice) },
            Err(TranslationError::Payload(DmaError::VisibilityFailed))
        );
        assert_eq!(rejected.load(Ordering::Relaxed), 1);
        assert_eq!(monitor.state.lock().unwrap().publications, before);
        assert!(!tree.is_poisoned());
        monitor.state.lock().unwrap().fail_admit = false;
        assert_eq!(monitor.walk(root, 1, 0x2000).unwrap().physical, 0x300000);
        assert_eq!(monitor.walk(root, 1, 0x4000), None);
        // Exact-start removal only, not an interior or absent interval.
        // SAFETY: synchronous fixture has no in-flight hardware accesses.
        assert_eq!(
            unsafe { tree.unmap(0x2001) },
            Err(TranslationError::NotMapped)
        );
        unsafe { tree.unmap(0x2000) }.unwrap();
        assert_eq!(retained.load(Ordering::Relaxed), 1);
        retired(tree, &monitor);
    }

    #[test]
    fn final_mode_six_native_span_keeps_unrepresentable_exclusive_end() {
        let (mut tree, monitor) = new_tree(6, 13);
        let root = tree.root_for_publication().unwrap().value();
        let rejected = Arc::new(AtomicUsize::new(0));
        let pages = pin(vec![0x300000], 13, rejected.clone(), None).into();
        // SAFETY: an oversized numeric IOVA interval must fail before mutation.
        assert_eq!(
            unsafe { tree.map(u64::MAX - 4095, pages, Direction::ToDevice) },
            Err(TranslationError::AddressLimit)
        );
        assert_eq!(rejected.load(Ordering::Relaxed), 1);
        assert!(!tree.is_poisoned());
        let drops = Arc::new(AtomicUsize::new(0));
        let physical = (1u64 << 48) - 8192;
        let address = u64::MAX - 8191;
        let pages = pin(vec![physical], 13, drops.clone(), None).into();
        // SAFETY: exact last8K model interval; its exclusive end requires the
        // TableHardware provider's full-domain invalidation, not wrapped bytes.
        unsafe { tree.map(address, pages, Direction::Bidirectional) }.unwrap();
        assert_eq!(
            monitor.walk(root, 6, u64::MAX),
            Some(Walk {
                physical: (1u64 << 48) - 1,
                read: true,
                write: true,
                coherent: true,
            })
        );
        assert!(address.checked_add(8192).is_none());
        // SAFETY: the fixture has no asynchronous requester or table writer.
        unsafe { tree.unmap(address) }.unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(
            monitor
                .state
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|event| matches!(event,
            Event::Invalidate(start, 8192, true) if *start == address))
        );
        retired(tree, &monitor);
    }

    #[test]
    fn unpublished_child_failures_rollback_without_poison_or_payload_retention() {
        for allocate_failure in [true, false] {
            let (mut tree, monitor) = new_tree(2, 12);
            let root = tree.root_for_publication().unwrap().value();
            {
                let mut state = monitor.state.lock().unwrap();
                if allocate_failure {
                    state.fail_allocate = Some(2);
                } else {
                    state.fail_publish = Some(2);
                }
            }
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: fresh isolated model span; failures precede any parent store.
            let result = unsafe { tree.map(0, payload(0x300000, &drops), Direction::ToDevice) };
            assert_eq!(
                result,
                Err(TranslationError::Table(TableError::Memory(
                    if allocate_failure {
                        MemoryError::OutOfMemory
                    } else {
                        MemoryError::Unavailable
                    }
                )))
            );
            assert!(!tree.is_poisoned());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(monitor.live_tables(), 1);
            assert_eq!(monitor.walk(root, 2, 0), None);
            {
                let mut state = monitor.state.lock().unwrap();
                state.fail_allocate = None;
                state.fail_publish = None;
            }
            let retry = Arc::new(AtomicUsize::new(0));
            // SAFETY: pre-mutation rollback left this exact model IOVA reusable.
            unsafe { tree.map(0, payload(0x500000, &retry), Direction::ToDevice) }.unwrap();
            unsafe { tree.unmap(0) }.unwrap();
            assert_eq!(retry.load(Ordering::Relaxed), 1);
            retired(tree, &monitor);
        }
    }

    #[test]
    fn root_construction_failures_release_unexposed_context_and_pins() {
        for stage in 0..4 {
            let monitor = Monitor::new();
            {
                let mut state = monitor.state.lock().unwrap();
                match stage {
                    1 => state.fail_allocate = Some(1),
                    2 => state.fail_publish = Some(1),
                    3 => state.panic_publish = Some(1),
                    _ => (),
                }
            }
            let hardware = Hardware {
                monitor: monitor.clone(),
                native_shift: 12,
            };
            let width = if stage == 0 { 31 } else { 48 };
            if stage == 3 {
                // SAFETY: an isolated unpublished root cannot be used by a
                // device. Unwinding its initial publication must release it.
                assert!(
                    catch_unwind(AssertUnwindSafe(|| unsafe {
                        PageTables::new(hardware, TableLevel::new(2).unwrap(), width, 30)
                    }))
                    .is_err()
                );
            } else {
                // SAFETY: same isolated model; invalid metadata/provider results
                // are injected before a root address can escape the constructor.
                let result =
                    unsafe { PageTables::new(hardware, TableLevel::new(2).unwrap(), width, 30) };
                let expected = match stage {
                    0 => TranslationError::Format(FormatError::PhysicalWidth),
                    1 => TranslationError::Table(TableError::Memory(MemoryError::OutOfMemory)),
                    _ => TranslationError::Table(TableError::Memory(MemoryError::Unavailable)),
                };
                match result {
                    Err(error) => assert_eq!(error, expected),
                    Ok(_) => panic!("root failure accepted"),
                }
            }
            assert_eq!(monitor.live_tables(), 0);
            assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
            assert_eq!(
                monitor.table_drops.load(Ordering::Relaxed),
                usize::from(stage >= 2)
            );
            if stage == 0 {
                assert_eq!(monitor.state.lock().unwrap().allocation_calls, 0);
            }
        }
    }

    #[test]
    fn actual_virtual_aperture_is_distinct_from_host_table_mode_capacity() {
        let monitor = Monitor::new();
        let hardware = Hardware {
            monitor: monitor.clone(),
            native_shift: 12,
        };
        // SAFETY: this software fixture admits a 32-bit virtual aperture even
        // though its three-level host format can represent 39 address bits.
        let mut tree =
            unsafe { PageTables::new(hardware, TableLevel::new(3).unwrap(), 48, 32) }.unwrap();
        let root = tree.root_for_publication().unwrap().value();
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: exact final page of the admitted 32-bit aperture is exclusive.
        unsafe { tree.map(0xffff_f000, payload(0x300000, &drops), Direction::ToDevice) }.unwrap();
        assert_eq!(
            monitor.walk(root, 3, 0xffff_ffff).unwrap().physical,
            0x300fff
        );
        for address in [1u64 << 32, (1u64 << 32) + 0xffff_f000] {
            let rejected = Arc::new(AtomicUsize::new(0));
            let before = monitor.state.lock().unwrap().events.len();
            // SAFETY: an address representable by mode3 but outside the actual
            // admitted aperture must not alias or mutate any retained mapping.
            assert_eq!(
                unsafe { tree.map(address, payload(0x500000, &rejected), Direction::FromDevice) },
                Err(TranslationError::AddressLimit)
            );
            assert_eq!(rejected.load(Ordering::Relaxed), 1);
            assert_eq!(monitor.state.lock().unwrap().events.len(), before);
            assert!(!tree.is_poisoned());
        }
        assert_eq!(
            monitor.walk(root, 3, 0xffff_ffff).unwrap().physical,
            0x300fff
        );
        // SAFETY: no asynchronous requester exists; exact model mapping is idle.
        unsafe { tree.unmap(0xffff_f000) }.unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        retired(tree, &monitor);

        for (mode, virtual_bits) in [(3, 0), (3, 11), (3, 40), (3, 65), (6, u8::MAX)] {
            let monitor = Monitor::new();
            let hardware = Hardware {
                monitor: monitor.clone(),
                native_shift: 12,
            };
            // SAFETY: only invalid numeric admission metadata is tested; this
            // failure must precede every allocation and visibility callback.
            let result = unsafe {
                PageTables::new(hardware, TableLevel::new(mode).unwrap(), 48, virtual_bits)
            };
            match result {
                Err(error) => assert_eq!(error, TranslationError::VirtualWidth),
                Ok(_) => panic!("invalid virtual aperture accepted"),
            }
            let state = monitor.state.lock().unwrap();
            assert_eq!(state.allocation_calls, 0);
            assert_eq!(state.publications, 0);
            assert!(state.events.is_empty());
            assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn later_path_failure_keeps_an_already_published_parent_and_payload() {
        for allocation_failure in [true, false] {
            let (mut tree, monitor) = new_tree(3, 12);
            let root = tree.root_for_publication().unwrap().value();
            {
                let mut state = monitor.state.lock().unwrap();
                // Root->level2 is already published when construction of the
                // level1 child fails; rolling back the whole binding is unsafe.
                if allocation_failure {
                    state.fail_allocate = Some(3);
                } else {
                    state.fail_publish = Some(4);
                }
            }
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: exact idle model interval, with injected later-path failure.
            let result = unsafe { tree.map(0, payload(0x300000, &drops), Direction::ToDevice) };
            assert_eq!(
                result,
                Err(TranslationError::Table(TableError::Memory(
                    if allocation_failure {
                        MemoryError::OutOfMemory
                    } else {
                        MemoryError::Unavailable
                    }
                )))
            );
            assert!(tree.is_poisoned());
            assert_eq!(monitor.live_tables(), 2);
            assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(monitor.walk(root, 3, 0), None);
            let rejected = Arc::new(AtomicUsize::new(0));
            // SAFETY: only the poisoned-owner refusal is exercised.
            assert_eq!(
                unsafe { tree.map(0, payload(0x500000, &rejected), Direction::ToDevice) },
                Err(TranslationError::Poisoned)
            );
            assert_eq!(rejected.load(Ordering::Relaxed), 1);
            retired(tree, &monitor);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn parent_leaf_and_invalidation_failures_poison_and_keep_original_pins() {
        for stage in [3, 4, 5] {
            let (mut tree, monitor) = new_tree(2, 12);
            let root = tree.root_for_publication().unwrap().value();
            {
                let mut state = monitor.state.lock().unwrap();
                if stage == 5 {
                    state.fail_invalidate = true;
                } else {
                    state.fail_publish = Some(stage);
                }
            }
            let drops = Arc::new(AtomicUsize::new(0));
            monitor.state.lock().unwrap().watch_payload = Some(drops.clone());
            // SAFETY: no model requester is active; injected uncertainty is retained.
            let result =
                unsafe { tree.map(0x8000, payload(0x600000, &drops), Direction::FromDevice) };
            let expected = if stage == 5 {
                TranslationError::Invalidation(DmaError::InvalidationFailed)
            } else {
                TranslationError::Table(TableError::Memory(MemoryError::Unavailable))
            };
            assert_eq!(result, Err(expected));
            assert!(tree.is_poisoned());
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(monitor.live_tables(), 2);
            if stage == 3 {
                assert_eq!(monitor.walk(root, 2, 0x8000), None);
            } else {
                assert_eq!(monitor.walk(root, 2, 0x8000).unwrap().physical, 0x600000);
            }
            let replacement = Arc::new(AtomicUsize::new(0));
            // SAFETY: refusal must precede any attempted IOVA/payload reuse.
            assert_eq!(
                unsafe { tree.map(0x8000, payload(0x700000, &replacement), Direction::ToDevice) },
                Err(TranslationError::Poisoned)
            );
            assert_eq!(replacement.load(Ordering::Relaxed), 1);
            assert_eq!(
                unsafe { tree.unmap(0x8000) },
                Err(TranslationError::Poisoned)
            );
            assert_eq!(tree.root_for_publication(), Err(TranslationError::Poisoned));
            retired(tree, &monitor);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn unmap_failure_and_callback_unwinds_keep_pins_and_prevent_reuse() {
        for scenario in [0, 1, 2, 3] {
            let (mut tree, monitor) = new_tree(2, 12);
            let root = tree.root_for_publication().unwrap().value();
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: this model reserves the exact idle IOVA span.
            unsafe { tree.map(0, payload(0x300000, &drops), Direction::Bidirectional) }.unwrap();
            let publications = monitor.state.lock().unwrap().publications;
            {
                let mut state = monitor.state.lock().unwrap();
                state.watch_payload = Some(drops.clone());
                match scenario {
                    0 => state.fail_invalidate = true,
                    1 => state.fail_publish = Some(publications + 1),
                    2 => state.panic_publish = Some(publications + 1),
                    _ => state.panic_invalidate = true,
                }
            }
            if scenario < 2 {
                // SAFETY: model is stopped; an unacknowledged removal retains pins.
                assert!(unsafe { tree.unmap(0) }.is_err());
            } else {
                // SAFETY: same stopped model. The injected callback unwinds after
                // a real leaf clear; the owner must stay conservatively poisoned.
                assert!(catch_unwind(AssertUnwindSafe(|| unsafe { tree.unmap(0) })).is_err());
            }
            assert!(tree.is_poisoned());
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(
                monitor.walk(root, 2, 0),
                None,
                "uncertain clear still retains its payload"
            );
            let rejected = Arc::new(AtomicUsize::new(0));
            // SAFETY: attempting reuse exercises the poisoned-owner refusal only.
            assert_eq!(
                unsafe { tree.map(0, payload(0x500000, &rejected), Direction::ToDevice) },
                Err(TranslationError::Poisoned)
            );
            assert_eq!(rejected.load(Ordering::Relaxed), 1);
            retired(tree, &monitor);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
        for panic_stage in [3, 4, 5] {
            let (mut tree, monitor) = new_tree(2, 12);
            tree.root_for_publication().unwrap();
            {
                let mut state = monitor.state.lock().unwrap();
                if panic_stage == 5 {
                    state.panic_invalidate = true;
                } else {
                    state.panic_publish = Some(panic_stage);
                }
            }
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: idle fixture injects unwind after parent/leaf publication.
            assert!(
                catch_unwind(AssertUnwindSafe(|| unsafe {
                    tree.map(0, payload(0x300000, &drops), Direction::ToDevice)
                }))
                .is_err()
            );
            assert!(tree.is_poisoned());
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            retired(tree, &monitor);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn empty_exposed_drop_quarantines_hardware_and_table_until_explicit_retirement() {
        let (tree, monitor) = new_tree(1, 12);
        drop(tree);
        assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 1);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);

        let (mut tree, monitor) = new_tree(1, 12);
        tree.root_for_publication().unwrap();
        retired(tree, &monitor);
        assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 1);

        let (mut tree, monitor) = new_tree(1, 12);
        tree.root_for_publication().unwrap();
        // One deliberately leaked 4K fixture proves actual Drop quarantine. Do
        // not reclaim its RAM behind the retained forgotten pin/context owners.
        let before = quarantine_status();
        drop(tree);
        let after = quarantine_status();
        assert!(after.trees >= before.trees.saturating_add(1));
        assert!(after.tables >= before.tables.saturating_add(1));
        assert!(after.payload_bytes >= before.payload_bytes);
        assert_eq!(monitor.live_tables(), 1);
        assert_eq!(monitor.table_drops.load(Ordering::Relaxed), 0);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);

        let (mut tree, monitor) = new_tree(1, 12);
        tree.root_for_publication().unwrap();
        monitor.state.lock().unwrap().fail_invalidate = true;
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: the isolated model has no actual requester; failed completion
        // conservatively models an exposed, uncertain payload mapping.
        assert_eq!(
            unsafe { tree.map(0, payload(0x300000, &drops), Direction::Bidirectional) },
            Err(TranslationError::Invalidation(DmaError::InvalidationFailed))
        );
        let before = quarantine_status();
        drop(tree);
        let after = quarantine_status();
        assert!(after.trees >= before.trees.saturating_add(1));
        assert!(after.tables >= before.tables.saturating_add(1));
        assert!(after.payload_bytes >= before.payload_bytes.saturating_add(4096));
        assert_eq!(monitor.live_tables(), 1);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }
}
