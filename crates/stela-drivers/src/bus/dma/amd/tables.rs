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
    ResourceLimit,
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

/// A private path edge, staged before any hardware-visible parent changes.
struct Link {
    parent: usize,
    slot: usize,
    entry: PageEntry,
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
    maximum_table_pages: usize,
    maximum_backing_bytes: usize,
    backing_bytes: usize,
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
    /// `maximum_table_pages` is the real domain's retained-table budget, including
    /// the root and empty children. The live IOVA allocator must reuse/pack its
    /// aperture within this budget; unmap does not implicitly free child tables.
    /// `maximum_backing_bytes` separately bounds full retained native pins,
    /// including unused tails, rather than assuming 4 KiB per logical table.
    pub unsafe fn new(
        hardware: H,
        level: TableLevel,
        physical_bits: u8,
        virtual_bits: u8,
        maximum_table_pages: usize,
        maximum_backing_bytes: usize,
    ) -> Result<Self, TranslationError> {
        PhysicalAddress::new(0, physical_bits).map_err(TranslationError::Format)?;
        if !(12..=64).contains(&virtual_bits) || u32::from(virtual_bits) > level.address_bits() {
            return Err(TranslationError::VirtualWidth);
        }
        if maximum_table_pages == 0
            || maximum_table_pages > u32::MAX as usize
            || maximum_backing_bytes < TABLE_BYTES
        {
            return Err(TranslationError::ResourceLimit);
        }
        let mut nodes = Vec::new();
        nodes
            .try_reserve(1)
            .map_err(|_| TranslationError::Memory(MemoryError::OutOfMemory))?;
        let root = Node::new(&hardware, level, physical_bits)?;
        let backing_bytes = root.table.retained_bytes();
        if backing_bytes > maximum_backing_bytes {
            return Err(TranslationError::ResourceLimit);
        }
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
                maximum_table_pages,
                maximum_backing_bytes,
                backing_bytes,
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

    fn stage_path(&mut self, address: u64, links: &mut Vec<Link>) -> Result<(), TranslationError> {
        let mut node = 0;
        while let Some(level) = self.nodes[node].level.child() {
            let slot = self.nodes[node].level.index(address);
            let mut child = self.nodes[node].children[slot] as usize;
            if child == 0 {
                if self.nodes.len() >= self.maximum_table_pages
                    || self
                        .backing_bytes
                        .checked_add(TABLE_BYTES)
                        .is_none_or(|bytes| bytes > self.maximum_backing_bytes)
                {
                    return Err(TranslationError::ResourceLimit);
                }
                let index =
                    u32::try_from(self.nodes.len()).map_err(|_| TranslationError::ResourceLimit)?;
                links
                    .try_reserve(1)
                    .map_err(|_| TranslationError::Memory(MemoryError::OutOfMemory))?;
                self.nodes
                    .try_reserve(1)
                    .map_err(|_| TranslationError::Memory(MemoryError::OutOfMemory))?;
                let new = Node::new(&self.hardware, level, self.physical_bits)?;
                let backing_bytes = self
                    .backing_bytes
                    .checked_add(new.table.retained_bytes())
                    .filter(|bytes| *bytes <= self.maximum_backing_bytes)
                    .ok_or(TranslationError::ResourceLimit)?;
                // Cache visibility does not publish a parent or allow the
                // callback to retain this span. The new page remains unreachable
                // by hardware and can be released on controlled staging failure.
                new.table
                    .publish(&self.hardware)
                    .map_err(TranslationError::Table)?;
                let entry = PageEntry::table(new.table.physical(), self.nodes[node].level)
                    .map_err(TranslationError::Format)?;
                child = index as usize;
                self.nodes.push(new);
                self.backing_bytes = backing_bytes;
                self.nodes[node].children[slot] = index;
                links.push(Link {
                    parent: node,
                    slot,
                    entry,
                });
            } else if child >= self.nodes.len() {
                return Err(TranslationError::Corrupt);
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
        let original_nodes = self.nodes.len();
        let original_backing_bytes = self.backing_bytes;
        let mut links = Vec::new();
        let staged = (|| {
            for offset in (0..bytes).step_by(TABLE_BYTES) {
                self.stage_path(address + offset as u64, &mut links)?;
            }
            self.check_leaves(position, false)
        })();
        if let Err(error) = staged {
            // No hardware parent was changed. Undo private edges while every
            // referenced staged parent still exists, then release unreachable
            // fresh RAM. A provider unwind never reaches this healthy rollback.
            for link in links.iter().rev() {
                self.nodes[link.parent].children[link.slot] = 0;
            }
            self.nodes.truncate(original_nodes);
            self.backing_bytes = original_backing_bytes;
            return Err(error);
        }
        // Child edges were staged after their parent edge. Reverse order makes
        // each new subtree visible before any ancestor can point at it.
        for link in links.iter().rev() {
            *mutated = true; // Coherent walkers may observe the next store.
            self.nodes[link.parent]
                .table
                .write(link.slot, link.entry)
                .map_err(TranslationError::Table)?;
            self.nodes[link.parent]
                .table
                .publish(&self.hardware)
                .map_err(TranslationError::Table)?;
        }
        self.write_leaves(position, true, mutated)
    }

    fn remove(&mut self, position: usize) -> Result<(), TranslationError> {
        self.check_leaves(position, true)?;
        let mut mutated = false;
        self.write_leaves(position, false, &mut mutated)
    }
}

#[cfg(test)]
mod tests;
