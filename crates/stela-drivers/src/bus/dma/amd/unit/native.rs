// SPDX-License-Identifier: GPL-2.0-only
// Command/register sequencing adapted from Linux drivers/iommu/amd at
// a804c5742bff224d4cb4d25dd383554d598be32b, AMD copyright 2007-2010.
//! Cold, exclusive AMDv1 requester ownership. This is process
//! local: the original PCI/UC/root owner is not promoted to Send/Sync. Native
//! provisioning and a cross-thread process-context adapter remain platform work.
//!
//! Each unit is one IVHD's remapper, with its device entries' coverage,
//! aliases and DTE settings; ATS/PASID/PRI, guest translation and
//! interrupt-table owners stay absent. A unit can give its covered
//! requesters a window domain that maps given memory one to one
//! ([`Unit::window`]), which a requester leaves when it attaches.
//! Faults keep every original owner; they never disable translation into
//! bypass. Completion stores acknowledge invalidations, not device stop or an
//! arbitrary posted-payload drain. No DmaDomain implementation is invented.
//! Healthy retirement releases internal RAM after engines stop and register
//! pointers clear. Original PCI/UC mappings have no consuming handback yet;
//! their registry quarantine remains boot-lifetime, not hotplug reclamation.
mod buffer;
mod firmware;
mod queue;
mod requester;

use super::registers::{self, FunctionInspection};
use crate::{
    Clock,
    bus::dma::{
        amd::{
            device::{DeviceTable, DeviceTableError, DeviceTableHardware},
            format::{Command, DomainId, PhysicalAddress, TableLevel},
            ivrs::Ivrs,
            memory::TableVisibility,
            tables::{PageTables, TableHardware, TranslationError},
        },
        mapping::{Direction, DmaError},
        memory::{CacheAttribute, MemoryError, PageGeometry, PageSource, PinnedPages},
        pages::DmaPages,
    },
};
use alloc::{rc::Rc, vec::Vec};
use buffer::Buffer;
use core::{
    cell::{Cell, RefCell},
    mem::ManuallyDrop,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};
pub use requester::{Mapping, Requester};

const DEVICE_TABLE: usize = 0;
const COMMAND_BASE: usize = 8;
const EVENT_BASE: usize = 16;
const CONTROL: usize = 24;
const EXCLUSION_BASE: usize = 32;
const EXCLUSION_LIMIT: usize = 40;
const HARDWARE_EVENT_STATUS: usize = 0x50;
const COMMAND_HEAD: usize = 0x2000;
const COMMAND_TAIL: usize = 0x2008;
const EVENT_HEAD: usize = 0x2010;
const EVENT_TAIL: usize = 0x2018;
const STATUS: usize = 0x2020;
const IOMMU_ENABLE: u64 = 1;
const EVENT_ENABLE: u64 = 1 << 2;
const COHERENT: u64 = 1 << 10;
const COMMAND_ENABLE: u64 = 1 << 12;
const EVENT_RUNNING: u64 = 1 << 3;
const COMMAND_RUNNING: u64 = 1 << 4;
const RUNNING: u64 = EVENT_RUNNING | COMMAND_RUNNING;
const RING_BYTES: usize = 8192;
const RING_LENGTH: u64 = 9 << 56;
const COMMAND_BYTES: usize = 16;
static QUARANTINED_UNITS: AtomicU64 = AtomicU64::new(0);

/// Exposed cold-unit owners kept on uncertain Drop. Not reset evidence.
pub fn quarantined_units() -> u64 {
    QUARANTINED_UNITS.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Firmware,
    Profile,
    NotCold,
    Busy,
    Requester,
    Exhausted,
    Fault,
    Timeout,
    Poisoned,
    Mapping,
    Memory(MemoryError),
    Register(registers::Error),
    DeviceTable(DeviceTableError),
    Translation(TranslationError),
    Dma(DmaError),
}

/// Native context/cache/RAM services, not numeric attestations.
///
/// # Safety
/// The implementor owns the original unit's root/bridge/reset/configuration,
/// firmware and all covered requester/IRQ/deferred/prior-DMA epochs. The cold
/// entry grant is independently established by reset and stopped/drained
/// requesters, not by a zero control register. All software/firmware unit/table
/// writers remain excluded until explicit final retirement. The kept
/// FunctionInspection is the original unit for this same epoch; native aligned
/// UC read64/write64 and coherent WB command/completion/event DMA are checked.
/// Unencrypted RAM and host-only AMDv1 tables are checked at physical_bits();
/// SNP, ATS (including integrated alternate signaling), PASID/PRI,
/// hardware table updates, guest and IRQ-remapping owners are absent and cannot
/// become enabled. Requesters cannot issue DMA while a new DTE is being
/// attached or detached. No driver may use this owner to reset another domain.
/// Every allocation is fresh zeroed CPU-exclusive RAM with true physical pins.
/// `enter` keeps checked process/root/current-CPU/CX16/cache context, prevents
/// migration when required, and excludes external writers. Nested entry on the
/// same process is supported, never waits on its own nonreentrant lock, permits
/// completion progress, and no callback may reenter this backend. This backend
/// is !Send/!Sync and serializes its own queue separately. `clock` is the
/// checked nonzero monotonic TSC clock for this context. Visibility and sync
/// perform real hardware ordering/cache work; unsupported work returns failure.
pub unsafe trait ColdPlatform: PageSource + TableVisibility {
    type Access<'a>
    where
        Self: 'a;
    fn enter(&self) -> Result<Self::Access<'_>, DmaError>;
    fn clock(&self) -> Clock;
    fn physical_bits(&self) -> u8;
    fn admit_payload(&self, pages: &DmaPages, direction: Direction) -> Result<bool, DmaError>;
    /// # Safety
    /// Kept pages, bounded range and original mapping direction. CPU
    /// ownership for a CPU sync and stopped writers are established by caller.
    unsafe fn sync(
        &self,
        pages: &DmaPages,
        range: Range<usize>,
        direction: Direction,
        for_cpu: bool,
    ) -> Result<(), DmaError>;
    /// Allow real hardware/IRQ progress. No completion permission is returned.
    fn relax(&self) {
        crate::waiting();
        core::hint::spin_loop();
    }
}

/// Bounded translation and wait resources; no implicit host-sized allocation.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub table_pages: usize,
    pub table_backing_bytes: usize,
    pub mappings: usize,
    pub wait_us: u64,
}

struct Resources<P> {
    inspection: FunctionInspection,
    platform: P,
    command: Buffer,
    completion: Buffer,
    event: Buffer,
}

struct Queue {
    tail: usize,
    sequence: u64,
}

struct Engine<P> {
    resources: ManuallyDrop<Resources<P>>,
    queue: RefCell<Queue>,
    poisoned: Cell<bool>,
    exposed: Cell<bool>,
    retired: Cell<bool>,
    control: u64,
    hardware_errors: bool,
    wait_us: u64,
    table_base: Cell<u64>,
}

impl<P> Drop for Engine<P> {
    fn drop(&mut self) {
        if self.exposed.get() && !self.retired.get() {
            let _ = QUARANTINED_UNITS.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
            // Keep original PCI/UC/root/platform owners and all possible DMA
            // targets together. Drop cannot establish cold/reset or DMA stop.
        } else {
            // SAFETY: no register exposure, or explicit acknowledged final
            // retirement. ManuallyDrop owns this unique resources object.
            unsafe { ManuallyDrop::drop(&mut self.resources) };
        }
    }
}

struct Hardware<P> {
    engine: Rc<Engine<P>>,
    domain: Option<DomainId>,
    // A poisoned/exposed tree keeps its original requester configuration
    // together with the original unit/root and payload/table pins.
    requester: Option<Rc<requester::Owner>>,
}
impl<P> Clone for Hardware<P> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            domain: self.domain,
            requester: self.requester.clone(),
        }
    }
}
impl<P: ColdPlatform> PageSource for Hardware<P> {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        self.engine.resources.platform.page_geometry()
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        self.engine
            .resources
            .platform
            .allocate(bytes, alignment, attribute)
    }
}
// SAFETY: the original unsafe platform supplies table visibility; this
// adapter preserves the exact bytes and original unit context.
unsafe impl<P: ColdPlatform> TableVisibility for Hardware<P> {
    unsafe fn publish(&self, cpu: NonNull<u8>, bytes: usize) -> Result<(), MemoryError> {
        // SAFETY: inherited exact WB span contract, forwarded without escape.
        unsafe { self.engine.resources.platform.publish(cpu, bytes) }
    }
}
// SAFETY: one closed, externally exclusive unit; enter keeps its CX16
// execution context. Queue completion is a real exact-sequence coherent store.
unsafe impl<P: ColdPlatform> DeviceTableHardware for Hardware<P> {
    type Access<'a>
        = P::Access<'a>
    where
        Self: 'a;
    fn enter(&self) -> Result<Self::Access<'_>, DmaError> {
        self.engine.resources.platform.enter()
    }
    fn invalidate(&self, requester: u16, old_domain: Option<DomainId>) -> Result<(), DmaError> {
        let commands = [
            Command::invalidate_device(requester),
            old_domain
                .map(|id| Command::invalidate_domain(id, true))
                .unwrap_or_else(|| Command::invalidate_device(requester)),
        ];
        self.engine
            .execute(&commands)
            .map_err(|_| DmaError::InvalidationFailed)
    }
}
// SAFETY: every tree is bound to its reserved domain and original requester;
// full-domain invalidation includes PDE caches and exact completion. Payload
// cache/encryption admission is supplied by the native platform.
unsafe impl<P: ColdPlatform> TableHardware for Hardware<P> {
    fn invalidate(&self, _: u64, _: usize) -> Result<(), DmaError> {
        let id = self.domain.ok_or(DmaError::IommuUnavailable)?;
        self.engine
            .execute(&[Command::invalidate_domain(id, true)])
            .map_err(|_| DmaError::InvalidationFailed)
    }
    fn admit_payload(&self, pages: &DmaPages, direction: Direction) -> Result<bool, DmaError> {
        self.engine
            .resources
            .platform
            .admit_payload(pages, direction)
    }
}

/// The window domain: one to one page tables shared by the requesters that
/// have no domain of their own.
struct Window<P: ColdPlatform> {
    tree: PageTables<Hardware<P>>,
    requesters: Vec<u16>,
}

/// Original cold unit plus complete blocked DTE table and bounded RID policy.
/// Requesters and their page trees keep this exact engine independently.
pub struct Unit<P: ColdPlatform> {
    engine: Rc<Engine<P>>,
    table: Rc<RefCell<DeviceTable<Hardware<P>>>>,
    coverage: Vec<bool>,
    aliases: Vec<(u16, u16)>,
    window: Option<Window<P>>,
    active: Rc<RefCell<Vec<u16>>>,
    next_domain: Cell<u32>,
    segment: u16,
    physical_bits: u8,
    limits: Limits,
}

impl<P: ColdPlatform> Unit<P> {
    /// # Safety
    /// `platform` is the original cold/exclusive native owner described by
    /// ColdPlatform, for this exact inspection and complete original IVRS. No
    /// DMA or external writer can start before initialization finishes. This
    /// does not derive cold/reset permission from register observations. Failure
    /// after first publication quarantines original resources.
    pub unsafe fn cold(
        inspection: FunctionInspection,
        ivrs: &Ivrs<'_>,
        platform: P,
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.table_pages == 0
            || limits.table_backing_bytes < 4096
            || limits.mappings == 0
            || limits.wait_us == 0
            || limits.wait_us > 1_000_000
            || platform.clock().ticks_per_microsecond == 0
        {
            return Err(Error::Profile);
        }
        let guard = platform.enter().map_err(Error::Dma)?;
        let admitted = firmware::admit(&inspection, ivrs, platform.physical_bits())?;
        let command = Buffer::allocate(&platform, RING_BYTES, admitted.bits)?;
        let completion = Buffer::allocate(&platform, 4096, admitted.bits)?;
        let event = Buffer::allocate(&platform, RING_BYTES, admitted.bits)?;
        drop(guard);
        let engine = Rc::new(Engine {
            resources: ManuallyDrop::new(Resources {
                inspection,
                platform,
                command,
                completion,
                event,
            }),
            queue: RefCell::new(Queue {
                tail: 0,
                sequence: 0,
            }),
            poisoned: Cell::new(false),
            exposed: Cell::new(false),
            retired: Cell::new(false),
            control: admitted.control,
            hardware_errors: admitted.hardware_errors,
            wait_us: limits.wait_us,
            table_base: Cell::new(0),
        });
        let hardware = Hardware {
            engine: engine.clone(),
            domain: None,
            requester: None,
        };
        // SAFETY: complete effective plain policy and original cold ownership
        // were checked before allocation; all context stays held.
        let mut table = unsafe { DeviceTable::new(hardware, &admitted.policies, admitted.bits) }
            .map_err(Error::DeviceTable)?;
        let _guard = engine.resources.platform.enter().map_err(Error::Dma)?;
        engine.check_cold()?;
        let base = table
            .register_for_publication()
            .map_err(Error::DeviceTable)?;
        // Arm before even the first store/callback can unwind or fail.
        engine.exposed.set(true);
        engine.initialize(base)?;
        drop(_guard);
        Ok(Self {
            engine,
            table: Rc::new(RefCell::new(table)),
            coverage: admitted.coverage,
            aliases: admitted.aliases,
            window: None,
            active: Rc::new(RefCell::new(Vec::new())),
            next_domain: Cell::new(1),
            segment: admitted.segment,
            physical_bits: admitted.bits,
            limits,
        })
    }

    /// Whether the unit's IVHD covers requester `rid` on `segment`.
    pub fn covers(&self, segment: u16, rid: u16) -> bool {
        segment == self.segment && self.coverage[usize::from(rid)]
    }

    /// The requester IDs `rid`'s DMA arrives under: its own and its alias.
    fn group(&self, rid: u16) -> Vec<u16> {
        let mut group = alloc::vec![rid];
        group.extend(
            self.aliases
                .iter()
                .filter(|&&(source, _)| source == rid)
                .map(|&(_, target)| target),
        );
        group
    }

    /// Whether another requester's DMA arrives under one of `group`'s IDs,
    /// so `group` cannot have a domain of its own.
    fn shared(&self, rid: u16, group: &[u16]) -> bool {
        self.aliases.iter().any(|&(source, target)| {
            source != rid && (group.contains(&target) || group.contains(&source))
        })
    }

    /// Give `requesters`, with their aliases, the window domain, which maps
    /// each of `ranges` (one physically contiguous run each) at its own
    /// physical address.
    ///
    /// # Safety
    /// Each requester DMAs only to `ranges` until it attaches, and each
    /// range is memory the platform admits for device DMA and keeps for the
    /// boot.
    pub unsafe fn window(
        &mut self,
        requesters: &[u16],
        ranges: Vec<DmaPages>,
    ) -> Result<(), Error> {
        if self.engine.retired.get() || self.engine.poisoned.get() {
            return Err(Error::Poisoned);
        }
        if self.window.is_some() || ranges.is_empty() {
            return Err(Error::Busy);
        }
        let mut covered = Vec::new();
        for &rid in requesters {
            if !self.coverage[usize::from(rid)] {
                return Err(Error::Requester);
            }
            for member in self.group(rid) {
                if !covered.contains(&member) {
                    covered.push(member);
                }
            }
        }
        let mut end = 0u64;
        let mut leaves = 0usize;
        for pages in &ranges {
            let size = 1u64 << pages.page_shift();
            let first = *pages.physical_pages().first().ok_or(Error::Mapping)?;
            if pages
                .physical_pages()
                .iter()
                .enumerate()
                .any(|(index, &page)| page != first + index as u64 * size)
            {
                return Err(Error::Mapping);
            }
            end = end.max(first + pages.bytes() as u64);
            leaves += pages.bytes().div_ceil(1 << 21) + 1;
        }
        let bits = (u64::BITS - (end - 1).leading_zeros()).max(21) as u8;
        let mode = (1..=4u8)
            .find(|mode| 12 + 9 * u32::from(*mode) >= u32::from(bits))
            .ok_or(Error::Profile)?;
        let level = TableLevel::new(mode).map_err(|_| Error::Profile)?;
        let next = self.next_domain.get();
        let id = u16::try_from(next)
            .ok()
            .and_then(DomainId::new)
            .ok_or(Error::Exhausted)?;
        self.next_domain.set(next + 1);
        let hardware = Hardware {
            engine: self.engine.clone(),
            domain: Some(id),
            requester: None,
        };
        let pages = leaves * usize::from(mode) + 1;
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()?;
        // SAFETY: the level covers every range's physical address, within
        // the admitted host translation; the tree is this domain's alone.
        let mut tree = unsafe {
            PageTables::new(
                hardware,
                level,
                self.physical_bits,
                level.address_bits() as u8,
                pages,
                pages * 4096,
            )
        }
        .map_err(Error::Translation)?;
        for range in ranges {
            let address = range.physical_pages()[0];
            // SAFETY: a fresh tree no device walks yet; each range maps at
            // its own address, and the ranges are the caller's.
            unsafe { tree.map(address, range, Direction::Bidirectional) }
                .map_err(Error::Translation)?;
        }
        let root = tree.root_for_publication().map_err(Error::Translation)?;
        for &rid in &covered {
            // SAFETY: forwarded: the requester DMAs only to the ranges.
            unsafe { self.table.borrow_mut().translate(rid, root, level, id) }
                .map_err(Error::DeviceTable)?;
        }
        drop(_guard);
        self.window = Some(Window {
            tree,
            requesters: covered,
        });
        Ok(())
    }

    /// Poll without clearing event/fault evidence. A fault poisons this exact
    /// owner; translation stays enabled and all live RAM/root owners remain.
    pub fn check_health(&self) -> Result<(), Error> {
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()
    }

    /// No standalone completion or cache invalidation is promoted into an
    /// arbitrary payload-drain witness. A native root drain provider is absent.
    pub fn drain_posted_writes(&self) -> Result<(), DmaError> {
        Err(DmaError::DrainUnavailable)
    }

    /// # Safety
    /// Every requester covered by the original cold grant is again stopped,
    /// with payload/IRQ/work/prior-DMA drains complete. No requester may
    /// resume after this operation: disabling translation would enable bypass.
    /// All Requester owners must have completed detach, not been dropped.
    /// Success retires internal walker/command/event targets, not PCI mappings;
    /// their original native platform retirement obligations still apply.
    pub unsafe fn retire(&mut self) -> Result<(), Error> {
        if !self.active.borrow().is_empty() || Rc::strong_count(&self.table) != 1 {
            return Err(Error::Busy);
        }
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        if let Some(window) = &mut self.window {
            for &rid in &window.requesters {
                // SAFETY: forwarded: every covered requester is stopped.
                unsafe { self.table.borrow_mut().block(rid) }.map_err(Error::DeviceTable)?;
            }
            // SAFETY: every DTE that named the tree is blocked and invalidated.
            unsafe { window.tree.retire() };
            self.window = None;
        }
        self.engine.execute(&[Command::invalidate_all()])?;
        self.engine.poisoned.set(true);
        self.engine.write(CONTROL, 0)?;
        let deadline = self
            .engine
            .resources
            .platform
            .clock()
            .deadline(self.limits.wait_us);
        loop {
            if self.engine.read(STATUS)? == 0 && self.engine.read(CONTROL)? == 0 {
                break;
            }
            if deadline.passed() {
                return Err(Error::Timeout);
            }
            self.engine.resources.platform.relax();
        }
        // Both engines are stopped. Remove every stale RAM pointer
        // before releasing its pin; a later cold owner cannot inherit pointers
        // into a previous allocator epoch. Never perform this on a fault path.
        for offset in [
            DEVICE_TABLE,
            COMMAND_BASE,
            EVENT_BASE,
            COMMAND_HEAD,
            COMMAND_TAIL,
            EVENT_HEAD,
            EVENT_TAIL,
        ] {
            self.engine.write(offset, 0)?;
            if self.engine.read(offset)? != 0 {
                return Err(Error::Fault);
            }
        }
        drop(_guard);
        // SAFETY: all external requesters/drains are a real caller obligation;
        // final full invalidation/store plus observed engine stop completed.
        unsafe { self.table.borrow_mut().retire() };
        self.engine.retired.set(true);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
