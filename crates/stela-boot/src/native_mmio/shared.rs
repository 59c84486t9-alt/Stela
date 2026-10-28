//! The mount's native MMIO source: owned uncached mappings in the
//! loader-built aperture, valid on every host processor and in every root
//! that shares the loader's window, which is every root the engine builds.
//!
//! The controls the leaves need are checked once on the boot processor
//! (`stela_boot_core::aperture::qualify`); the other host processors run
//! with the same PAT, which their bootstrap programs from the boot
//! processor's. An access checks only that the current root reaches the
//! aperture and that the only handler running is a device interrupt's
//! ([`crate::native_irq`]); mapping and unmapping refuse in every handler.
//! Installations are
//! serialized by the platform's lock and need no remote flush; once the other
//! processors start, a retirement shoots the translation down on each of them
//! ([`super::shootdown`]).
use super::*;
use super::{
    capture::LEAVES,
    platform::{aliases, owned_table},
};
use crate::{engine::host::HostOwner, native_smp::memory_types::Image};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    arch::asm,
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_boot_core::aperture::{self, Controls, Flush, Processors};
use stela_drivers::bus::{
    mmio::owned::{
        AddressSpace, Authority, CacheAttribute, InstalledMapping, MapFailure, MapRequest,
        MappingPlatform, PhysicalSpan, Protection, Resource, ResourceBacking, ResourceKind,
    },
    pci::EcamWindow,
};

/// Which host processors may hold aperture translations, for the boot.
pub(crate) static PROCESSORS: Processors = Processors::new();

/// A span this source reserved: a captured ECAM bus or a BAR inside a root
/// bridge window, outside RAM.
struct Backing {
    owner: Arc<Captured>,
    span: PhysicalSpan,
    kind: ResourceKind,
}
// SAFETY: `Source` mints a backing only for spans the captured MCFG or root
// bridge windows describe and the final memory map leaves outside RAM.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn kind(&self) -> ResourceKind {
        self.kind
    }
}

struct Captured {
    wire: &'static Wire,
}

/// The aperture's two mapping sizes: 4 KiB pages in its leaf tables and
/// 2 MiB pages in its directory's other entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Size {
    Page,
    Large,
}

impl Size {
    fn bytes(self) -> u64 {
        match self {
            Size::Page => PAGE,
            Size::Large => PAGE << 9,
        }
    }
    /// The slots of this size, numbered from the aperture's base in units
    /// of this size.
    fn slots(self) -> core::ops::Range<usize> {
        match self {
            Size::Page => 0..LEAVES * ENTRIES,
            Size::Large => LEAVES..ENTRIES,
        }
    }
    /// The size a request maps with: 2 MiB pages when it is 2 MiB aligned at
    /// both ends.
    fn of(physical: PhysicalSpan) -> Self {
        let large = Size::Large.bytes();
        if physical.start().is_multiple_of(large) && physical.bytes().is_multiple_of(large) {
            Size::Large
        } else {
            Size::Page
        }
    }
}

struct Allocation {
    request: MapRequest,
    size: Size,
    first: usize,
    count: usize,
}

struct Platform {
    captured: Arc<Captured>,
    space: AddressSpace,
    flush: Flush,
    /// The TSC rate the shootdown's wait is measured in.
    tsc_hz: u64,
    /// The loader root's top-level entry for the aperture, and its slot.
    loader_entry: u64,
    slot: usize,
    held: AtomicBool,
    mappings: UnsafeCell<Vec<Allocation>>,
}
// SAFETY: the metadata is immutable; `mappings` is reached only under `held`.
unsafe impl Send for Platform {}
unsafe impl Sync for Platform {}

/// Present, NX, and PWT and PCD for PAT entry 3, uncached.
const RIGHTS: u64 = PRESENT | NX | (1 << 3) | (1 << 4);
/// The processor's accessed and dirty bits.
const ACCESSED_DIRTY: u64 = 0x60;

fn current_root() -> u64 {
    let root: u64;
    // SAFETY: CPL0 observation.
    unsafe { asm!("mov {}, cr3", out(reg) root, options(nomem, nostack, preserves_flags)) };
    root & ADDRESS
}

impl Platform {
    fn wire(&self) -> &'static Wire {
        self.captured.wire
    }
    /// The entry of slot `index` of `size`.
    fn entry(&self, size: Size, index: usize) -> Result<*mut u64, Error> {
        if !size.slots().contains(&index) {
            return Err(Error::InvalidRange);
        }
        let wire = self.wire();
        Ok(match size {
            Size::Page => {
                owned_table(wire, wire.leaves[index / ENTRIES])?.wrapping_add(index % ENTRIES)
            }
            Size::Large => owned_table(wire, wire.directory)?.wrapping_add(index),
        })
    }
    fn address(&self, size: Size, index: usize) -> u64 {
        self.wire().virtual_base + index as u64 * size.bytes()
    }
    fn value(size: Size, physical: u64, protection: Protection) -> u64 {
        physical
            | RIGHTS
            | if protection == Protection::ReadWrite {
                WRITABLE
            } else {
                0
            }
            | if size == Size::Large { HUGE } else { 0 }
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
    fn invalidate(&self, size: Size, first: usize, count: usize) {
        // SAFETY: TLB maintenance only; CR4 is restored to its value.
        unsafe {
            asm!("mfence", options(nostack, preserves_flags));
            match self.flush {
                Flush::Pages => {
                    for index in first..first + count {
                        let address = self.address(size, index);
                        asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags));
                    }
                }
                Flush::AllContexts => {
                    let saved: u64;
                    asm!("pushfq", "pop {}", "cli", out(reg) saved);
                    let cr4: u64;
                    asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
                    asm!("mov cr4, {}", in(reg) cr4 ^ (1 << 7), options(nostack, preserves_flags));
                    asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
                    asm!("push {}", "popfq", in(reg) saved);
                }
            }
            asm!("mfence", options(nostack, preserves_flags));
        }
    }
    fn resource(&self, resource: &Resource) -> bool {
        if let Some(backing) = resource.backing().downcast_ref::<Backing>() {
            return Arc::ptr_eq(&backing.owner, &self.captured)
                && backing.span == resource.physical_span();
        }
        stela_drivers::platform::acpi::resources::reservation_parent(resource)
            .is_some_and(|parent| self.resource(parent))
    }
}

struct Guard<'a>(&'a Platform);
impl Guard<'_> {
    fn mappings(&mut self) -> &mut Vec<Allocation> {
        // SAFETY: the held lock; no callback runs while borrowed.
        unsafe { &mut *self.0.mappings.get() }
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

// SAFETY: map publishes only the aperture's own leaves, uncached through PAT
// entry 3, which `qualify` checked; every processor runs the same PAT and
// every engine root shares the leaf table. Installation needs no remote
// flush, and retirement refuses once a remote TLB may hold the translation.
unsafe impl MappingPlatform for Platform {
    fn check_context(&self, space: AddressSpace) -> Result<(), Error> {
        if space != self.space
            || (crate::engine::host::in_interrupt() && !crate::native_irq::in_device_dispatch())
        {
            return Err(Error::Unavailable);
        }
        // SAFETY: the current root page is RAM the physmap reaches.
        let entry = unsafe {
            (crate::layout::physical(current_root()) as *const u64)
                .add(self.slot)
                .read_volatile()
        };
        if !aperture::shares_aperture(entry, self.loader_entry) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        let unchanged = MapFailure::Unchanged;
        if crate::engine::host::in_interrupt() {
            return Err(unchanged(Error::Unavailable));
        }
        self.check_context(request.address_space)
            .map_err(unchanged)?;
        if request.attribute != CacheAttribute::Uncached {
            return Err(unchanged(Error::UnsupportedCache));
        }
        if !self.resource(resource) {
            return Err(unchanged(Error::OutsideResource));
        }
        let size = Size::of(request.physical);
        let count = usize::try_from(request.physical.bytes() / size.bytes())
            .map_err(|_| unchanged(Error::InvalidRange))?;
        let slots = size.slots();
        if count == 0 || count > slots.len() {
            return Err(unchanged(Error::Exhausted));
        }
        let mut guard = self.lock();
        let mappings = guard.mappings();
        mappings
            .try_reserve(1)
            .map_err(|_| unchanged(Error::Exhausted))?;
        let first = (slots.start..=slots.end - count)
            .find(|first| {
                mappings
                    .iter()
                    .filter(|m| m.size == size)
                    .all(|m| first + count <= m.first || m.first + m.count <= *first)
            })
            .ok_or(unchanged(Error::Exhausted))?;
        for index in first..first + count {
            // SAFETY: an owned aperture table, a bounded slot.
            if unsafe { self.entry(size, index).map_err(unchanged)?.read_volatile() } != 0 {
                return Err(unchanged(Error::MappingFailed));
            }
        }
        mappings.push(Allocation {
            request,
            size,
            first,
            count,
        });
        for offset in 0..count {
            let physical = request.physical.start() + offset as u64 * size.bytes();
            // SAFETY: every slot was checked empty above.
            unsafe {
                self.entry(size, first + offset)
                    .expect("checked")
                    .write_volatile(Self::value(size, physical, request.protection))
            };
        }
        self.invalidate(size, first, count);
        Ok(InstalledMapping {
            token: request.id,
            cpu_base: NonNull::new(self.address(size, first) as *mut u8).expect("nonzero aperture"),
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(&self, request: MapRequest, mapping: InstalledMapping) -> Result<(), Error> {
        if crate::engine::host::in_interrupt() {
            return Err(Error::Unavailable);
        }
        self.check_context(request.address_space)?;
        let mut guard = self.lock();
        let mappings = guard.mappings();
        let at = mappings
            .iter()
            .position(|m| m.request == request)
            .ok_or(Error::UnmapFailed)?;
        let allocation = &mappings[at];
        let (size, first, count) = (allocation.size, allocation.first, allocation.count);
        if mapping.token != request.id
            || mapping.physical != request.physical
            || mapping.cpu_base.as_ptr() as u64 != self.address(size, first)
        {
            return Err(Error::UnmapFailed);
        }
        for offset in 0..count {
            let physical = request.physical.start() + offset as u64 * size.bytes();
            let expected = Self::value(size, physical, request.protection);
            if unsafe { self.entry(size, first + offset)?.read_volatile() } & !ACCESSED_DIRTY
                != expected
            {
                return Err(Error::UnmapFailed);
            }
        }
        for offset in 0..count {
            unsafe { self.entry(size, first + offset)?.write_volatile(0) };
        }
        self.invalidate(size, first, count);
        // A processor that did not acknowledge may still translate through
        // the slots, so they stay allocated and the mapping is refused.
        if !super::shootdown::retire(self.tsc_hz) {
            return Err(Error::Busy);
        }
        mappings.swap_remove(at);
        Ok(())
    }
}

/// A claimed ECAM bus: its MCFG window index and bus, the window, and the
/// reservation of the bus's configuration space.
struct Bus {
    at: (usize, u8),
    window: EcamWindow,
    resource: Resource,
}

/// The owned MMIO authority over the captured firmware description.
pub(crate) struct Source {
    platform: Arc<Platform>,
    authority: Authority,
    /// Each claimed ECAM bus, by its window and bus.
    buses: core::cell::RefCell<Vec<Bus>>,
}

impl Source {
    /// Activate the authority on the boot processor, after `host::install`
    /// and before the other host processors start; the TSC runs at `tsc_hz`.
    ///
    /// # Safety
    /// `wire` is this boot's sealed capture; `owner` is the boot processor's
    /// installed host; no firmware, SMM or other driver maps the aperture.
    pub(crate) unsafe fn activate(
        wire: &'static Wire,
        owner: &mut HostOwner,
        tsc_hz: u64,
    ) -> Result<Self, Error> {
        if !wire.valid() || !PROCESSORS.alone() {
            return Err(Error::Unavailable);
        }
        let (catalog, snapshot) = {
            let execution = owner.enter_root().map_err(failed)?;
            let context = execution.context();
            (
                context.roots().clone(),
                context.memory_snapshot().map_err(failed)?,
            )
        };
        let flush = aperture::qualify(&Controls {
            cr0: snapshot.cr0,
            cr3: snapshot.cr3,
            cr4: snapshot.cr4,
            efer: snapshot.efer,
            pat: snapshot.pat,
            levels: wire.levels,
        })
        .map_err(|refusal| {
            crate::output::arguments(format_args!(
                "NATIVE MMIO unavailable controls={refusal:?}\n"
            ));
            Error::UnsupportedCache
        })?;
        if !snapshot.pat_valid || !catalog.roots().contains(&wire.root) {
            return Err(Error::Unavailable);
        }
        let image = Image::from_snapshot(&snapshot).map_err(failed)?;
        let space = AddressSpace {
            identity: wire.root,
            physical_bits: image.physical_bits,
            virtual_bits: if wire.levels == 5 { 57 } else { 48 },
        };
        let shift = 12 + 9 * (wire.levels - 1);
        let slot = ((wire.virtual_base >> shift) & 511) as usize;
        // SAFETY: the loader root is an owned table page.
        let loader_entry = unsafe { owned_table(wire, wire.root)?.add(slot).read_volatile() };
        let platform = Arc::new(Platform {
            captured: Arc::new(Captured { wire }),
            space,
            flush,
            tsc_hz,
            loader_entry,
            slot,
            held: AtomicBool::new(false),
            mappings: UnsafeCell::new(Vec::new()),
        });
        let mut written = Vec::new();
        written.try_reserve_exact(LEAVES + 1).map_err(failed)?;
        written.extend_from_slice(&wire.leaves);
        written.push(wire.directory);
        for &table in &written {
            crate::native_memory::cache::verify_writeback(
                crate::layout::physical(table),
                table,
                PAGE as usize,
                crate::layout::physical(0),
            )
            .map_err(failed)?;
        }
        let aliases = aliases(wire, &catalog, &snapshot, space, &written)?;
        platform.check_context(space)?;
        for root in catalog.roots() {
            let mut table = *root;
            for level in (2..wire.levels).rev() {
                let slot = ((wire.virtual_base >> (12 + 9 * level)) & 511) as usize;
                // SAFETY: an owned table page.
                let entry = unsafe { owned_table(wire, table)?.add(slot).read_volatile() };
                if entry & (PRESENT | HUGE) != PRESENT {
                    return Err(Error::Unavailable);
                }
                table = entry & ADDRESS;
            }
            if table != wire.directory {
                return Err(Error::Unavailable);
            }
        }
        let directory = owned_table(wire, wire.directory)?;
        for (index, &leaf) in wire.leaves.iter().enumerate() {
            // SAFETY: the owned directory.
            let entry = unsafe { directory.add(index).read_volatile() };
            if entry & (PRESENT | WRITABLE | HUGE) != (PRESENT | WRITABLE)
                || entry & ADDRESS != leaf
            {
                return Err(Error::Unavailable);
            }
        }
        for size in [Size::Page, Size::Large] {
            for index in size.slots() {
                // SAFETY: the owned aperture tables.
                if unsafe { platform.entry(size, index)?.read_volatile() } != 0 {
                    return Err(Error::Unavailable);
                }
            }
        }
        // SAFETY: the inventory holds every root's and the guest RAM's
        // aliases; the leaf table is owned and shared by every root.
        let authority = unsafe { Authority::activate(platform.clone(), space, aliases) }?;
        Ok(Self {
            platform,
            authority,
            buses: core::cell::RefCell::new(Vec::new()),
        })
    }

    pub(crate) fn authority(&self) -> &Authority {
        &self.authority
    }

    fn reserve(&self, span: PhysicalSpan, kind: ResourceKind) -> Result<Resource, Error> {
        let resource = Resource::new(Box::new(Backing {
            owner: self.platform.captured.clone(),
            span,
            kind,
        }));
        self.authority.register_resource(resource.clone())?;
        Ok(resource)
    }

    /// The ECAM window and reservation of `bus` on `segment`, claimed once.
    ///
    /// # Safety
    /// The caller owns every function on that bus: its configuration space,
    /// resets and the drivers that reach it.
    pub(crate) unsafe fn claim_bus(
        &self,
        segment: u16,
        bus: u8,
    ) -> Result<(EcamWindow, Resource), Error> {
        let wire = self.platform.wire();
        let windows = stela_runtime::pc::acpi::mcfg(wire.mcfg()).map_err(failed)?;
        let index = windows
            .iter()
            .position(|window| {
                window.segment == segment && (window.start_bus..=window.end_bus).contains(&bus)
            })
            .ok_or(Error::OutsideResource)?;
        if let Some(claimed) = self
            .buses
            .borrow()
            .iter()
            .find(|claimed| claimed.at == (index, bus))
        {
            return Ok((claimed.window, claimed.resource.clone()));
        }
        let inventory =
            super::ecam::EcamInventory::validate(&windows, self.platform.space.physical_bits)?;
        let (window, span) = inventory.subset(index, bus..=bus, wire.roots())?;
        if !wire.excludes_memory(span.start(), span.end()) {
            return Err(Error::OutsideResource);
        }
        let resource = self.reserve(span, ResourceKind::Registers)?;
        self.buses.borrow_mut().push(Bus {
            at: (index, bus),
            window,
            resource: resource.clone(),
        });
        Ok((window, resource))
    }

    /// Reserve the memory BAR at bus address `address` for `bytes` on
    /// `segment`, when a root bridge window holds it and it is outside RAM.
    ///
    /// # Safety
    /// The caller owns the function that decodes it.
    pub(crate) unsafe fn claim_bar(
        &self,
        segment: u16,
        address: u64,
        bytes: u64,
        prefetchable: bool,
    ) -> Result<Resource, Error> {
        let wire = self.platform.wire();
        let windows = wire
            .roots()
            .iter()
            .filter(|root| root.space == 0)
            .map(|root| aperture::BusWindow {
                segment: root.segment,
                minimum: root.minimum,
                maximum: root.maximum,
                translation: root.translation,
            });
        let physical = aperture::bar_physical(windows, u32::from(segment), address, bytes)
            .ok_or(Error::OutsideResource)?;
        let span = PhysicalSpan::new(physical, bytes)?;
        if !span.start().is_multiple_of(PAGE) || !span.bytes().is_multiple_of(PAGE) {
            return Err(Error::InvalidRange);
        }
        if !wire.excludes_memory(span.start(), span.end()) {
            return Err(Error::OutsideResource);
        }
        self.reserve(
            span,
            if prefetchable {
                ResourceKind::PrefetchableMemory
            } else {
                ResourceKind::Registers
            },
        )
    }
}

impl Source {
    /// Map bus 0's first configuration page, read it, and retire the mapping
    /// after the other host processors started: the retirement's shootdown
    /// generation, which every processor acknowledged.
    ///
    /// # Safety
    /// The caller owns bus 0's configuration space.
    pub(crate) unsafe fn check_shootdown(&self) -> Result<u64, Error> {
        let windows = stela_runtime::pc::acpi::mcfg(self.platform.wire().mcfg()).map_err(failed)?;
        let window = windows.first().ok_or(Error::Unavailable)?;
        // SAFETY: forwarded from the caller.
        let (_, resource) = unsafe { self.claim_bus(window.segment, window.start_bus) }?;
        let mut mapping = self.authority.map(
            resource,
            0,
            PAGE as usize,
            CacheAttribute::Uncached,
            Protection::ReadOnly,
        )?;
        let identity = mapping.read32(0)?;
        let before = PROCESSORS.requested();
        // SAFETY: the read above was the mapping's only use.
        unsafe { mapping.retire() }?;
        let generation = PROCESSORS.requested();
        if identity == u32::MAX || generation == before || PROCESSORS.alone() {
            return Err(Error::InvalidPlatformReply);
        }
        Ok(generation)
    }

    /// Reserve the registers at `span`, which an ACPI device's `_CRS` names,
    /// when the final memory map leaves them outside RAM and they avoid the
    /// local APIC. The authority refuses a span that overlaps another
    /// reservation.
    ///
    /// # Safety
    /// The caller owns the device that decodes the span.
    pub(crate) unsafe fn claim_platform(&self, span: PhysicalSpan) -> Result<Resource, Error> {
        if !span.start().is_multiple_of(PAGE) || !span.bytes().is_multiple_of(PAGE) {
            return Err(Error::InvalidRange);
        }
        let apic = crate::apic::base_msr() & crate::apic::BASE_ADDRESS;
        if !self
            .platform
            .wire()
            .excludes_memory(span.start(), span.end())
            || (span.start() < apic + PAGE && apic < span.end())
        {
            return Err(Error::OutsideResource);
        }
        self.reserve(span, ResourceKind::Registers)
    }
}

fn in8(port: u16) -> u8 {
    let value: u8;
    // SAFETY: a port read; the caller owns the port.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}

fn out8(port: u16, value: u8) {
    // SAFETY: a port write; the caller owns the port.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    };
}

/// The I/O APIC's index and data registers, and its first redirection entry
/// (Intel 82093AA datasheet 3.1, 3.2.4).
const IOREGSEL: usize = 0;
const IOWIN: usize = 0x10;
const IOAPICVER: u32 = 1;
const REDIRECTION: u32 = 0x10;
const MASKED: u32 = 1 << 16;

impl Source {
    /// Mask ISA interrupts `irqs` at the 8259 PICs and at the I/O APIC pins
    /// the MADT routes them to.
    ///
    /// # Safety
    /// No other owner programs the PICs or those I/O APICs.
    pub(crate) unsafe fn mask_isa(&self, irqs: &[u8]) -> Result<(), Error> {
        for &irq in irqs {
            // OCW1, the interrupt mask register (Intel 8259A datasheet).
            let port = if irq < 8 { 0x21 } else { 0xa1 };
            out8(port, in8(port) | 1 << (irq & 7));
        }
        let wire = self.platform.wire();
        let routing =
            crate::native_irq::madt::Routing::parse(wire.madt(), self.platform.space.physical_bits)
                .map_err(failed)?;
        let lines = irqs
            .iter()
            .map(|&irq| routing.isa(irq).map(|line| line.gsi))
            .collect::<Result<Vec<_>, _>>()
            .map_err(failed)?;
        for unit in &routing.units {
            let page = unit.base & !(PAGE - 1);
            let offset = (unit.base - page) as usize;
            let span = PhysicalSpan::new(page, PAGE)?;
            if !wire.excludes_memory(span.start(), span.end()) {
                return Err(Error::OutsideResource);
            }
            let resource = self.reserve(span, ResourceKind::Registers)?;
            let mut mapping = self.authority.map(
                resource,
                0,
                PAGE as usize,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )?;
            let select = |index: u32| mapping.write32(offset + IOREGSEL, index);
            select(IOAPICVER)?;
            let pins = (mapping.read32(offset + IOWIN)? >> 16 & 0xff) + 1;
            for &gsi in &lines {
                let Some(pin) = gsi.checked_sub(unit.gsi_base).filter(|pin| *pin < pins) else {
                    continue;
                };
                select(REDIRECTION + 2 * pin)?;
                let low = mapping.read32(offset + IOWIN)?;
                mapping.write32(offset + IOWIN, low | MASKED)?;
            }
            // SAFETY: the mapping's only user is this loop, which is done.
            unsafe { mapping.retire() }?;
        }
        Ok(())
    }
}
