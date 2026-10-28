//! The mount's native MMIO source: owned uncached mappings in the
//! loader-built aperture, valid on every host processor and in every root
//! that shares the loader's window, which is every root the engine builds.
//!
//! The controls the leaves need are checked once on the boot processor
//! (`stela_boot_core::aperture::qualify`); the other host processors run
//! with the same PAT, which their bootstrap programs from the boot
//! processor's. An access checks only that the current root reaches the
//! aperture and that no interrupt handler is running. Installations are
//! serialized by the platform's lock and need no remote flush; once the other
//! processors start, retirement refuses ([`aperture::Processors`]).
use super::platform::{aliases, owned_table};
use super::*;
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

struct Allocation {
    request: MapRequest,
    first: usize,
    pages: usize,
}

struct Platform {
    captured: Arc<Captured>,
    space: AddressSpace,
    flush: Flush,
    /// The loader root's top-level entry for the aperture, and its slot.
    loader_entry: u64,
    slot: usize,
    held: AtomicBool,
    mappings: UnsafeCell<Vec<Allocation>>,
}
// SAFETY: the metadata is immutable; `mappings` is reached only under `held`.
unsafe impl Send for Platform {}
unsafe impl Sync for Platform {}

const RIGHTS: u64 = PRESENT | NX | (1 << 3) | (1 << 4);

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
    fn leaf(&self, index: usize) -> Result<*mut u64, Error> {
        if index >= ENTRIES {
            return Err(Error::InvalidRange);
        }
        Ok(owned_table(self.wire(), self.wire().leaf)?.wrapping_add(index))
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
    fn invalidate(&self, first: usize, pages: usize) {
        // SAFETY: TLB maintenance only; CR4 is restored to its value.
        unsafe {
            asm!("mfence", options(nostack, preserves_flags));
            match self.flush {
                Flush::Pages => {
                    for index in first..first + pages {
                        let address = self.wire().virtual_base + index as u64 * PAGE;
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
        if space != self.space || crate::engine::host::in_interrupt() {
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
        self.check_context(request.address_space)
            .map_err(unchanged)?;
        if request.attribute != CacheAttribute::Uncached {
            return Err(unchanged(Error::UnsupportedCache));
        }
        if !self.resource(resource) {
            return Err(unchanged(Error::OutsideResource));
        }
        let pages = usize::try_from(request.physical.bytes() / PAGE)
            .map_err(|_| unchanged(Error::InvalidRange))?;
        if pages == 0 || pages > ENTRIES {
            return Err(unchanged(Error::Exhausted));
        }
        let mut guard = self.lock();
        let mappings = guard.mappings();
        mappings
            .try_reserve(1)
            .map_err(|_| unchanged(Error::Exhausted))?;
        let first = (0..=ENTRIES - pages)
            .find(|first| {
                mappings
                    .iter()
                    .all(|m| first + pages <= m.first || m.first + m.pages <= *first)
            })
            .ok_or(unchanged(Error::Exhausted))?;
        for index in first..first + pages {
            // SAFETY: the owned leaf table, a bounded slot.
            if unsafe { self.leaf(index).map_err(unchanged)?.read_volatile() } != 0 {
                return Err(unchanged(Error::MappingFailed));
            }
        }
        let rights = RIGHTS
            | if request.protection == Protection::ReadWrite {
                WRITABLE
            } else {
                0
            };
        mappings.push(Allocation {
            request,
            first,
            pages,
        });
        for offset in 0..pages {
            // SAFETY: every slot was checked empty above.
            unsafe {
                self.leaf(first + offset)
                    .expect("checked")
                    .write_volatile((request.physical.start() + offset as u64 * PAGE) | rights)
            };
        }
        self.invalidate(first, pages);
        Ok(InstalledMapping {
            token: request.id,
            cpu_base: NonNull::new((self.wire().virtual_base + first as u64 * PAGE) as *mut u8)
                .expect("nonzero aperture"),
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(&self, request: MapRequest, mapping: InstalledMapping) -> Result<(), Error> {
        self.check_context(request.address_space)?;
        if !PROCESSORS.may_retire() {
            return Err(Error::Busy);
        }
        let mut guard = self.lock();
        let mappings = guard.mappings();
        let at = mappings
            .iter()
            .position(|m| m.request == request)
            .ok_or(Error::UnmapFailed)?;
        let allocation = &mappings[at];
        if mapping.token != request.id
            || mapping.physical != request.physical
            || mapping.cpu_base.as_ptr() as u64
                != self.wire().virtual_base + allocation.first as u64 * PAGE
        {
            return Err(Error::UnmapFailed);
        }
        let rights = RIGHTS
            | if request.protection == Protection::ReadWrite {
                WRITABLE
            } else {
                0
            };
        for offset in 0..allocation.pages {
            let expected = (request.physical.start() + offset as u64 * PAGE) | rights;
            // Accessed and dirty belong to the processor.
            if unsafe { self.leaf(allocation.first + offset)?.read_volatile() } & !0x60 != expected
            {
                return Err(Error::UnmapFailed);
            }
        }
        for offset in 0..allocation.pages {
            unsafe { self.leaf(allocation.first + offset)?.write_volatile(0) };
        }
        self.invalidate(allocation.first, allocation.pages);
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
    /// and before the other host processors start.
    ///
    /// # Safety
    /// `wire` is this boot's sealed capture; `owner` is the boot processor's
    /// installed host; no firmware, SMM or other driver maps the aperture.
    pub(crate) unsafe fn activate(
        wire: &'static Wire,
        owner: &mut HostOwner,
    ) -> Result<Self, Error> {
        if !wire.valid() || !PROCESSORS.may_retire() {
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
            loader_entry,
            slot,
            held: AtomicBool::new(false),
            mappings: UnsafeCell::new(Vec::new()),
        });
        crate::native_memory::cache::verify_writeback(
            crate::layout::physical(wire.leaf),
            wire.leaf,
            PAGE as usize,
            crate::layout::physical(0),
        )
        .map_err(failed)?;
        let aliases = aliases(wire, &catalog, &snapshot, space, None)?;
        platform.check_context(space)?;
        for index in 0..ENTRIES {
            // SAFETY: the owned leaf table.
            if unsafe { platform.leaf(index)?.read_volatile() } != 0 {
                return Err(Error::Unavailable);
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
