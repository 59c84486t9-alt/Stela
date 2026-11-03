use super::*;
mod hpet;
mod publication;
use crate::{
    engine::host::{MmioRoots, RootContext, RootExecution, RootProcessScope},
    native_smp::{memory_types::Image, topology::Snapshot},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    arch::asm,
    cell::UnsafeCell,
    marker::PhantomData,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};
pub(crate) use hpet::{ExclusiveHpet, HpetMapping};
#[cfg(feature = "diagnostics")]
pub(crate) use publication::{QualifiedRam, RootPublication};
use stela_drivers::bus::{
    mmio::owned::{
        AddressSpace, Authority, CacheAttribute, ExistingAlias, InstalledMapping, MapFailure,
        MapRequest, MappingPlatform, PhysicalSpan, Protection, Resource, ResourceBacking,
        ResourceKind,
    },
    pci::EcamWindow,
};

struct Resources {
    wire: &'static Wire,
    _roots: Arc<MmioRoots>,
}
struct Backing {
    owner: Arc<Resources>,
    span: PhysicalSpan,
}
// SAFETY: ScopedSource's concrete claim methods reserve only the
// MADT/MCFG resources after the explicit native device handoff. The original
// root assignment, final map exclusions and epoch remain pinned permanently.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }
}
struct Allocation {
    request: MapRequest,
    first: usize,
    pages: usize,
}
struct Platform {
    context: Arc<RootContext>,
    scope: AtomicPtr<RootProcessScope>,
    space: AddressSpace,
    snapshot: Snapshot,
    resources: Arc<Resources>,
    held: AtomicBool,
    ram_publisher: AtomicBool,
    mappings: UnsafeCell<Vec<Allocation>>,
}
// SAFETY: source/root metadata is immutable. Foreign CPUs fail the
// time-free RootContext check before touching the affine scope pointer. Mappings are accessed
// under held on the sole admitted CPU; scope publication/removal masks IRQs.
unsafe impl Send for Platform {}
// SAFETY: shared references rely on the same argument as `Send` above.
unsafe impl Sync for Platform {}

fn msr(index: u32) -> u64 {
    // SAFETY: only checked Intel architectural registers from observe's
    // CPUID-checked memory image are read by this module.
    unsafe { crate::cpu::msr::rdmsr(index) }
}
fn memory_register(index: u32) -> bool {
    index == 0xfe
        || index == 0x2ff
        || (0x200..=0x21f).contains(&index)
        || matches!(index, 0x250 | 0x258 | 0x259 | 0x268..=0x26f)
}
impl Platform {
    fn controls(&self) -> Result<(), Error> {
        let (cr0, cr3, cr4): (u64, u64, u64);
        // SAFETY: pure CPL0 observation after the CPU/root check.
        unsafe {
            asm!("mov {}, cr0",out(reg) cr0,options(nomem,nostack,preserves_flags));
            asm!("mov {}, cr3",out(reg) cr3,options(nomem,nostack,preserves_flags));
            asm!("mov {}, cr4",out(reg) cr4,options(nomem,nostack,preserves_flags));
        }
        if cr0 != self.snapshot.cr0
            || cr3 != self.snapshot.cr3
            || cr4 != self.snapshot.cr4
            || msr(crate::cpu::msr::EFER.index) != self.snapshot.efer
            || msr(crate::cpu::msr::PAT.index) != self.snapshot.pat
            || self.snapshot.msrs[..self.snapshot.msr_count as usize]
                .iter()
                .filter(|m| memory_register(m.index))
                .any(|m| msr(m.index) != m.value)
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn table(&self, physical: u64) -> Result<*mut u64, Error> {
        if !self.resources.wire.table_owned(physical) {
            return Err(Error::Unavailable);
        }
        Ok(crate::layout::physical(physical) as *mut u64)
    }
    fn leaf(&self, index: usize) -> Result<*mut u64, Error> {
        if index >= ENTRIES {
            return Err(Error::InvalidRange);
        }
        Ok(self.table(self.resources.wire.leaf)?.wrapping_add(index))
    }
    fn flush(&self, first: usize, pages: usize) {
        // SAFETY: The admitted processor has PGE and PCIDE clear. INVLPG removes the
        // current host translation; every other root reload flushes
        // before use, and all share these same aperture leaves.
        unsafe {
            asm!("mfence", options(nostack, preserves_flags));
            for index in first..first + pages {
                let address = self.resources.wire.virtual_base + index as u64 * PAGE;
                asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags));
            }
            asm!("mfence", options(nostack, preserves_flags));
        }
    }
    fn lock(&self) -> Result<Guard<'_>, Error> {
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        Ok(Guard(self))
    }
    fn resource(&self, resource: &Resource) -> bool {
        if let Some(backing) = resource.backing().downcast_ref::<Backing>() {
            return Arc::ptr_eq(&backing.owner, &self.resources)
                && backing.span == resource.physical_span();
        }
        stela_drivers::platform::acpi::resources::reservation_parent(resource)
            .is_some_and(|parent| self.resource(parent))
    }
    /// Bounded evidence from the original final map on claim refusal.
    /// This does not reinterpret a descriptor or change the exclusion predicate.
    fn report_memory_refusal(&self, name: &str, span: PhysicalSpan) {
        let memory = self.resources.wire.memory();
        crate::output::arguments(format_args!(
            "CHECK native-mmio RESOURCE REFUSED kind={name} span={:#x}..{:#x}\n",
            span.start(),
            span.end()
        ));
        let mut count = 0;
        for (index, entry) in memory.iter().enumerate() {
            if entry.start < span.end() && span.start() < entry.end {
                if count < 8 {
                    crate::output::arguments(format_args!(
                        "CHECK native-mmio MEMORY overlap index={index} span={:#x}..{:#x} type={} attributes={:#x}\n",
                        entry.start, entry.end, entry.kind, entry.attributes
                    ));
                }
                count += 1;
            }
        }
        crate::output::arguments(format_args!(
            "CHECK native-mmio MEMORY intersections={count} shown={}\n",
            count.min(8)
        ));
        for (position, entry) in [
            (
                "before",
                memory
                    .iter()
                    .filter(|entry| entry.end <= span.start())
                    .max_by_key(|entry| entry.end),
            ),
            (
                "after",
                memory
                    .iter()
                    .filter(|entry| entry.start >= span.end())
                    .min_by_key(|entry| entry.start),
            ),
        ] {
            if let Some(entry) = entry {
                crate::output::arguments(format_args!(
                    "CHECK native-mmio MEMORY neighbour={position} span={:#x}..{:#x} type={} attributes={:#x}\n",
                    entry.start, entry.end, entry.kind, entry.attributes
                ));
            }
        }
    }
}
struct Guard<'a>(&'a Platform);
impl Guard<'_> {
    fn mappings(&mut self) -> &mut Vec<Allocation> {
        // SAFETY: exclusive held acquisition, no callbacks while borrowed.
        unsafe { &mut *self.0.mappings.get() }
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

// SAFETY: map publishes only owned preallocated leaves after concrete source,
// root, aliases, PAT/MTRR and process-scope checks. The single-BSP
// profile and PCID/PGE refusal give a complete local TLB join; no SMP or WC
// completion is guessed. Every uncertainty keeps the allocation reserved.
unsafe impl MappingPlatform for Platform {
    fn check_context(&self, space: AddressSpace) -> Result<(), Error> {
        self.context.check_current().map_err(failed)?;
        if self.context.in_interrupt() || space != self.space {
            return Err(Error::Unavailable);
        }
        let scope = self.scope.load(Ordering::Acquire);
        if scope.is_null() {
            return Err(Error::Unavailable);
        }
        // SAFETY: same physical CPU checked BEFORE pointer load. Session owns
        // the exact Arc until IRQ-disabled removal; IRQ reentry refused above.
        unsafe { &*scope }.check().map_err(failed)?;
        self.controls()
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
            let physical = resource.physical_span();
            crate::output::arguments(format_args!(
                "CHECK native-mmio MAP RESOURCE REFUSED request={:#x}..{:#x} resource={:#x}..{:#x} kind={:?} original_backing={}\n",
                request.physical.start(),
                request.physical.end(),
                physical.start(),
                physical.end(),
                resource.kind(),
                resource.backing().is::<Backing>()
            ));
            return Err(unchanged(Error::OutsideResource));
        }
        let pages = usize::try_from(request.physical.bytes() / PAGE)
            .map_err(|_| unchanged(Error::InvalidRange))?;
        if pages == 0 || pages > ENTRIES {
            return Err(unchanged(Error::Exhausted));
        }
        let mut guard = self.lock().map_err(unchanged)?;
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
            // SAFETY: concrete kept LOADER_DATA page, bounded PT slot.
            if unsafe { self.leaf(index).map_err(unchanged)?.read_volatile() } != 0 {
                return Err(unchanged(Error::MappingFailed));
            }
        }
        let rights = PRESENT
            | NX
            | (1 << 3)
            | (1 << 4)
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
            // SAFETY: every leaf was preflighted; no fallible mutation remains.
            unsafe {
                self.leaf(first + offset)
                    .expect("preflighted")
                    .write_volatile((request.physical.start() + offset as u64 * PAGE) | rights)
            };
        }
        self.flush(first, pages);
        self.check_context(request.address_space)
            .map_err(MapFailure::Uncertain)?;
        Ok(InstalledMapping {
            token: request.id,
            cpu_base: NonNull::new(
                (self.resources.wire.virtual_base + first as u64 * PAGE) as *mut u8,
            )
            .expect("nonzero window"),
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(&self, request: MapRequest, mapping: InstalledMapping) -> Result<(), Error> {
        self.check_context(request.address_space)?;
        let mut guard = self.lock()?;
        let mappings = guard.mappings();
        let at = mappings
            .iter()
            .position(|m| m.request == request)
            .ok_or(Error::UnmapFailed)?;
        let allocation = &mappings[at];
        if mapping.token != request.id
            || mapping.physical != request.physical
            || mapping.attribute != request.attribute
            || mapping.protection != request.protection
            || mapping.cpu_base.as_ptr() as u64
                != self.resources.wire.virtual_base + allocation.first as u64 * PAGE
        {
            return Err(Error::UnmapFailed);
        }
        let rights = PRESENT
            | NX
            | (1 << 3)
            | (1 << 4)
            | if request.protection == Protection::ReadWrite {
                WRITABLE
            } else {
                0
            };
        for offset in 0..allocation.pages {
            let expected = (request.physical.start() + offset as u64 * PAGE) | rights;
            // A/D are hardware-owned. Every other bit must still be ours.
            // SAFETY: the guard serializes the owned leaf table, mapped by the firmware identity
            // map.
            if unsafe { self.leaf(allocation.first + offset)?.read_volatile() } & !0x60 != expected
            {
                return Err(Error::UnmapFailed);
            }
        }
        for offset in 0..allocation.pages {
            // SAFETY: the guard serializes the owned leaf table, and these entries belong to the
            // retiring allocation.
            unsafe { self.leaf(allocation.first + offset)?.write_volatile(0) };
        }
        self.flush(allocation.first, allocation.pages);
        self.check_context(request.address_space)?;
        mappings.swap_remove(at);
        Ok(())
    }
}

pub(crate) struct ScopedSource {
    platform: Arc<Platform>,
    authority: Authority,
}
/// Local process grant kept across every OriginalMapping/MappingView. A
/// failed retirement cannot let the dispatcher leave the root execution scope.
pub(crate) struct Session {
    source: Arc<Platform>,
    scope: Arc<RootProcessScope>,
    _local: PhantomData<*mut ()>,
}
impl Drop for Session {
    fn drop(&mut self) {
        if self.scope.check().is_err() {
            self.source
                .context
                .fatal(stela_drivers::platform::work::WorkError::CorruptContext);
        }
        let saved = self
            .source
            .context
            .save_disable()
            .unwrap_or_else(|e| self.source.context.fatal(e));
        let live = match self.source.lock() {
            Ok(mut guard) => {
                !guard.mappings().is_empty() || self.source.ram_publisher.load(Ordering::Acquire)
            }
            Err(_) => true,
        };
        if live {
            self.source
                .context
                .fatal(stela_drivers::platform::work::WorkError::Busy);
        }
        self.source.scope.store(ptr::null_mut(), Ordering::Release);
        // SAFETY: `saved` came from `save_disable` on this CPU above.
        unsafe { self.source.context.restore(saved) };
    }
}
impl ScopedSource {
    /// # Safety
    /// Post-EBS dispatcher on its single admitted processor. `wire` is
    /// the sealed capture kept by this handoff; execution owns the
    /// HostOwner canonical fixed root catalog. Firmware/SMM and native device ownership are
    /// transferred separately by the typed claim methods below. No guest or
    /// outside root/cache publisher runs concurrently with this scope.
    pub(crate) unsafe fn activate(
        wire: &'static Wire,
        execution: &RootExecution,
    ) -> Result<(Self, Session), Error> {
        if !wire.valid() {
            return Err(Error::Unavailable);
        }
        let scope = execution.process_scope().map_err(failed)?;
        let context = scope.context().clone();
        let roots = context.roots().clone();
        let snapshot = context.memory_snapshot().map_err(failed)?;
        if !roots.roots().contains(&wire.root) {
            return Err(Error::Unavailable);
        }
        let vendor = snapshot.get(0, 0).ok_or(Error::Unavailable)?;
        if [vendor.ebx, vendor.edx, vendor.ecx] != [0x756e_6547, 0x4965_6e69, 0x6c65_746e]
            || !snapshot.pat_valid
            || snapshot.pat as u8 != 6
            || snapshot.pat >> 24 & 0xff != 0
            || snapshot.cr0 & (1 << 16) == 0
            || snapshot.cr4 & ((1 << 7) | (1 << 17)) != 0
            || snapshot.cr3 & !ADDRESS != 0
            || snapshot.cr4 & (1 << 12) != if wire.levels == 5 { 1 << 12 } else { 0 }
            || snapshot.efer & (1 << 11) == 0
        {
            return Err(Error::UnsupportedCache);
        }
        let image = Image::from_snapshot(&snapshot).map_err(failed)?;
        let space = AddressSpace {
            identity: wire.root,
            physical_bits: image.physical_bits,
            virtual_bits: if wire.levels == 5 { 57 } else { 48 },
        };
        let resources = Arc::new(Resources {
            wire,
            _roots: roots,
        });
        let platform = Arc::new(Platform {
            context,
            scope: AtomicPtr::new(Arc::as_ptr(&scope).cast_mut()),
            space,
            snapshot,
            resources,
            held: AtomicBool::new(false),
            ram_publisher: AtomicBool::new(false),
            mappings: UnsafeCell::new(Vec::new()),
        });
        platform.check_context(space)?;
        crate::native_memory::cache::verify_writeback(
            crate::layout::physical(wire.leaf),
            wire.leaf,
            PAGE as usize,
            crate::layout::physical(0),
        )
        .map_err(failed)?;
        let aliases = inventory(&platform, None)?;
        for index in 0..ENTRIES {
            // SAFETY: `leaf` checks the index against the owned leaf table, which the firmware
            // identity map covers.
            if unsafe { platform.leaf(index)?.read_volatile() } != 0 {
                return Err(Error::Unavailable);
            }
        }
        // SAFETY: complete root-set/UEFI RAM aliases were inventoried;
        // the dedicated leaf table is owned and shared by each root.
        let authority = unsafe { Authority::activate(platform.clone(), space, aliases) }?;
        let session = Session {
            source: platform.clone(),
            scope,
            _local: PhantomData,
        };
        Ok((
            Self {
                platform,
                authority,
            },
            session,
        ))
    }
    pub(crate) fn authority(&self) -> &Authority {
        &self.authority
    }
    /// Re-enter the same root epoch after all earlier mappings retired.
    /// Future guest shadow aliases remain confined to the imported real RAM.
    pub(crate) fn enter(&self, execution: &RootExecution) -> Result<Session, Error> {
        self.platform.context.check_current().map_err(failed)?;
        self.platform.controls()?;
        let scope = execution.process_scope().map_err(failed)?;
        let context = scope.context();
        if !Arc::ptr_eq(context, &self.platform.context) {
            return Err(Error::Unavailable);
        }
        let saved = context.save_disable().map_err(failed)?;
        let published = self.platform.scope.compare_exchange(
            ptr::null_mut(),
            Arc::as_ptr(&scope).cast_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        // SAFETY: `saved` came from `save_disable` on this CPU above.
        unsafe { context.restore(saved) };
        published.map_err(|_| Error::Busy)?;
        Ok(Session {
            source: self.platform.clone(),
            scope,
            _local: PhantomData,
        })
    }
    /// Inspect the aperture after complete consumer retirement.
    pub(crate) fn verify_empty(&self) -> Result<(), Error> {
        self.platform.check_context(self.platform.space)?;
        let mut guard = self.platform.lock()?;
        if !guard.mappings().is_empty() {
            return Err(Error::Busy);
        }
        for index in 0..ENTRIES {
            // SAFETY: `leaf` checks the index against the owned leaf table, which the firmware
            // identity map covers.
            if unsafe { self.platform.leaf(index)?.read_volatile() } != 0 {
                return Err(Error::UnmapFailed);
            }
        }
        Ok(())
    }
    pub(crate) fn madt(&self) -> &'static [u8] {
        self.platform.resources.wire.madt()
    }
    /// # Safety
    /// Native dispatcher owns every MADT IOAPIC selector/window for
    /// this epoch, excluding firmware/SMM/other drivers and CPUs.
    /// This is a controller handoff, independent from any IRQ pin/sharer grant.
    pub(crate) unsafe fn claim_ioapics(&self) -> Result<usize, Error> {
        self.platform.check_context(self.platform.space)?;
        let routing =
            crate::native_irq::madt::Routing::parse(self.madt(), self.platform.space.physical_bits)
                .map_err(failed)?;
        if routing.units.is_empty() {
            return Err(Error::Unavailable);
        }
        let count = routing.units.len();
        for unit in routing.units {
            let span = PhysicalSpan::new(unit.base, PAGE)?;
            if !self
                .platform
                .resources
                .wire
                .excludes_memory(span.start(), span.end())
            {
                self.platform.report_memory_refusal("ioapic", span);
                return Err(Error::OutsideResource);
            }
            self.authority
                .register_resource(Resource::new(Box::new(Backing {
                    owner: self.platform.resources.clone(),
                    span,
                })))
                .map_err(|refusal| refusal.error)?;
        }
        Ok(count)
    }
    /// # Safety
    /// Dispatcher exclusively owns this complete requested original
    /// ECAM bus subset, including every function/config/reset access and native
    /// root epoch. This is distinct from the captured resource permission below.
    pub(crate) unsafe fn claim_ecam(
        &self,
        index: usize,
        buses: core::ops::RangeInclusive<u8>,
    ) -> Result<(EcamWindow, Resource), Error> {
        self.platform.check_context(self.platform.space)?;
        let wire = self.platform.resources.wire;
        let windows = stela_runtime::pc::acpi::mcfg(wire.mcfg()).map_err(failed)?;
        let table = wire.mcfg();
        if table[36..44].iter().any(|byte| *byte != 0)
            || table[44..]
                .as_chunks::<16>()
                .0
                .iter()
                .any(|entry| entry[12..16].iter().any(|byte| *byte != 0))
        {
            return Err(Error::Unavailable);
        }
        // Validate every complete original window before selecting a subset;
        // a small request cannot hide physical or same-segment bus overlap.
        let inventory =
            super::ecam::EcamInventory::validate(&windows, self.platform.space.physical_bits)?;
        let (first, last) = (*buses.start(), *buses.end());
        let (window, span) = inventory.subset(index, buses, wire.roots()).inspect_err(|error| {
            crate::output::arguments(format_args!(
                "CHECK native-mmio ECAM SUBSET REFUSED index={index} requested_buses={first}..={last} original_windows={} error={error:?}\n",
                windows.len()
            ));
            if let Some(original) = windows.get(index) {
                crate::output::arguments(format_args!(
                    "CHECK native-mmio ECAM ORIGINAL segment={} buses={}..={} base={:#x}\n",
                    original.segment, original.start_bus, original.end_bus, original.base
                ));
            }
            let mut count = 0;
            for (index, root) in wire.roots().iter().enumerate() {
                if root.space == 2 {
                    if count < 8 {
                        crate::output::arguments(format_args!(
                            "CHECK native-mmio ROOT bus index={index} bridge={} segment={} flags={:#x} specific={:#x} minimum={:#x} maximum={:#x} translation={:#x} length={:#x}\n",
                            root.bridge, root.segment, root.flags, root.specific, root.minimum,
                            root.maximum, root.translation, root.length
                        ));
                    }
                    count += 1;
                }
            }
            crate::output::arguments(format_args!(
                "CHECK native-mmio ROOT bus_records={count} shown={}\n",
                count.min(8)
            ));
        })?;
        if !wire.excludes_memory(span.start(), span.end()) {
            self.platform.report_memory_refusal("ecam", span);
            return Err(Error::OutsideResource);
        }
        let resource = Resource::new(Box::new(Backing {
            owner: self.platform.resources.clone(),
            span,
        }));
        self.authority
            .register_resource(resource.clone())
            .map_err(|refusal| refusal.error)?;
        Ok((window, resource))
    }
}

fn inventory(platform: &Platform, write_table: Option<u64>) -> Result<Vec<ExistingAlias>, Error> {
    let wire = platform.resources.wire;
    let written = [Some(wire.leaf), write_table];
    let aliases = aliases(
        wire,
        &platform.resources._roots,
        &platform.snapshot,
        platform.space,
        &written.iter().flatten().copied().collect::<Vec<_>>(),
    )?;
    platform.check_context(platform.space)?;
    Ok(aliases)
}

/// A table page the loader owns, through the physmap.
pub(super) fn owned_table(wire: &Wire, physical: u64) -> Result<*mut u64, Error> {
    if !wire.table_owned(physical) {
        return Err(Error::Unavailable);
    }
    Ok(crate::layout::physical(physical) as *mut u64)
}

/// Every existing alias the roots and the guest's RAM hold, with
/// its cache policy where the roots fix one, after checking each root leads
/// to the aperture's leaf table. `written` are the table pages the caller
/// writes, whose aliases must be write-back.
pub(super) fn aliases(
    wire: &Wire,
    catalog: &MmioRoots,
    snapshot: &Snapshot,
    space: AddressSpace,
    written: &[u64],
) -> Result<Vec<ExistingAlias>, Error> {
    let roots = catalog.roots();
    if !roots.contains(&(snapshot.cr3 & ADDRESS)) {
        return Err(Error::Unavailable);
    }
    let mut visited = Vec::new();
    let mut aliases = Vec::new();
    let image = Image::from_snapshot(snapshot).map_err(failed)?;
    struct Walk<'a> {
        wire: &'a Wire,
        snapshot: &'a Snapshot,
        space: AddressSpace,
        image: Image,
        written: &'a [u64],
    }
    fn walk(
        p: &Walk<'_>,
        table: u64,
        level: u32,
        visited: &mut Vec<(u64, u32)>,
        aliases: &mut Vec<ExistingAlias>,
    ) -> Result<(), Error> {
        if visited.contains(&(table, level)) {
            return Ok(());
        }
        if visited.len() >= 65536 {
            return Err(Error::Exhausted);
        }
        visited.try_reserve(1).map_err(failed)?;
        visited.push((table, level));
        p.image.writeback_ram(table, PAGE).map_err(failed)?;
        let address = owned_table(p.wire, table)?;
        for index in 0..ENTRIES {
            // SAFETY: `owned_table` admitted this table page and `index` is below `ENTRIES`.
            let entry = unsafe { address.add(index).read_volatile() };
            if entry & PRESENT == 0 {
                continue;
            }
            if level == 0 || entry & HUGE != 0 {
                if level > 2
                    || (level != 0
                        && entry & ADDRESS & ((1u64 << (12 + 9 * level)) - 1) & !(1 << 12) != 0)
                {
                    return Err(Error::Unavailable);
                }
                let bytes = 1u64 << (12 + 9 * level);
                let physical = entry & ADDRESS & !(bytes - 1);
                if physical
                    .checked_add(bytes)
                    .is_none_or(|end| end > 1u64 << p.space.physical_bits)
                {
                    return Err(Error::InvalidRange);
                }
                let pat_index =
                    (entry >> 3 & 3) | ((entry >> if level == 0 { 7 } else { 12 }) & 1) << 2;
                // The adapter writes these table pages. Every data alias of
                // them must agree with their proven WB CPU access and WB
                // page-walker fetch policy; UC/WC/WT/unknown aliases refuse.
                if p.written
                    .iter()
                    .any(|&table| physical < table + PAGE && table < physical + bytes)
                    && (p.snapshot.pat >> (8 * pat_index)) & 0xff != 6
                {
                    return Err(Error::CacheConflict);
                }
                let attribute = if (p.snapshot.pat >> (8 * pat_index)) & 0xff == 0 {
                    Some(CacheAttribute::Uncached)
                } else {
                    None
                };
                aliases.try_reserve(1).map_err(failed)?;
                aliases.push(ExistingAlias {
                    physical: PhysicalSpan::new(physical, bytes)?,
                    attribute,
                });
            } else {
                if entry & ((1 << 3) | (1 << 4)) != 0 {
                    return Err(Error::UnsupportedCache);
                }
                walk(p, entry & ADDRESS, level - 1, visited, aliases)?;
            }
        }
        Ok(())
    }
    let walker = Walk {
        wire,
        snapshot,
        space,
        image,
        written,
    };
    // Every real root is scanned; shared table pages are visited once. Future
    // guest aliases are restricted by HostOwner to its RAM inventory,
    // conservatively imported below with unknown policy (blocks device reuse).
    for root in roots {
        walk(&walker, *root, wire.levels - 1, &mut visited, &mut aliases)?;
    }
    for physical in catalog.ram() {
        aliases.try_reserve(1).map_err(failed)?;
        aliases.push(ExistingAlias {
            physical: *physical,
            attribute: None,
        });
    }
    for root in roots {
        let mut table = *root;
        for level in (1..wire.levels).rev() {
            let slot = ((wire.virtual_base >> (12 + 9 * level)) & 511) as usize;
            // SAFETY: `owned_table` admitted this table page and `slot` is below 512.
            let entry = unsafe { owned_table(wire, table)?.add(slot).read_volatile() };
            if entry & (PRESENT | WRITABLE | HUGE) != (PRESENT | WRITABLE) {
                return Err(Error::Unavailable);
            }
            table = entry & ADDRESS;
        }
        if table != wire.leaf {
            return Err(Error::Unavailable);
        }
    }
    Ok(aliases)
}
