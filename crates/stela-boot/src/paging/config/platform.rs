//! Actual standalone mapping publication under retained allocated page tables.
use super::*;
use crate::native_smp::{memory_types::Image, topology::Snapshot};
use core::{
    arch::asm,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64},
};
use owned::{ExistingAlias, InstalledMapping, MapFailure, MapRequest, MappingPlatform};

pub(super) struct Platform {
    pub(super) space: AddressSpace,
    root: Arc<super::super::active::RetainedRoot>,
    prepared: Prepared,
    snapshot: Snapshot,
    leaves: [u64; LEAVES],
    tokens: Box<[AtomicU64]>,
    held: AtomicBool,
}
struct Critical<'a> {
    platform: &'a Platform,
    flags: u64,
}
impl Drop for Critical<'_> {
    fn drop(&mut self) {
        self.platform.held.store(false, Ordering::Release);
        // SAFETY: same non-migrating admitted BSP; restore exact incoming IF.
        if self.flags & (1 << 9) != 0 {
            unsafe {
                asm!("sti", options(nomem, nostack));
            }
        }
    }
}
impl Platform {
    pub(super) fn new(
        root: Arc<super::super::active::RetainedRoot>,
        mut prepared: Prepared,
    ) -> Result<Self, Error> {
        root.check_current().map_err(Error::Root)?;
        let leaves = prepared.leaves.take().ok_or(Error::ResourceInventory)?;
        // SAFETY: actual retained CPL0 BSP/current root; no guest/AP runs.
        let snapshot = unsafe { crate::native_smp::firmware::observe() }
            .map_err(|_| Error::ResourceInventory)?;
        let image = Image::from_snapshot(&snapshot).map_err(Error::Tables)?;
        let space = AddressSpace {
            identity: snapshot.cr3,
            physical_bits: prepared.physical_bits,
            virtual_bits: 48,
        };
        if snapshot.cr4 & ((1 << 12) | (1 << 17) | (1 << 7)) != 0
            || snapshot.pat >> (3 * 8) & 0xff != 0
        {
            return Err(Error::ResourceInventory);
        }
        for leaf in leaves {
            if !root.tables.pages.iter().any(|page| page.physical == leaf) {
                return Err(Error::ResourceInventory);
            }
            image
                .writeback_ram(leaf, PAGE as u64)
                .map_err(Error::Tables)?;
            for index in 0..512 {
                if root.tables.read_owned(leaf, index) != Some(0) {
                    return Err(Error::ResourceConflict);
                }
            }
        }
        let mut tokens = Vec::new();
        tokens
            .try_reserve_exact(SLOTS)
            .map_err(|_| Error::Allocation)?;
        tokens.extend((0..SLOTS).map(|_| AtomicU64::new(0)));
        Ok(Self {
            space,
            root,
            prepared,
            snapshot,
            leaves,
            tokens: tokens.into_boxed_slice(),
            held: AtomicBool::new(false),
        })
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.root.check_current().map_err(Error::Root)?;
        if IRQ_DEPTH.load(Ordering::Acquire) != 0 {
            return Err(Error::Mapping(owned::Error::Unavailable));
        }
        for register in &self.snapshot.msrs[..self.snapshot.msr_count as usize] {
            if register.index == 0xfe
                || register.index == 0x2ff
                || (0x200..=0x21f).contains(&register.index)
                || matches!(
                    register.index,
                    0x250 | 0x258 | 0x259 | 0x268..=0x26f | 0xc001_0010 | 0xc001_001a | 0xc001_001d
                )
            {
                // SAFETY: observe captured this exact architectural/vendor
                // register on this same CPU; no unsupported probe is invented.
                if unsafe { crate::cpu::msr::rdmsr(register.index) } != register.value {
                    return Err(Error::ResourceInventory);
                }
            }
        }
        Ok(())
    }
    pub(super) fn check_bus(&self, address: Address) -> Result<(), Error> {
        self.check()?;
        let inventory = stela_boot_core::ecam::EcamInventory::validate(
            &self.prepared.windows,
            self.prepared.physical_bits,
        )
        .map_err(Error::Mapping)?;
        let index = self
            .prepared
            .windows
            .iter()
            .position(|window| {
                window.segment == address.segment
                    && (window.start_bus..=window.end_bus).contains(&address.bus)
            })
            .ok_or(Error::ResourceInventory)?;
        inventory
            .subset(index, address.bus..=address.bus, &self.prepared.roots)
            .map_err(Error::Mapping)?;
        Ok(())
    }
    pub(super) fn verify_empty(&self) -> Result<(), Error> {
        self.check()?;
        let _critical = self.critical().map_err(Error::Mapping)?;
        for slot in 0..SLOTS {
            // SAFETY: actual privately owned leaf, bounded slot, IRQ excluded;
            // this checks hardware table storage, not just registry metadata.
            if self.tokens[slot].load(Ordering::Acquire) != 0
                || unsafe { self.leaf(slot).read_volatile() } != 0
            {
                return Err(Error::Mapping(owned::Error::UnmapFailed));
            }
        }
        Ok(())
    }
    pub(super) fn identity_device(&self, span: PhysicalSpan) -> Result<(), Error> {
        self.check()?;
        self.prepared.device_range(span.start(), span.end())?;
        for physical in (span.start()..span.end()).step_by(PAGE) {
            let leaf = self
                .root
                .tables
                .observe(physical)
                .map_err(RootError::Traversal)
                .map_err(Error::Root)?
                .ok_or(Error::ResourceInventory)?;
            if leaf.physical != physical
                || !leaf.writable
                || leaf.user
                || !leaf.nx
                || (self.snapshot.pat >> (8 * leaf.pat_index)) & 0xff != 0
            {
                return Err(Error::ResourceConflict);
            }
        }
        Ok(())
    }
    fn critical(&self) -> Result<Critical<'_>, owned::Error> {
        self.check().map_err(|_| owned::Error::Unavailable)?;
        let flags: u64;
        // SAFETY: actual CPL0 checked CPU, excluding same-BSP IRQ reentry
        // before taking the only mutation flag. No sleeping lock or callback.
        unsafe {
            asm!("pushfq","pop {}","cli",out(reg)flags);
        }
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            if flags & (1 << 9) != 0 {
                unsafe {
                    asm!("sti", options(nomem, nostack));
                }
            }
            return Err(owned::Error::Busy);
        }
        Ok(Critical {
            platform: self,
            flags,
        })
    }
    fn leaf(&self, slot: usize) -> *mut u64 {
        // Called only with bounded slot under Critical; leaves were consumed
        // from this exact builder and remain genuine retained WB allocations.
        (self.leaves[slot / 512] as *mut u64).wrapping_add(slot % 512)
    }
    fn flush(&self, first: usize, pages: usize) {
        // SAFETY: actual sole current root, PGE/PCID disabled and no AP/guest;
        // all publications/removals hold this same IRQ-excluded mutation lease.
        unsafe {
            asm!("mfence", options(nostack, preserves_flags));
            for slot in first..first + pages {
                asm!("invlpg [{}]",in(reg) (APERTURE+slot*PAGE),options(nostack,preserves_flags));
            }
            asm!("mfence", options(nostack, preserves_flags));
        }
    }
    pub(super) fn aliases(&self) -> Result<Vec<ExistingAlias>, Error> {
        self.check()?;
        let _critical = self.critical().map_err(Error::Mapping)?;
        let image = Image::from_snapshot(&self.snapshot).map_err(Error::Tables)?;
        let mut aliases = Vec::new();
        let mut visited = Vec::new();
        self.walk(
            self.snapshot.cr3 & super::super::ADDRESS,
            3,
            &image,
            &mut visited,
            &mut aliases,
        )?;
        Ok(aliases)
    }
    fn walk(
        &self,
        table: u64,
        level: u32,
        image: &Image,
        visited: &mut Vec<(u64, u32)>,
        aliases: &mut Vec<ExistingAlias>,
    ) -> Result<(), Error> {
        if visited.contains(&(table, level)) {
            return Ok(());
        }
        if !self
            .root
            .tables
            .pages
            .iter()
            .any(|page| page.physical == table)
        {
            return Err(Error::ResourceInventory);
        }
        visited.try_reserve(1).map_err(|_| Error::Allocation)?;
        visited.push((table, level));
        image
            .writeback_ram(table, PAGE as u64)
            .map_err(Error::Tables)?;
        for index in 0..512 {
            let entry = self
                .root
                .tables
                .read_owned(table, index)
                .ok_or(Error::ResourceInventory)?;
            if entry & 1 == 0 {
                continue;
            }
            if level == 0 || entry & (1 << 7) != 0 {
                if level > 2 {
                    return Err(Error::ResourceInventory);
                }
                let bytes = 1u64 << (12 + 9 * level);
                let physical = entry & super::super::ADDRESS & !(bytes - 1);
                let pat = (entry >> 3 & 3) | ((entry >> if level == 0 { 7 } else { 12 }) & 1) << 2;
                let kind = (self.snapshot.pat >> (8 * pat)) & 0xff;
                for leaf in self.leaves {
                    if physical < leaf + PAGE as u64 && leaf < physical + bytes && kind != 6 {
                        return Err(Error::ResourceConflict);
                    }
                }
                aliases.try_reserve(1).map_err(|_| Error::Allocation)?;
                aliases.push(ExistingAlias {
                    physical: PhysicalSpan::new(physical, bytes).map_err(Error::Mapping)?,
                    attribute: if kind == 0 {
                        Some(CacheAttribute::Uncached)
                    } else {
                        None
                    },
                });
            } else {
                if entry & ((1 << 3) | (1 << 4)) != 0 {
                    return Err(Error::ResourceInventory);
                }
                self.walk(
                    entry & super::super::ADDRESS,
                    level - 1,
                    image,
                    visited,
                    aliases,
                )?;
            }
        }
        Ok(())
    }
}
fn rights(request: MapRequest) -> u64 {
    super::super::PRESENT
        | super::super::NX
        | (1 << 3)
        | (1 << 4)
        | if request.protection == Protection::ReadWrite {
            2
        } else {
            0
        }
}
// SAFETY: this provider retains the actual consumed builder/allocation catalog,
// one fixed single-BSP root, all aliases and empty private aperture leaves.
// IRQ exclusion precedes mutation; unknown contexts/cache/owners refuse. Tokens
// and allocations survive every uncertain failure. No other root is admitted.
unsafe impl MappingPlatform for Platform {
    fn check_context(&self, space: AddressSpace) -> Result<(), owned::Error> {
        if space != self.space {
            return Err(owned::Error::Unavailable);
        }
        self.check().map_err(|_| owned::Error::Unavailable)
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        let unchanged = MapFailure::Unchanged;
        self.check_context(request.address_space)
            .map_err(unchanged)?;
        let backing = resource
            .backing()
            .downcast_ref::<Backing>()
            .ok_or(unchanged(owned::Error::OutsideResource))?;
        if !core::ptr::eq(self, backing.platform.as_ref())
            || backing.span != resource.physical_span()
        {
            return Err(unchanged(owned::Error::OutsideResource));
        }
        if request.attribute != CacheAttribute::Uncached {
            return Err(unchanged(owned::Error::UnsupportedCache));
        }
        self.prepared
            .device_range(request.physical.start(), request.physical.end())
            .map_err(|_| unchanged(owned::Error::OutsideResource))?;
        let pages = usize::try_from(request.physical.bytes() / PAGE as u64)
            .map_err(|_| unchanged(owned::Error::InvalidRange))?;
        if pages == 0 || pages > SLOTS {
            return Err(unchanged(owned::Error::Exhausted));
        }
        let _critical = self.critical().map_err(unchanged)?;
        let first = (0..=SLOTS - pages)
            .find(|first| {
                self.tokens[*first..*first + pages]
                    .iter()
                    .all(|slot| slot.load(Ordering::Acquire) == 0)
            })
            .ok_or(unchanged(owned::Error::Exhausted))?;
        for slot in first..first + pages {
            if unsafe { self.leaf(slot).read_volatile() } != 0 {
                return Err(unchanged(owned::Error::MappingFailed));
            }
        }
        for offset in 0..pages {
            self.tokens[first + offset].store(request.id, Ordering::Release);
            // SAFETY: bounded empty actual owned PTE under exclusive IRQ lease;
            // no Rust reference aliases hardware A/D writes.
            unsafe {
                self.leaf(first + offset).write_volatile(
                    (request.physical.start() + offset as u64 * PAGE as u64) | rights(request),
                );
            }
        }
        self.flush(first, pages);
        self.check_context(request.address_space)
            .map_err(MapFailure::Uncertain)?;
        Ok(InstalledMapping {
            token: request.id,
            cpu_base: NonNull::new((APERTURE + first * PAGE) as *mut u8)
                .expect("canonical high window"),
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: MapRequest,
        mapping: InstalledMapping,
    ) -> Result<(), owned::Error> {
        self.check_context(request.address_space)?;
        let _critical = self.critical()?;
        let first = self
            .tokens
            .iter()
            .position(|slot| slot.load(Ordering::Acquire) == request.id)
            .ok_or(owned::Error::UnmapFailed)?;
        let pages = usize::try_from(request.physical.bytes() / PAGE as u64)
            .map_err(|_| owned::Error::UnmapFailed)?;
        if pages == 0
            || first.checked_add(pages).is_none_or(|end| end > SLOTS)
            || mapping.token != request.id
            || mapping.physical != request.physical
            || mapping.attribute != request.attribute
            || mapping.protection != request.protection
            || mapping.cpu_base.as_ptr() as usize != APERTURE + first * PAGE
        {
            return Err(owned::Error::UnmapFailed);
        }
        for offset in 0..pages {
            if self.tokens[first + offset].load(Ordering::Acquire) != request.id
                || unsafe { self.leaf(first + offset).read_volatile() } & !0x60
                    != ((request.physical.start() + offset as u64 * PAGE as u64) | rights(request))
            {
                return Err(owned::Error::UnmapFailed);
            }
        }
        for offset in 0..pages {
            unsafe {
                self.leaf(first + offset).write_volatile(0);
            }
        }
        self.flush(first, pages);
        self.check_context(request.address_space)?;
        for slot in &self.tokens[first..first + pages] {
            slot.store(0, Ordering::Release);
        }
        Ok(())
    }
}
