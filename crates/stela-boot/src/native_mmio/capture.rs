//! Owned copies of the actual UEFI resource settings and final memory map.
//! No firmware protocol, borrowed descriptor buffer or allocator crosses EBS.
use super::*;
use crate::{handoff::Region, tables::Frames};
use stela_runtime::pc::acpi;
use uefi::{
    boot,
    mem::memory_map::MemoryMap,
    proto::pci::{configuration::ResourceRangeType, root_bridge::PciRootBridgeIo},
};

const MAGIC: u64 = 0x5354_4c4d_4d49_4f31;
const MAX_ROOTS: usize = 64;
const MAX_MEMORY: usize = 512;
const TABLE_BYTES: usize = 65536;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct Memory {
    pub start: u64,
    pub end: u64,
    pub kind: u32,
    pub attributes: u64,
}
/// All fields are initialized by the actual loader. Kept in reserved
/// LOADER_DATA pages, mapped by the native physmap and never offered to guests.
#[repr(C)]
pub(crate) struct Wire {
    magic: u64,
    pub(super) root: u64,
    pub(super) leaf: u64,
    pub(super) virtual_base: u64,
    pub(super) cores: u32,
    pub(super) levels: u32,
    root_count: usize,
    memory_count: usize,
    madt_bytes: usize,
    mcfg_bytes: usize,
    fadt_bytes: usize,
    hpet_bytes: usize,
    roots: [RootWindow; MAX_ROOTS],
    memory: [Memory; MAX_MEMORY],
    madt: [u8; TABLE_BYTES],
    mcfg: [u8; TABLE_BYTES],
    fadt: [u8; TABLE_BYTES],
    hpet: [u8; 56],
}
impl Wire {
    pub(super) fn valid(&self) -> bool {
        self.magic == MAGIC
            && self.root_count <= MAX_ROOTS
            && self.memory_count <= MAX_MEMORY
            && self.madt_bytes <= TABLE_BYTES
            && self.mcfg_bytes <= TABLE_BYTES
            && self.fadt_bytes <= TABLE_BYTES
            && matches!(self.hpet_bytes, 0 | 56)
            && self.cores == 1
            && matches!(self.levels, 4 | 5)
    }
    pub(crate) fn madt(&self) -> &[u8] {
        &self.madt[..self.madt_bytes]
    }
    pub(super) fn mcfg(&self) -> &[u8] {
        &self.mcfg[..self.mcfg_bytes]
    }
    pub(crate) fn fadt(&self) -> &[u8] {
        &self.fadt[..self.fadt_bytes]
    }
    pub(super) fn hpet(&self) -> &[u8] {
        &self.hpet[..self.hpet_bytes]
    }
    pub(super) fn roots(&self) -> &[RootWindow] {
        &self.roots[..self.root_count]
    }
    pub(super) fn memory(&self) -> &[Memory] {
        &self.memory[..self.memory_count]
    }
    pub(super) fn table_owned(&self, physical: u64) -> bool {
        physical.is_multiple_of(PAGE)
            && physical.checked_add(PAGE).is_some_and(|end| {
                self.memory()
                    .iter()
                    .any(|r| r.kind == 2 && r.start <= physical && end <= r.end)
            })
    }
    pub(super) fn excludes_memory(&self, first: u64, end: u64) -> bool {
        self.memory().iter().all(|r| {
            r.end <= first
                || end <= r.start
                || (matches!(r.kind, 0 | 11) && r.attributes & (1 << 63) == 0)
        })
    }
}

pub(crate) struct Prepared {
    region: Region,
}
impl Prepared {
    /// Copy genuine root settings without disconnecting the firmware's bus
    /// driver. A missing/unsupported descriptor set leaves MMIO unavailable.
    pub(crate) fn capture() -> Result<Self, &'static str> {
        let bytes = size_of::<Wire>().next_multiple_of(PAGE as usize);
        let base = crate::firmware::pages(bytes / PAGE as usize)?;
        // SAFETY: fresh owned loader pages, zero is valid for every wire field.
        let wire = unsafe {
            (base as *mut Wire).write_bytes(0, 1);
            &mut *(base as *mut Wire)
        };
        let handles = boot::find_handles::<PciRootBridgeIo>()
            .map_err(|_| "MMIO root bridge inventory unavailable")?;
        if handles.is_empty() {
            return Err("MMIO root bridge inventory empty");
        }
        // Block firmware event callbacks while borrowing and copying these
        // immutable settings. This BSP performs no connect/disconnect or
        // protocol installation while borrowed; MP capture already joined.
        // Exclusive opening would stop the firmware PCI bus driver and can
        // destroy its children/assignments, so it is not an inventory read.
        // SAFETY: actual application-level BSP entry, before EBS, with joined
        // MP callbacks; the matching guard restores TPL on every exit path.
        let tpl = unsafe { boot::raise_tpl(boot::Tpl::NOTIFY) };
        for (bridge, handle) in handles.into_iter().enumerate() {
            // SAFETY: serialized pre-EBS BSP and blocked event callbacks above;
            // the published interface/settings are stable for this short copy.
            let root = unsafe {
                boot::open_protocol::<PciRootBridgeIo>(
                    boot::OpenProtocolParams {
                        handle,
                        agent: boot::image_handle(),
                        controller: None,
                    },
                    boot::OpenProtocolAttributes::GetProtocol,
                )
            }
            .map_err(|_| "MMIO root bridge settings unavailable")?;
            let descriptors = root
                .configuration()
                .map_err(|_| "MMIO root settings unavailable")?;
            for descriptor in descriptors {
                if wire.root_count == MAX_ROOTS {
                    return Err("MMIO root inventory capacity exceeded");
                }
                let space = match descriptor.resource_range_type {
                    ResourceRangeType::Memory => 0,
                    ResourceRangeType::Io => 1,
                    ResourceRangeType::Bus => 2,
                    ResourceRangeType::Unknown(_) => {
                        return Err("MMIO root resource type unsupported");
                    }
                };
                wire.roots[wire.root_count] = RootWindow {
                    segment: root.segment_nr(),
                    bridge: u32::try_from(bridge + 1).map_err(|_| "MMIO bridge count overflow")?,
                    flags: descriptor.general_flags,
                    specific: descriptor.type_specific_flags,
                    space,
                    reserved: 0,
                    minimum: descriptor.address_min,
                    maximum: descriptor.address_max,
                    translation: descriptor.translation_offset,
                    length: descriptor.address_length,
                };
                wire.root_count += 1;
            }
        }
        drop(tpl);
        let rsdp = crate::storage::rsdp().ok_or("MMIO ACPI root unavailable")?;
        // SAFETY: the actual UEFI configuration table points to retained readable
        // firmware tables before EBS. find validates RSDP/root/SDT checksums.
        for (signature, destination, length) in [
            (b"APIC", &mut wire.madt[..], &mut wire.madt_bytes),
            (b"MCFG", &mut wire.mcfg[..], &mut wire.mcfg_bytes),
            (b"FACP", &mut wire.fadt[..], &mut wire.fadt_bytes),
        ] {
            let source = unsafe { acpi::find(rsdp, signature) }
                .map_err(|_| "MMIO ACPI inventory unavailable")?;
            if source.len() > destination.len() {
                return Err("MMIO ACPI table capacity exceeded");
            }
            destination[..source.len()].copy_from_slice(source);
            *length = source.len();
        }
        // HPET is optional for other clocks. Absence, invalid checksum or
        // unsupported original length leaves the typed HPET factory unavailable;
        // no default address/capability is reconstructed.
        // SAFETY: same actual pre-EBS readable firmware ACPI root as above.
        if let Ok(source) = unsafe { acpi::find(rsdp, b"HPET") }
            && source.len() == wire.hpet.len()
        {
            wire.hpet.copy_from_slice(source);
            wire.hpet_bytes = source.len();
        }
        Ok(Self {
            region: Region {
                physical: base as u64,
                bytes: bytes as u64,
            },
        })
    }
    pub(crate) fn region(&self) -> Region {
        self.region
    }
    /// Prepare one empty shared-window PT. No physical device mapping or cache
    /// policy is created here; the post-EBS owner publishes individual leaves.
    pub(crate) fn aperture(
        &self,
        frames: &mut dyn Frames,
        root: u64,
        cores: usize,
    ) -> Result<(), &'static str> {
        // SAFETY: this private pre-EBS capture owns these exact loader pages.
        let wire = unsafe { &mut *(self.region.physical as *mut Wire) };
        let base = crate::layout::window() + APERTURE_OFFSET;
        let leaf =
            crate::tables::entry(frames, root, base, 0, true)?.ok_or("MMIO aperture missing")?;
        // SAFETY: the builder returned the first slot of a new PT for aligned base.
        if (0..ENTRIES).any(|i| unsafe { leaf.add(i).read_volatile() } != 0) {
            return Err("MMIO aperture overlaps an existing mapping");
        }
        wire.root = root;
        wire.leaf = leaf as u64;
        wire.virtual_base = base;
        wire.cores = u32::try_from(cores).map_err(|_| "MMIO core count overflow")?;
        wire.levels = crate::layout::top_level() + 1;
        Ok(())
    }
    /// Seal from the actual successful ExitBootServices map, after every owned
    /// allocation. On overflow magic stays absent and post-EBS admission refuses.
    pub(crate) fn finish(&self, map: &impl MemoryMap) -> Result<(), &'static str> {
        // SAFETY: sole loader writer, not published to the engine until sealed.
        let wire = unsafe { &mut *(self.region.physical as *mut Wire) };
        for entry in map.entries() {
            if wire.memory_count == MAX_MEMORY {
                return Err("MMIO final memory inventory capacity exceeded");
            }
            let end = entry
                .phys_start
                .checked_add(
                    entry
                        .page_count
                        .checked_mul(PAGE)
                        .ok_or("MMIO memory size overflow")?,
                )
                .ok_or("MMIO memory end overflow")?;
            if end <= entry.phys_start
                || !entry.phys_start.is_multiple_of(PAGE)
                || wire.memory[..wire.memory_count]
                    .iter()
                    .any(|previous| previous.start < end && entry.phys_start < previous.end)
            {
                return Err("MMIO final memory inventory has invalid or overlapping entries");
            }
            wire.memory[wire.memory_count] = Memory {
                start: entry.phys_start,
                end,
                kind: entry.ty.0,
                attributes: entry.att.bits(),
            };
            wire.memory_count += 1;
        }
        wire.magic = MAGIC;
        Ok(())
    }
}
