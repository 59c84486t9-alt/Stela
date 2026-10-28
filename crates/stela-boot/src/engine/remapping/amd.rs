//! AMD-Vi units ([`stela_drivers::bus::dma::amd`]): one per IVHD, each its
//! own PCI function. The units are process local; the boot processor, which
//! runs the host drivers, owns them, and their domains refuse other
//! processors and interrupt handlers.
use super::CLAIMED_DISPLAYS;
use crate::{native_mmio, output};
use alloc::{boxed::Box, format, string::String, sync::Arc, vec, vec::Vec};
use core::{cell::RefCell, ops::Range, ptr::NonNull};
use stela_boot_core::remapping::{self, Present};
use stela_drivers::{
    Clock,
    bus::{
        dma::{
            amd::{
                ivrs::{Ivrs, MemoryScope},
                memory::TableVisibility,
                unit::{
                    native::{ColdPlatform, Error, Limits, Mapping, Requester, Unit},
                    registers::{FunctionInspection, Inputs},
                },
            },
            mapping::{Direction, DmaDomain, DmaError, DomainMapping},
            memory::{
                CacheAttribute, MemoryError, PageBacking, PageGeometry, PageSource, PinnedPages,
            },
            pages::DmaPages,
        },
        mmio::owned::{PhysicalSpan, Protection},
        pci::{Address, Function, owned::OwnedConfig, requester::RequesterBinding},
    },
};

const PAGE: u64 = 4096;
/// The register apertures an AMD-Vi unit decodes: without and with its
/// performance counters.
const APERTURES: [u64; 2] = [16 << 10, 512 << 10];
/// The most IVHD blocks one IVRS may hold.
const MAXIMUM_BLOCKS: usize = 64;

/// Whether this is the boot processor: the application processors join the
/// aperture shootdown, and the boot processor holds no slot.
fn on_boot_processor() -> bool {
    crate::engine::host::shootdown().0.is_none() && !crate::engine::host::in_interrupt()
}

/// The boot processor's cold-unit services: the native allocator's pages,
/// coherent table walks (the unit's control sets Coherent) and the TSC.
pub(super) struct Platform {
    tsc_hz: u64,
    physical_bits: u8,
}

pub(super) struct Access;

impl PageSource for Platform {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        crate::native_memory::SOURCE.page_geometry()
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        crate::native_memory::SOURCE.allocate(bytes, alignment, attribute)
    }
}

// SAFETY: the unit walks its tables coherently (control bit Coherent), so a
// store ordered by MFENCE before the unit's command is visible to it.
unsafe impl TableVisibility for Platform {
    unsafe fn publish(&self, _: NonNull<u8>, _: usize) -> Result<(), MemoryError> {
        crate::native_dma::vtd::publish();
        Ok(())
    }
}

// SAFETY: the boot processor alone, outside interrupts, reaches the unit;
// its pages are the native allocator's zeroed write-back RAM, which the
// unit reaches coherently; the clock is the invariant TSC.
unsafe impl ColdPlatform for Platform {
    type Access<'a> = Access;
    fn enter(&self) -> Result<Self::Access<'_>, DmaError> {
        if !on_boot_processor() {
            return Err(DmaError::IommuUnavailable);
        }
        Ok(Access)
    }
    fn clock(&self) -> Clock {
        Clock {
            ticks_per_microsecond: (self.tsc_hz / 1_000_000).max(1),
        }
    }
    fn physical_bits(&self) -> u8 {
        self.physical_bits
    }
    fn admit_payload(&self, pages: &DmaPages, _: Direction) -> Result<bool, DmaError> {
        if pages.cache_attribute() != CacheAttribute::WriteBack {
            return Err(DmaError::CoherenceUnavailable);
        }
        Ok(true)
    }
    unsafe fn sync(
        &self,
        _: &DmaPages,
        _: Range<usize>,
        _: Direction,
        _: bool,
    ) -> Result<(), DmaError> {
        // Device DMA to write-back RAM is snooped; the fence drains
        // write-combining buffers before the device reads.
        crate::native_dma::vtd::publish();
        Ok(())
    }
}

/// Memory the window maps that no allocator owns: the drivers' DMA region
/// and firmware reserved regions. The window never maps it for the CPU.
struct Borrowed {
    pages: Vec<u64>,
}

// SAFETY: the pages are kept for the boot by their owner (the loader's DMA
// allocation, firmware reservations); `cpu_base` is the physmap address
// of the first page, which the unit's tables never dereference.
unsafe impl PageBacking for Borrowed {
    fn cpu_base(&self) -> NonNull<u8> {
        NonNull::new(crate::layout::physical(self.pages[0]) as *mut u8).expect("physmap")
    }
    fn physical_pages(&self) -> &[u64] {
        &self.pages
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}

fn borrowed(range: &Range<u64>) -> Option<DmaPages> {
    let start = range.start & !(PAGE - 1);
    let end = range.end.next_multiple_of(PAGE);
    let pages: Vec<u64> = (start..end).step_by(PAGE as usize).collect();
    let bytes = pages.len() * PAGE as usize;
    if pages.is_empty() {
        return None;
    }
    PinnedPages::new(Box::new(Borrowed { pages }), bytes, PAGE as usize)
        .ok()
        .map(DmaPages::from)
}

/// The present requesters an IVMD names.
fn named(scope: MemoryScope, segment: u16, present: &[Present]) -> Vec<u16> {
    present
        .iter()
        .map(|function| function.rid)
        .filter(|&rid| match scope {
            MemoryScope::AllDevices => true,
            MemoryScope::Device(id) => id.segment == segment && id.device_id == rid,
            MemoryScope::Range { first, last } => {
                first.segment == segment && (first.device_id..=last.device_id).contains(&rid)
            }
        })
        .collect()
}

pub(super) struct Taken {
    unit: RefCell<Unit<Platform>>,
    segment: u16,
    requesters: Vec<u16>,
}

/// The function at `address`'s own configuration page.
///
/// # Safety
/// No driver owns the function.
unsafe fn config(mmio: &native_mmio::Source, address: Address) -> Option<Function<OwnedConfig>> {
    // SAFETY: forwarded; the bus is shared with the drivers, each owning
    // its own function's page.
    let (window, resource) = unsafe { mmio.claim_bus(address.segment, address.bus) }.ok()?;
    let offset = usize::from(address.device) << 15 | usize::from(address.function) << 12;
    let mapping = mmio
        .authority()
        .map(
            resource,
            offset,
            PAGE as usize,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .ok()?;
    // SAFETY: the mapping is the function's own configuration page.
    let config = unsafe { OwnedConfig::attach(address, window, mapping) }.ok()?;
    Function::new(address, config)
}

/// Inspect the unit at `function` with its register aperture mapped.
///
/// # Safety
/// The mount owns the unit's function and registers.
unsafe fn inspect(
    mmio: &native_mmio::Source,
    mut function: Function<OwnedConfig>,
    base: u64,
    ivrs: &Ivrs<'_>,
) -> Result<FunctionInspection, String> {
    let mut refusals = Vec::new();
    for bytes in APERTURES {
        let span = PhysicalSpan::new(base, bytes).map_err(|error| format!("span {error:?}"))?;
        // SAFETY: forwarded; the IVHD names these registers.
        let resource = match unsafe { mmio.claim_platform(span) } {
            Ok(resource) => resource,
            Err(error) => {
                refusals.push(format!("{bytes:#x} bytes: {error:?}"));
                continue;
            }
        };
        let mapping = mmio
            .authority()
            .map(
                resource.clone(),
                0,
                bytes as usize,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(|error| format!("mapping {error:?}"))?;
        let inputs = Inputs {
            function,
            mappings: vec![mapping],
        };
        // SAFETY: forwarded: the function and registers are the mount's.
        match unsafe { FunctionInspection::inspect(inputs, ivrs) } {
            Ok(inspection) => return Ok(inspection),
            Err((error, inputs)) => {
                refusals.push(format!("{bytes:#x} bytes: {error:?}"));
                function = inputs.function;
                // Release the aperture so the next size can claim it.
                for mut mapping in inputs.mappings {
                    // SAFETY: the refused inspection was the mapping's only use.
                    unsafe { mapping.retire() }.map_err(|error| format!("unmap {error:?}"))?;
                }
                let authority = mmio.authority();
                authority
                    .register_resource(resource)
                    .and_then(|id| authority.unregister_resource(id))
                    .map_err(|error| format!("release {error:?}"))?;
            }
        }
    }
    Err(format!(
        "its function or registers did not match the IVRS: {refusals:?}"
    ))
}

/// Take every unit of `table` (an IVRS) the policy allows.
///
/// # Safety
/// As for [`super::Remappers::take`].
pub(super) unsafe fn take(
    table: &[u8],
    inventories: &[(u16, Vec<Present>)],
    drivers: &Range<u64>,
    mmio: &native_mmio::Source,
    tsc_hz: u64,
    physical_bits: u8,
) -> Vec<Taken> {
    let mut taken = Vec::new();
    let ivrs = match Ivrs::parse(table, MAXIMUM_BLOCKS) {
        Ok(ivrs) => ivrs,
        Err(error) => {
            output::arguments(format_args!(
                "UNSUPPORTED host IVRS unreadable ({error:?}): host DMA stays untranslated\n"
            ));
            return taken;
        }
    };
    for description in ivrs.units() {
        let id = description.id();
        let base = description.mmio_address();
        let Some((_, present)) = inventories
            .iter()
            .find(|(segment, _)| *segment == id.segment)
        else {
            continue;
        };
        let address = Address {
            segment: id.segment,
            bus: (id.device_id >> 8) as u8,
            device: (id.device_id >> 3 & 31) as u8,
            function: (id.device_id & 7) as u8,
        };
        let left = |why: &dyn core::fmt::Debug| {
            output::arguments(format_args!(
                "HOST IOMMU AMD-Vi unit {base:#x} left untranslated: {why:?}\n"
            ));
        };
        // SAFETY: forwarded; no driver claims an IOMMU function.
        let Some(function) = (unsafe { config(mmio, address) }) else {
            left(&"its configuration space could not be mapped");
            continue;
        };
        // SAFETY: forwarded.
        let inspection = match unsafe { inspect(mmio, function, base, &ivrs) } {
            Ok(inspection) => inspection,
            Err(why) => {
                left(&why);
                continue;
            }
        };
        let platform = Platform {
            tsc_hz,
            physical_bits,
        };
        let limits = Limits {
            table_pages: 513,
            table_backing_bytes: 513 * PAGE as usize,
            mappings: 4096,
            wait_us: 100_000,
        };
        // SAFETY: forwarded: the firmware's translation was turned off at
        // ExitBootServices and no driver has started.
        let mut unit = match unsafe { Unit::cold(inspection, &ivrs, platform, limits) } {
            Ok(unit) => unit,
            Err(error) => {
                left(&error);
                continue;
            }
        };
        let covered: Vec<u16> = present
            .iter()
            .map(|function| function.rid)
            .filter(|&rid| rid != id.device_id && unit.covers(id.segment, rid))
            .collect();
        let reserved: Vec<(u16, Range<u64>)> = ivrs
            .memory_definitions()
            .flat_map(|region| {
                named(region.scope(), id.segment, present)
                    .into_iter()
                    .map(move |rid| (rid, region.start()..region.end()))
            })
            .collect();
        let held: Vec<u16> = reserved.iter().map(|(rid, _)| *rid).collect();
        let requesters = match remapping::decide(&covered, &held, present, CLAIMED_DISPLAYS) {
            Ok(requesters) => requesters,
            Err(why) => {
                left(&why);
                // SAFETY: no requester was attached and the unit blocks
                // nothing it translated; retiring stops it.
                if unsafe { unit.retire() }.is_err() {
                    left(&"and it did not stop");
                }
                continue;
            }
        };
        let mut window = vec![drivers.clone()];
        window.extend(
            reserved
                .iter()
                .filter(|(rid, _)| requesters.contains(rid))
                .map(|(_, range)| range.clone()),
        );
        let Some(ranges) = window.iter().map(borrowed).collect::<Option<Vec<_>>>() else {
            left(&"an empty window range");
            continue;
        };
        // SAFETY: forwarded: the requesters DMA only to the drivers' region
        // and their reserved regions until they attach.
        if let Err(error) = unsafe { unit.window(&requesters, ranges) } {
            left(&error);
            continue;
        }
        output::arguments(format_args!(
            "HOST IOMMU AMD-Vi unit {base:#x} translates {} requesters\n",
            requesters.len()
        ));
        taken.push(Taken {
            unit: RefCell::new(unit),
            segment: id.segment,
            requesters,
        });
    }
    taken
}

impl Taken {
    pub(super) fn covers(&self, segment: u16, rid: u16) -> bool {
        self.segment == segment && self.requesters.contains(&rid)
    }

    /// A domain of its own for `binding`'s requester.
    pub(super) fn domain(&self, binding: RequesterBinding) -> Result<Arc<dyn DmaDomain>, Error> {
        let mut unit = self.unit.try_borrow_mut().map_err(|_| Error::Busy)?;
        // SAFETY: the driver's binding of its stopped function, whose bus
        // mastering it enables after mapping through this domain.
        let requester = unsafe { unit.attach_binding(binding) }?;
        Ok(Arc::new(Domain {
            inner: RefCell::new(Inner {
                requester,
                mappings: Vec::new(),
                next: 1,
            }),
        }))
    }
}

struct Inner {
    requester: Requester<Platform>,
    mappings: Vec<(DomainMapping, Mapping)>,
    next: u64,
}

/// A requester's own AMD-Vi domain, reached from the boot processor alone.
struct Domain {
    inner: RefCell<Inner>,
}

// SAFETY: every method checks it runs on the boot processor outside an
// interrupt handler before it touches the process-local requester.
unsafe impl Send for Domain {}
// SAFETY: as above.
unsafe impl Sync for Domain {}

fn failed(error: Error) -> DmaError {
    match error {
        Error::Dma(error) => error,
        _ => DmaError::MappingFailed,
    }
}

impl Domain {
    fn inner(&self) -> Result<core::cell::RefMut<'_, Inner>, DmaError> {
        if !on_boot_processor() {
            return Err(DmaError::IommuUnavailable);
        }
        self.inner
            .try_borrow_mut()
            .map_err(|_| DmaError::IommuUnavailable)
    }
}

// SAFETY: the requester's own AMD-Vi domain maps the ordered pages with the
// direction's rights and completes the invalidation before map returns.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        address_limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let mut inner = self.inner()?;
        let mapping = inner
            .requester
            .map(pages.clone(), direction, address_limit)
            .map_err(failed)?;
        let info = DomainMapping {
            id: inner.next,
            address: mapping.address(),
            bytes: mapping.bytes(),
        };
        inner.next += 1;
        inner.mappings.push((info, mapping));
        Ok(info)
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
        let mut inner = self.inner()?;
        let index = inner
            .mappings
            .iter()
            .position(|(info, _)| *info == mapping)
            .ok_or(DmaError::Unmapped)?;
        let Inner {
            requester,
            mappings,
            ..
        } = &mut *inner;
        // SAFETY: forwarded: the device's accesses to it have completed.
        unsafe { requester.unmap(&mappings[index].1) }.map_err(failed)?;
        mappings.swap_remove(index);
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        let inner = self.inner()?;
        let (_, live) = inner
            .mappings
            .iter()
            .find(|(info, _)| *info == mapping)
            .ok_or(DmaError::Unmapped)?;
        // SAFETY: forwarded.
        unsafe { inner.requester.sync(live, range, false) }.map_err(failed)
    }
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        let inner = self.inner()?;
        let (_, live) = inner
            .mappings
            .iter()
            .find(|(info, _)| *info == mapping)
            .ok_or(DmaError::Unmapped)?;
        // SAFETY: forwarded.
        unsafe { inner.requester.sync(live, range, true) }.map_err(failed)
    }
}
