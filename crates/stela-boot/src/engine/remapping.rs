//! The host's DMA remapping units, VT-d's (DMAR) and AMD-Vi's (IVRS, in
//! [`amd`]), taken before the host drivers start
//! ([`stela_boot_core::remapping`] decides which). Every requester a taken
//! unit covers starts in the unit's window domain, which maps the drivers'
//! DMA region and the reserved regions (RMRR, IVMD) of the unit's USB host
//! controllers one to one, so a device reaches that memory and no other
//! RAM. A driver that asks the native services for a domain gets its own
//! ([`Remappers::domain`]).
//!
//! The display functions a driver maps the firmware's reserved regions for
//! are a policy input: none yet, so a unit whose scope holds a display
//! controller is left untranslated until a display driver claims it.
mod amd;

use super::storage::RestoreRoot;
use crate::{
    native_dma::{
        dmar,
        requester::RequesterClaim,
        vtd::{MmioRegisters, Unit, VtdError},
    },
    native_mmio, output,
};
use alloc::{sync::Arc, vec::Vec};
use core::ops::Range;
use stela_boot_core::remapping::{self, Present};
use stela_drivers::bus::{
    dma::{mapping::DmaDomain, memory::CacheAttribute},
    mmio::owned::{PhysicalSpan, Protection},
    pci::{EcamWindow, requester::RequesterBinding},
};
use stela_runtime::pc::acpi;

/// The processor's physical address width (CPUID 0x80000008).
fn physical_bits() -> u8 {
    let leaf = core::arch::x86_64::__cpuid(0x8000_0008);
    (leaf.eax & 0xff) as u8
}

/// The display functions whose driver maps their unit's reserved regions.
const CLAIMED_DISPLAYS: &[u16] = &[];

struct Taken {
    segment: u16,
    requesters: Vec<u16>,
    unit: Arc<Unit<MmioRegisters>>,
}

/// The units the mount translates for.
pub(super) struct Remappers {
    taken: Vec<Taken>,
    amd: Vec<amd::Taken>,
}

/// Every function on `window`'s buses, each bus scanned as a root so a
/// host bridge's bus the firmware did not describe is still covered.
///
/// # Safety
/// The current root maps `window`'s configuration space uncached.
unsafe fn inventory(window: &EcamWindow) -> Vec<Present> {
    let roots: Vec<u8> = (window.start_bus..=window.end_bus).collect();
    remapping::enumerate(&roots, |rid, offset| {
        let bus = (rid >> 8) as u8;
        if !(window.start_bus..=window.end_bus).contains(&bus) {
            return None;
        }
        let address = window.base + (u64::from(rid) << 12) + u64::from(offset);
        // SAFETY: an aligned dword of the mapped configuration space.
        let value = unsafe { (address as *const u32).read_volatile() };
        (value != u32::MAX).then_some(value)
    })
}

impl Remappers {
    pub(super) const fn none() -> Self {
        Self {
            taken: Vec::new(),
            amd: Vec::new(),
        }
    }

    /// Take the units of the firmware's DMAR the policy allows, each with a
    /// window over `drivers` and its USB controllers' reserved regions.
    /// Units the policy leaves and units that refuse are reported and stay
    /// untranslated.
    ///
    /// # Safety
    /// No host driver has started; `root` is the loader root, which maps
    /// the ACPI tables at `rsdp` and `ecam`'s configuration space. The
    /// firmware's translation was turned off at ExitBootServices.
    pub(super) unsafe fn take(
        rsdp: u64,
        root: u64,
        ecam: &[EcamWindow],
        drivers: Range<u64>,
        mmio: &native_mmio::Source,
        tsc_hz: u64,
    ) -> Self {
        let mut remappers = Self::none();
        if rsdp == 0 {
            return remappers;
        }
        let (dmar, ivrs, inventories) = {
            // SAFETY: forwarded; the loader root maps the tables and ECAM.
            let _root = unsafe { RestoreRoot::enter(root) };
            // SAFETY: the firmware's RSDP, whose tables the loader root maps.
            let find = |signature| {
                unsafe { acpi::find(rsdp, signature) }
                    .ok()
                    .map(<[u8]>::to_vec)
            };
            let (dmar, ivrs) = (find(b"DMAR"), find(b"IVRS"));
            if dmar.is_none() && ivrs.is_none() {
                return remappers;
            }
            let inventories: Vec<(u16, Vec<Present>)> = ecam
                .iter()
                // SAFETY: the loader root maps each window.
                .map(|window| (window.segment, unsafe { inventory(window) }))
                .collect();
            (dmar, ivrs, inventories)
        };
        if let Some(ivrs) = ivrs {
            // SAFETY: forwarded.
            remappers.amd =
                unsafe { amd::take(&ivrs, &inventories, &drivers, mmio, tsc_hz, physical_bits()) };
        }
        let Some(table) = dmar else {
            return remappers;
        };
        let parsed = match dmar::parse(&table) {
            Ok(parsed) => parsed,
            Err(error) => {
                output::arguments(format_args!(
                    "UNSUPPORTED host DMAR unreadable ({error:?}): host DMA stays untranslated\n"
                ));
                return remappers;
            }
        };
        for (segment, present) in &inventories {
            for (index, decision) in remapping::plan(&parsed, *segment, present, CLAIMED_DISPLAYS) {
                let unit = &parsed.units[index];
                let requesters = match decision {
                    Ok(requesters) => requesters,
                    Err(why) => {
                        output::arguments(format_args!(
                            "HOST IOMMU VT-d unit {:#x} left untranslated: {why:?}\n",
                            unit.base
                        ));
                        continue;
                    }
                };
                let mut window = alloc::vec![drivers.clone()];
                for region in parsed.reserved.iter().filter(|region| {
                    region.segment == *segment
                        && region.scopes.iter().any(|scope| {
                            scope
                                .resolve(present)
                                .iter()
                                .any(|rid| requesters.contains(rid))
                        })
                }) {
                    window.push(region.base..region.limit + 1);
                }
                // SAFETY: forwarded; the unit's registers are the mount's.
                match unsafe {
                    Self::take_unit(
                        unit,
                        &requesters,
                        &window,
                        parsed.physical_bits,
                        mmio,
                        tsc_hz,
                    )
                } {
                    Ok(taken) => {
                        output::arguments(format_args!(
                            "HOST IOMMU VT-d unit {:#x} translates {} requesters\n",
                            unit.base,
                            requesters.len()
                        ));
                        remappers.taken.push(Taken {
                            segment: *segment,
                            requesters,
                            unit: taken,
                        });
                    }
                    Err(error) => output::arguments(format_args!(
                        "HOST IOMMU VT-d unit {:#x} left untranslated: {error:?}\n",
                        unit.base
                    )),
                }
            }
        }
        remappers
    }

    /// # Safety
    /// As for [`Self::take`].
    unsafe fn take_unit(
        unit: &dmar::Drhd,
        requesters: &[u16],
        window: &[Range<u64>],
        physical_bits: u8,
        mmio: &native_mmio::Source,
        tsc_hz: u64,
    ) -> Result<Arc<Unit<MmioRegisters>>, VtdError> {
        let span =
            PhysicalSpan::new(unit.base, unit.bytes as u64).map_err(|_| VtdError::RegisterRange)?;
        // SAFETY: the DMAR names this unit's registers, which no driver owns.
        let resource = unsafe { mmio.claim_platform(span) }.map_err(|_| VtdError::RegisterRange)?;
        let mapping = mmio
            .authority()
            .map(
                resource,
                0,
                unit.bytes,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(|_| VtdError::RegisterRange)?;
        let base = mapping
            .address(0, unit.bytes)
            .map_err(|_| VtdError::RegisterRange)?;
        // The unit keeps its registers for the boot.
        core::mem::forget(mapping);
        // SAFETY: the mapping is the unit's uncached register window in the
        // aperture, which every root maps, kept above.
        let registers =
            unsafe { MmioRegisters::new(base, unit.bytes, crate::apic::rdtsc, tsc_hz.max(1)) }?;
        // SAFETY: forwarded: the policy resolved the scope and the window
        // holds the reserved regions the covered requesters use.
        unsafe {
            Unit::take_over(
                registers,
                &crate::native_memory::SOURCE,
                requesters,
                physical_bits.min(52),
                window,
            )
        }
    }

    /// Report the faults each taken unit recorded: DMA a device sent outside
    /// its domain.
    pub(super) fn report_faults(&self) {
        for taken in &self.taken {
            match taken.unit.pending_faults() {
                Ok(faults) => {
                    for fault in faults {
                        output::arguments(format_args!(
                            "HOST IOMMU fault requester={:#06x} address={:#x} reason={:#x} {}\n",
                            fault.requester,
                            fault.address,
                            fault.reason,
                            if fault.read { "read" } else { "write" },
                        ));
                    }
                }
                Err(error) => {
                    output::arguments(format_args!("HOST IOMMU faults unreadable: {error:?}\n"))
                }
            }
        }
    }

    /// The domain of its own for `binding`'s requester when a taken unit
    /// covers it; the binding back when none does.
    pub(super) fn domain(
        &self,
        binding: RequesterBinding,
    ) -> Result<Result<Arc<dyn DmaDomain>, VtdError>, RequesterBinding> {
        let segment = binding.address().segment;
        let rid = binding.requester();
        if let Some(taken) = self.amd.iter().find(|taken| taken.covers(segment, rid)) {
            return Ok(taken.domain(binding).map_err(|error| {
                output::arguments(format_args!(
                    "HOST IOMMU AMD-Vi attach refused: {error:?}\n"
                ));
                VtdError::Busy
            }));
        }
        let Some(taken) = self
            .taken
            .iter()
            .find(|taken| taken.segment == segment && taken.requesters.contains(&rid))
        else {
            return Err(binding);
        };
        // SAFETY: the driver's binding of its stopped function, whose bus
        // mastering it enables after mapping through this domain.
        Ok(
            unsafe { RequesterClaim::from_binding(binding) }.and_then(|claim| {
                // SAFETY: as above; the claim is that function's.
                let domain = unsafe { taken.unit.attach_requester(claim) }?;
                Ok(domain as Arc<dyn DmaDomain>)
            }),
        )
    }
}
