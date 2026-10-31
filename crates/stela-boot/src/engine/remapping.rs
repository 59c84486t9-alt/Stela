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
mod preparation;

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
    pci::{
        Address, EcamWindow,
        requester::{FunctionRole, RequesterBinding, roles},
    },
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
    descriptor: usize,
    unit: Arc<Unit<MmioRegisters>>,
}

/// The units the mount translates for.
pub(super) struct Remappers {
    taken: Vec<Taken>,
    amd: Vec<amd::Taken>,
    roles: core::cell::RefCell<roles::Inventory>,
    topology: core::cell::RefCell<Vec<(u16, Vec<Present>)>>,
    dmar: Option<dmar::Remapping>,
}

/// Every present function, grouped by PCI segment across the platform's
/// validated ECAM windows, so each remapping unit sees its entire scope.
///
/// # Safety
/// The current root maps every window's configuration space uncached.
unsafe fn inventory(windows: &[EcamWindow]) -> Vec<(u16, Vec<Present>)> {
    remapping::enumerate_segments(windows, |window, rid, offset| {
        // SAFETY: enumerate_segments selects the validated window containing
        // this requester, and offset names an aligned configuration dword.
        let value = unsafe { configuration(window, rid, offset) };
        (value != u32::MAX).then_some(value)
    })
}

/// # Safety
/// The validated window is mapped uncached in this root and contains rid's
/// bus. offset is an aligned dword no later than 4092 in this function.
unsafe fn configuration(window: &EcamWindow, rid: u16, offset: u16) -> u32 {
    let address = window.base + (u64::from(rid) << 12) + u64::from(offset);
    // SAFETY: the caller supplies this exact complete mapped ECAM dword.
    unsafe { (address as *const u32).read_volatile() }
}

/// The requester ID of the function at `address`.
fn requester(address: Address) -> u16 {
    u16::from(address.bus) << 8 | u16::from(address.device) << 3 | u16::from(address.function)
}

impl Remappers {
    pub(super) const fn none() -> Self {
        Self {
            taken: Vec::new(),
            amd: Vec::new(),
            roles: core::cell::RefCell::new(roles::Inventory::empty()),
            topology: core::cell::RefCell::new(Vec::new()),
            dmar: None,
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
    /// firmware's translation was turned off at ExitBootServices. PCI function,
    /// SR-IOV, reset and routing writers stay excluded through the inventory and
    /// later claims; ECAM lists every admitted bus, not only remapped segments.
    pub(super) unsafe fn take(
        rsdp: u64,
        root: u64,
        ecam: &[EcamWindow],
        drivers: Range<u64>,
        mmio: &native_mmio::Source,
        tsc_hz: u64,
    ) -> Self {
        let mut remappers = Self::none();
        let (dmar, ivrs, inventories, roles) = {
            // SAFETY: forwarded; the loader root maps the tables and ECAM.
            let _root = unsafe { RestoreRoot::enter(root) };
            let find = |signature| {
                if rsdp == 0 {
                    return None;
                }
                // SAFETY: the firmware's RSDP, whose tables the loader root maps.
                unsafe { acpi::find(rsdp, signature) }
                    .ok()
                    .map(<[u8]>::to_vec)
            };
            let (dmar, ivrs) = (find(b"DMAR"), find(b"IVRS"));
            // SAFETY: the loader root maps every validated ECAM window.
            let inventories = unsafe { inventory(ecam) };
            let functions: Vec<_> = inventories
                .iter()
                .flat_map(|(segment, present)| {
                    present.iter().map(|function| Address {
                        segment: *segment,
                        bus: (function.rid >> 8) as u8,
                        device: ((function.rid >> 3) & 31) as u8,
                        function: (function.rid & 7) as u8,
                    })
                })
                .collect();
            let roles = roles::Inventory::capture(&functions, |address, offset| {
                if offset > 4092 || !offset.is_multiple_of(4) {
                    return None;
                }
                let window = ecam.iter().find(|window| {
                    window.segment == address.segment
                        && (window.start_bus..=window.end_bus).contains(&address.bus)
                })?;
                // SAFETY: current loader root maps this checked window;
                // capture runs before any host driver/configuration writer starts.
                Some(unsafe { configuration(window, requester(address), offset) })
            });
            (dmar, ivrs, inventories, roles)
        };
        for issue in roles.issues() {
            output::arguments(format_args!(
                "UNSUPPORTED Stela PCI function-role inventory: {issue:?}\n"
            ));
        }
        *remappers.roles.get_mut() = roles;
        *remappers.topology.get_mut() = inventories.clone();
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
        remappers.dmar = Some(parsed.clone());
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
                            descriptor: index,
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

    /// The taken hardware unit selected by this requester's firmware route.
    /// An untaken descriptor remains explicitly untranslated, even when the
    /// parent bridge uses a different taken unit.
    fn vtd(&self, segment: u16, rid: u16) -> Result<Option<&Taken>, VtdError> {
        let Some(dmar) = &self.dmar else {
            return Ok(None);
        };
        let topology = self.topology.borrow();
        let Some((_, present)) = topology.iter().find(|(found, _)| *found == segment) else {
            return Err(VtdError::Unsupported);
        };
        let selected =
            remapping::route(dmar, segment, present, rid).map_err(|_| VtdError::Unsupported)?;
        Ok(selected.and_then(|descriptor| {
            self.taken
                .iter()
                .find(|taken| taken.descriptor == descriptor)
        }))
    }

    fn amd(&self, segment: u16, rid: u16) -> Result<Option<&amd::Taken>, VtdError> {
        let mut selected = None;
        for taken in &self.amd {
            if taken.routes(segment, rid).map_err(|_| VtdError::Busy)? {
                if selected.is_some() {
                    return Err(VtdError::Unsupported);
                }
                selected = Some(taken);
            }
        }
        Ok(selected)
    }

    /// Initial complete PF/VF inventory, kept under the original PCI epoch.
    /// New arrivals require a fresh role inventory before a native claim.
    pub(super) fn function_role(&self, address: Address) -> FunctionRole {
        self.roles.borrow().role(address)
    }

    /// Join the complete adopted subtree and the original bridge's updated
    /// bus numbers before selecting firmware routes or granting native claims.
    pub(super) fn observe_arrivals(
        &self,
        bridge: Address,
        functions: &[Address],
        read32: &mut dyn FnMut(Address, u16) -> Option<u32>,
    ) -> bool {
        let fresh = roles::Inventory::capture(functions, &mut *read32);
        let mut updates = Vec::new();
        for address in core::iter::once(bridge).chain(functions.iter().copied()) {
            let observation = (|| {
                let class = read32(address, 8).filter(|value| *value != u32::MAX)?;
                let header = read32(address, 12).filter(|value| *value != u32::MAX)?;
                let buses = if header >> 16 & 0x7f == 1 {
                    let buses = read32(address, 24).filter(|value| *value != u32::MAX)?;
                    let secondary = (buses >> 8) as u8;
                    let subordinate = (buses >> 16) as u8;
                    if secondary <= address.bus || subordinate < secondary {
                        return None;
                    }
                    Some((secondary, subordinate))
                } else {
                    None
                };
                Some(Present {
                    rid: requester(address),
                    class: [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
                    bridge: buses,
                })
            })();
            let Some(observation) = observation else {
                self.roles.borrow_mut().invalidate_topology(address);
                return false;
            };
            updates.push(observation);
        }
        let mut topology = self.topology.borrow_mut();
        let Some((_, present)) = topology
            .iter_mut()
            .find(|(segment, _)| *segment == bridge.segment)
        else {
            self.roles.borrow_mut().invalidate_topology(bridge);
            return false;
        };
        if !present
            .iter()
            .any(|entry| entry.rid == requester(bridge) && entry.class[..2] == [6, 4])
            || updates[0].class[..2] != [6, 4]
            || updates[0].bridge.is_none()
        {
            self.roles.borrow_mut().invalidate_topology(bridge);
            return false;
        }
        for update in updates {
            if let Some(entry) = present.iter_mut().find(|entry| entry.rid == update.rid) {
                if entry.class != update.class {
                    self.roles.borrow_mut().invalidate_topology(bridge);
                    return false;
                }
                *entry = update;
            } else {
                present.push(update);
            }
        }
        present.sort_unstable_by_key(|entry| entry.rid);
        let mut roles = self.roles.borrow_mut();
        let previous = roles.issues().len();
        roles.extend(fresh);
        for issue in &roles.issues()[previous..] {
            output::arguments(format_args!(
                "UNSUPPORTED Stela PCI function-role arrival: {issue:?}\n"
            ));
        }
        functions
            .iter()
            .all(|address| roles.role(*address) != FunctionRole::Unverified)
    }

    /// Whether a taken unit confines the DMA of the function at `address`.
    pub(super) fn translates(&self, address: Address) -> bool {
        let rid = requester(address);
        self.amd(address.segment, rid)
            .ok()
            .flatten()
            .is_some_and(|taken| taken.covers(address.segment, rid))
            || self
                .vtd(address.segment, rid)
                .ok()
                .flatten()
                .is_some_and(|taken| taken.unit.allows(rid))
    }

    /// Confinement for every possible future child, rather than only the
    /// bridge's own RID. A still-untranslated explicit child unit cannot be
    /// hidden by an active include-all unit that happens to route its parent.
    pub(super) fn translates_subtree(&self, address: Address) -> bool {
        let topology = self.topology.borrow();
        let Some((_, present)) = topology
            .iter()
            .find(|(segment, _)| *segment == address.segment)
        else {
            return false;
        };
        let rid = requester(address);
        let Some((first, last)) = present
            .iter()
            .find(|entry| entry.rid == rid)
            .and_then(|entry| entry.bridge)
        else {
            return false;
        };
        if !self.amd.is_empty() {
            return (first..=last).all(|bus| {
                (0..=255u16).all(|function| {
                    self.amd(address.segment, u16::from(bus) << 8 | function)
                        .is_ok_and(|taken| taken.is_some())
                })
            });
        }
        let Some(dmar) = &self.dmar else {
            return false;
        };
        remapping::subtree_routes(dmar, address.segment, present, rid).is_some_and(|routes| {
            !routes.is_empty()
                && routes.iter().all(|descriptor| {
                    self.taken
                        .iter()
                        .any(|taken| taken.descriptor == *descriptor)
                })
        })
    }

    /// Admit a newly observed requester through its own firmware route.
    /// Initial blocked entries stay blocked until the driver's stopped receipt
    /// authorizes private attachment; parent coverage grants no child route.
    pub(super) fn admit(&self, address: Address) -> Result<(), VtdError> {
        let rid = requester(address);
        if let Some(taken) = self.amd(address.segment, rid)? {
            return taken.admit(rid).map_err(|error| {
                output::arguments(format_args!(
                    "HOST IOMMU AMD-Vi admission refused: {error:?}\n"
                ));
                VtdError::Busy
            });
        }
        self.vtd(address.segment, rid)?
            .map_or(Ok(()), |taken| taken.unit.admit_requester(rid))
    }

    /// The domain of its own for `binding`'s requester when a taken unit
    /// covers it; the binding back when none does.
    pub(super) fn domain(
        &self,
        binding: RequesterBinding,
    ) -> Result<Result<Arc<dyn DmaDomain>, VtdError>, RequesterBinding> {
        let segment = binding.address().segment;
        let rid = binding.requester();
        let amd = match self.amd(segment, rid) {
            Ok(taken) => taken,
            Err(error) => return Ok(Err(error)),
        };
        if let Some(taken) = amd {
            if !taken.covers(segment, rid) {
                return Ok(Err(VtdError::Unsupported));
            }
            return Ok(taken.domain(binding).map_err(|error| {
                output::arguments(format_args!(
                    "HOST IOMMU AMD-Vi attach refused: {error:?}\n"
                ));
                VtdError::Busy
            }));
        }
        let taken = match self.vtd(segment, rid) {
            Ok(Some(taken)) if taken.unit.allows(rid) => taken,
            Ok(Some(_)) | Err(_) => return Ok(Err(VtdError::Unsupported)),
            Ok(None) => return Err(binding),
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
