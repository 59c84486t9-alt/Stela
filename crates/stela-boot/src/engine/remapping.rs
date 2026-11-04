//! The host's DMA remapping units, VT-d's (DMAR) and AMD-Vi's (IVRS, in
//! [`amd`]), taken before the host drivers start
//! ([`stela_boot_core::remapping`] decides which). Intel requesters start
//! blocked unless the unit retains an RMRR-backed window. AMD-Vi units keep
//! their existing window policy. A driver that asks
//! the native services for a domain gets its own ([`Remappers::domain`]).
//!
//! The display functions a driver maps the firmware's reserved regions for
//! are a policy input: none yet, so a unit whose scope holds a display
//! controller is left untranslated until a display driver claims it.
mod amd;
mod preparation;

use super::storage::RestoreRoot;
use crate::{
    native_dma::{
        InactiveFirmwareUnits, dmar,
        firmware_state::Kind,
        requester::RequesterClaim,
        vtd::interrupt::DirectDelivery,
        vtd::{BlockedRequester, BoundRequester, InitialBlock, MmioRegisters, Unit, VtdError},
    },
    native_mmio, output,
};
use alloc::{sync::Arc, vec::Vec};
use core::ops::Range;
use stela_boot_core::remapping::{self, Present};
use stela_drivers::bus::{
    dma::{
        mapping::{DmaDomain, DmaError},
        memory::CacheAttribute,
    },
    mmio::owned::{Error as MappingError, PhysicalSpan, Protection},
    pci::{
        Address, ConfigError, ConfigFailure,
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
    initial: InitialContexts,
}

enum InitialContexts {
    Window,
    Blocked,
}

/// The drained initial cohorts of every original Intel DMA unit, paired
/// with the same MMIO source that contained the PCI functions. Line
/// controller and endpoint-engine retirement remain independent.
struct BlockedFabric {
    source: &'static native_mmio::Source,
    units: Vec<(usize, InitialBlock<MmioRegisters>)>,
}

impl BlockedFabric {
    /// Observe every original unit in the same direct-delivery epoch. The
    /// caller may hold the pins across a later IRQ handoff.
    ///
    /// # Safety
    /// The original Source is mapped on the owning process CPU and excludes
    /// register/reset writers. No native interrupt-format change is in flight.
    unsafe fn pin_direct_delivery(&self) -> Result<Vec<DirectDelivery<MmioRegisters>>, VtdError> {
        let mut pins = Vec::new();
        pins.try_reserve_exact(self.units.len())
            .map_err(|_| VtdError::Exhausted)?;
        for (_, cohort) in &self.units {
            // SAFETY: caller holds this exact mounted source and process root.
            pins.push(unsafe { cohort.pin_direct_delivery() }?);
        }
        for pin in &pins {
            // SAFETY: same mounted context. All original units remain pinned
            // until the complete cohort has been checked.
            unsafe { pin.check() }?;
        }
        Ok(pins)
    }

    fn requester(
        &self,
        source: &native_mmio::Source,
        descriptor: usize,
        rid: u16,
    ) -> Result<BlockedRequester<MmioRegisters>, DmaError> {
        if !core::ptr::eq(self.source, source) {
            return Err(DmaError::IommuUnavailable);
        }
        let (_, cohort) = self
            .units
            .iter()
            .find(|(index, _)| *index == descriptor)
            .ok_or(DmaError::IommuUnavailable)?;
        cohort.claim(rid)
    }
}

/// The units the mount translates for.
pub(super) struct Remappers {
    taken: Vec<Taken>,
    initial_fabric: Option<BlockedFabric>,
    initial_lines: Option<native_mmio::InitialPciLines>,
    requesters: core::cell::RefCell<Vec<BoundRequester<MmioRegisters>>>,
    amd: Vec<amd::Taken>,
    amd_fabric: Option<&'static native_mmio::Source>,
    amd_blocked: bool,
    roles: core::cell::RefCell<roles::Inventory>,
    topology: core::cell::RefCell<Vec<(u16, Vec<Present>)>>,
    dmar: Option<dmar::Remapping>,
}

#[derive(Clone, Copy)]
pub(super) enum PreparationError {
    Dma(DmaError),
    Interrupt(MappingError),
    Configuration(native_mmio::ContainmentError),
    AmdConfiguration,
}

impl From<DmaError> for PreparationError {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

fn address(segment: u16, rid: u16) -> Address {
    Address {
        segment,
        bus: (rid >> 8) as u8,
        device: (rid >> 3 & 31) as u8,
        function: (rid & 7) as u8,
    }
}

/// The requester ID of the function at `address`.
fn requester(address: Address) -> u16 {
    u16::from(address.bus) << 8 | u16::from(address.device) << 3 | u16::from(address.function)
}

impl Remappers {
    pub(super) fn has_blocked_fabric(&self) -> bool {
        self.initial_fabric.is_some() || self.amd_blocked
    }

    pub(super) const fn none() -> Self {
        Self {
            taken: Vec::new(),
            initial_fabric: None,
            initial_lines: None,
            requesters: core::cell::RefCell::new(Vec::new()),
            amd: Vec::new(),
            amd_fabric: None,
            amd_blocked: false,
            roles: core::cell::RefCell::new(roles::Inventory::empty()),
            topology: core::cell::RefCell::new(Vec::new()),
            dmar: None,
        }
    }

    /// Take the units of the firmware's DMAR the policy allows. A unit with
    /// retained USB reserved regions gets a window over those regions and
    /// `drivers`. Other units start blocked. Units the policy leaves and units
    /// that refuse are reported.
    ///
    /// # Safety
    /// No host driver has started. `root` is the loader root for the ACPI
    /// tables at `rsdp`, and firmware translation ended at ExitBootServices.
    /// PCI function, SR-IOV, reset and routing writers stay excluded through
    /// inventory and later claims. `pci` retains the same captured ECAM buses.
    pub(super) unsafe fn take(
        rsdp: u64,
        root: u64,
        drivers: Range<u64>,
        pci: &native_mmio::ContainedPci<'static>,
        inactive_firmware_units: &InactiveFirmwareUnits,
        tsc_hz: u64,
    ) -> Self {
        let mmio = pci.source();
        let mut remappers = Self::none();
        let (dmar, ivrs) = {
            // SAFETY: forwarded; the loader root maps the original tables.
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
            (find(b"DMAR"), find(b"IVRS"))
        };
        // SAFETY: the original source owns every captured bus and excludes
        // configuration writers throughout the complete topology/role census.
        let inventory = unsafe {
            mmio.with_config_inventory(|windows, reader| {
                let inventories =
                    remapping::try_enumerate_segments(windows, |window, rid, offset| {
                        let address = address(window.segment, rid);
                        let value = reader.read32(address, offset)?;
                        // The original containment census validated the
                        // bridge layout and bus route before sealing them.
                        if offset != 0 || value as u16 != u16::MAX {
                            pci.check_observation(address, offset, value)?;
                        }
                        Ok::<_, MappingError>(Some(value))
                    })?;
                let functions: Vec<_> = inventories
                    .iter()
                    .flat_map(|(segment, present)| {
                        present
                            .iter()
                            .map(|function| address(*segment, function.rid))
                    })
                    .collect();
                if functions.len() != pci.functions() {
                    return Err(MappingError::InvalidPlatformReply.into());
                }
                let roles = roles::Inventory::capture(&functions, |address, offset| {
                    reader
                        .read32(address, offset)
                        .map(Some)
                        .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))
                });
                pci.check_stopped(reader).map(|()| (inventories, roles))
            })
        };
        let (inventories, roles) = match inventory {
            Ok(inventory) => inventory,
            Err(error) => {
                output::arguments(format_args!(
                    "UNSUPPORTED Stela PCI topology inventory: {error:?}\n"
                ));
                return remappers;
            }
        };
        let roles = match roles {
            Ok(roles) => roles,
            Err(error) => {
                output::arguments(format_args!(
                    "UNSUPPORTED Stela PCI function-role inventory: {error:?}\n"
                ));
                return remappers;
            }
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
            let (units, blocked) = unsafe {
                amd::take(
                    &ivrs,
                    &inventories,
                    &drivers,
                    mmio,
                    dmar.is_none().then_some(inactive_firmware_units),
                    tsc_hz,
                    physical_bits(),
                )
            };
            remappers.amd = units;
            remappers.amd_blocked = blocked.is_some();
            if blocked == Some(true) {
                // SAFETY: no driver, AP or competing configuration writer
                // can change the original stopped PCI cohort during takeover.
                match unsafe { remappers.recheck_amd_stopped(pci) } {
                    Ok(()) => {
                        remappers.amd_fabric = Some(mmio);
                        output::arguments(format_args!(
                            "HOST IOMMU AMD-Vi blocked PCI fabric qualified: {} units\n",
                            remappers.amd.len()
                        ));
                    }
                    Err(error) => output::arguments(format_args!(
                        "HOST IOMMU AMD-Vi blocked PCI fabric changed: {error}\n"
                    )),
                }
            } else if blocked == Some(false) {
                output::arguments(format_args!(
                    "HOST IOMMU AMD-Vi blocked PCI fabric incomplete\n"
                ));
            }
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
        let mut cohorts = Vec::new();
        remappers.dmar = Some(parsed.clone());
        if cohorts.try_reserve_exact(parsed.units.len()).is_err()
            || remappers
                .taken
                .try_reserve_exact(parsed.units.len())
                .is_err()
        {
            output::arguments(format_args!(
                "HOST IOMMU VT-d inventory could not be retained\n"
            ));
            return remappers;
        }
        let mut covered = 0;
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
                let mut window = Vec::new();
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
                if !window.is_empty() {
                    window.push(drivers.clone());
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
                        let initial = if window.is_empty() {
                            // A blocked new root cannot qualify a previous
                            // firmware root that was disabled without a drain.
                            let result = if inactive_firmware_units.contains(
                                Kind::Vtd,
                                unit.segment,
                                unit.base,
                            ) {
                                taken.acknowledge_initial_block(&requesters)
                            } else {
                                Err(DmaError::DrainUnavailable)
                            };
                            match result {
                                Ok(cohort) => {
                                    covered += requesters.len();
                                    cohorts.push((index, cohort));
                                    output::arguments(format_args!(
                                        "HOST IOMMU VT-d unit {:#x} blocked and drained {} initial requesters\n",
                                        unit.base,
                                        requesters.len()
                                    ));
                                }
                                Err(error) => output::arguments(format_args!(
                                    "HOST IOMMU VT-d unit {:#x} blocked cohort not qualified: {error:?}\n",
                                    unit.base
                                )),
                            }
                            InitialContexts::Blocked
                        } else {
                            output::arguments(format_args!(
                                "HOST IOMMU VT-d unit {:#x} retains a reserved window for {} requesters\n",
                                unit.base,
                                requesters.len()
                            ));
                            InitialContexts::Window
                        };
                        remappers.taken.push(Taken {
                            descriptor: index,
                            unit: taken,
                            initial,
                        });
                    }
                    Err(error) => output::arguments(format_args!(
                        "HOST IOMMU VT-d unit {:#x} left untranslated: {error:?}\n",
                        unit.base
                    )),
                }
            }
        }
        // The planner deduplicates RIDs inside each unit and refuses
        // overlaps between units. A full count therefore requires each
        // function from the independently checked PCI census exactly once.
        if !cohorts.is_empty()
            && cohorts.len() == parsed.units.len()
            && inactive_firmware_units.matches_dmar(&parsed.units)
            && covered == pci.functions()
        {
            // SAFETY: no PCI driver, controller or AP can write configuration
            // between the original census and this post-drain readback.
            if let Err(error) = unsafe { pci.recheck_stopped() } {
                output::arguments(format_args!(
                    "HOST IOMMU VT-d blocked PCI fabric changed after drain: {error}\n"
                ));
                return remappers;
            }
            let fabric = BlockedFabric {
                source: mmio,
                units: cohorts,
            };
            // SAFETY: same original exclusive mount context as unit takeover.
            // This startup check publishes no IRQ route. The pins release
            // before later independent IRQ-mode selection.
            match unsafe { fabric.pin_direct_delivery() } {
                Ok(pins) => {
                    drop(pins);
                    remappers.initial_fabric = Some(fabric);
                    output::arguments(format_args!(
                        "HOST IOMMU VT-d blocked PCI fabric qualified: {} units, {covered} functions\n",
                        parsed.units.len()
                    ));
                }
                Err(error) => output::arguments(format_args!(
                    "HOST IOMMU VT-d initial interrupt mode refused: {error:?}\n"
                )),
            }
        } else if !parsed.units.is_empty() {
            output::arguments(format_args!(
                "HOST IOMMU VT-d blocked PCI fabric incomplete: {}/{} units, {covered}/{} functions\n",
                cohorts.len(),
                parsed.units.len(),
                pci.functions()
            ));
        }
        remappers
    }

    /// # Safety
    /// Whole native IOAPIC ownership was explicitly handed off. The captured
    /// platform and every current DMA/IRQ mode writer stay exclusive.
    pub(super) unsafe fn install_ioapics(
        &mut self,
        pci: &native_mmio::ContainedPci<'static>,
    ) -> Result<usize, MappingError> {
        let source = pci.source();
        let modes = if let Some(fabric) = self
            .initial_fabric
            .as_ref()
            .filter(|fabric| core::ptr::eq(fabric.source, source))
        {
            // SAFETY: original complete Intel unit cohort and live root.
            unsafe { fabric.pin_direct_delivery() }
                .map_err(|error| {
                    output::arguments(format_args!("HOST IOAPIC direct mode refused: {error:?}\n"));
                    MappingError::Unavailable
                })?
                .into_iter()
                .map(native_mmio::ModePin::Intel)
                .collect()
        } else if self
            .amd_fabric
            .is_some_and(|amd| core::ptr::eq(amd, source))
        {
            self.amd
                .iter()
                .map(|unit| {
                    unit.pin_direct_delivery()
                        .map(native_mmio::ModePin::Amd)
                        .map_err(|error| {
                            output::arguments(format_args!(
                                "HOST IOAPIC AMD-Vi direct mode refused: {error:?}\n"
                            ));
                            MappingError::Unavailable
                        })
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            return Err(MappingError::Unavailable);
        };
        // SAFETY: forwarded controller handoff and complete original modes.
        let count = unsafe { source.install_ioapics(modes) }?;
        match source.initial_pci_lines() {
            Ok(lines) => {
                self.initial_lines = Some(lines);
                output::arguments(format_args!("HOST PCI initial interrupt paths contained\n"));
            }
            Err(error) => output::arguments(format_args!(
                "HOST PCI initial interrupt containment unavailable: {error:?}\n"
            )),
        }
        Ok(count)
    }

    fn initial_requester(
        &self,
        source: &native_mmio::Source,
        taken: &Taken,
        rid: u16,
    ) -> Result<Option<BlockedRequester<MmioRegisters>>, DmaError> {
        match taken.initial {
            InitialContexts::Window => Ok(None),
            InitialContexts::Blocked => self
                .initial_fabric
                .as_ref()
                .ok_or(DmaError::DrainUnavailable)?
                .requester(source, taken.descriptor, rid)
                .map(Some),
        }
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
        // SAFETY: the unit's exclusive uncached register window is mapped
        // through this boot's shared aperture.
        let registers =
            unsafe { MmioRegisters::from_mapping(mapping, crate::apic::rdtsc, tsc_hz.max(1)) }?;
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
    /// A routed but untaken unit supplies no requester-domain grant, even
    /// when the parent bridge uses a different taken unit.
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
        selected
            .map(|descriptor| {
                self.taken
                    .iter()
                    .find(|taken| taken.descriptor == descriptor)
                    .ok_or(VtdError::Unsupported)
            })
            .transpose()
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
        read32: &mut dyn FnMut(Address, u16) -> Result<Option<u32>, ConfigError>,
    ) -> Result<bool, ConfigError> {
        let fresh = roles::Inventory::capture(functions, &mut *read32).inspect_err(|_| {
            self.roles.borrow_mut().invalidate_topology(bridge);
        })?;
        let mut updates = Vec::with_capacity(functions.len() + 1);
        for address in core::iter::once(bridge).chain(functions.iter().copied()) {
            let observation = (|| {
                let read = |value: Option<u32>| value.filter(|value| *value != u32::MAX);
                let Some(class) = read(read32(address, 8)?) else {
                    return Ok(None);
                };
                let Some(header) = read(read32(address, 12)?) else {
                    return Ok(None);
                };
                let buses = if header >> 16 & 0x7f == 1 {
                    let Some(buses) = read(read32(address, 24)?) else {
                        return Ok(None);
                    };
                    let secondary = (buses >> 8) as u8;
                    let subordinate = (buses >> 16) as u8;
                    if secondary <= address.bus || subordinate < secondary {
                        return Ok(None);
                    }
                    Some((secondary, subordinate))
                } else {
                    None
                };
                Ok(Some(Present {
                    rid: requester(address),
                    class: [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
                    bridge: buses,
                }))
            })();
            match observation {
                Ok(Some(observation)) => updates.push(observation),
                Ok(None) => {
                    self.roles.borrow_mut().invalidate_topology(address);
                    return Ok(false);
                }
                Err(error) => {
                    self.roles.borrow_mut().invalidate_topology(address);
                    return Err(error);
                }
            }
        }
        let mut topology = self.topology.borrow_mut();
        let Some((_, present)) = topology
            .iter_mut()
            .find(|(segment, _)| *segment == bridge.segment)
        else {
            self.roles.borrow_mut().invalidate_topology(bridge);
            return Ok(false);
        };
        if !present
            .iter()
            .any(|entry| entry.rid == requester(bridge) && entry.class[..2] == [6, 4])
            || updates[0].class[..2] != [6, 4]
            || updates[0].bridge.is_none()
        {
            self.roles.borrow_mut().invalidate_topology(bridge);
            return Ok(false);
        }
        if updates.iter().any(|update| {
            present
                .iter()
                .any(|entry| entry.rid == update.rid && entry.class != update.class)
        }) {
            self.roles.borrow_mut().invalidate_topology(bridge);
            return Ok(false);
        }
        for update in updates {
            if let Some(entry) = present.iter_mut().find(|entry| entry.rid == update.rid) {
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
        Ok(functions
            .iter()
            .all(|address| roles.role(*address) != FunctionRole::Unverified))
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
        source: &native_mmio::Source,
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
        let claim = match unsafe { RequesterClaim::from_binding(binding) } {
            Ok(claim) => claim,
            Err((error, binding)) => {
                // A failed epoch check returns the SAME retained binding.
                // Refusal cannot authorize releasing its original graph.
                let _kept = core::mem::ManuallyDrop::new(alloc::boxed::Box::new(
                    core::mem::ManuallyDrop::new(binding),
                ));
                return Ok(Err(error));
            }
        };
        let initial = self
            .initial_requester(source, taken, rid)
            .and_then(|blocked| blocked.map_or(Ok(()), |requester| requester.drain()));
        if let Err(error) = initial {
            output::arguments(format_args!(
                "HOST IOMMU VT-d requester {rid:#06x} initial handoff refused: {error:?}\n"
            ));
            let _kept = core::mem::ManuallyDrop::new(claim);
            return Ok(Err(match error {
                DmaError::InvalidationFailed => VtdError::Invalidation,
                _ => VtdError::Unsupported,
            }));
        }
        // SAFETY: the same checked stopped claim and original unit remain held.
        let owner = match unsafe { taken.unit.attach_requester(claim) } {
            Ok(owner) => owner,
            Err(failure) => return Ok(Err(failure.error)),
        };
        let domain = owner.domain();
        // The serialized service keeps affine config custody. The returned
        // DMA projection contains no command/configuration callback.
        self.requesters.borrow_mut().push(owner);
        Ok(Ok(domain as Arc<dyn DmaDomain>))
    }
}
