//! The host drivers' native services ([`NativeServices`]): configuration
//! space and BAR mappings through the owned MMIO aperture
//! ([`native_mmio::Source`]), DMA pages from the native allocator, DMA
//! domains, and the firmware's ACPI namespace.
//!
//! Remapping units cover each discovered requester with the driver's DMA
//! window before probe starts devices. A claimed requester receives its own
//! domain. Hosts without an active remapper use a passthrough domain and
//! report unrestricted DMA once.
use super::aml::HostAcpi;
use crate::{native_memory, native_mmio, output};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use stela_boot_core::passthrough::Passthrough;
use stela_drivers::{
    bus::{
        dma::{mapping::DmaDomain, memory::PageSource},
        mmio::owned::{self, CacheAttribute, Mapping, PhysicalSpan, Protection},
        pci::{
            Address, Bar, ConfigSpace, Function, FunctionError,
            owned::OwnedConfig,
            requester::{ClaimError, FunctionRole, RequesterBinding, StoppedRequester},
        },
        thunderbolt::manager::{Platform, Uuid},
    },
    platform::acpi::resources::{self, DeviceResources, MemoryBroker, Resource, Space},
    probe::{NativeServices, ServiceError},
};

const FUNCTION_BYTES: usize = 4096;
const COMMAND: u16 = 4;
const BUS_MASTER: u16 = 1 << 2;
const INTX_DISABLE: u16 = 1 << 10;
const STATUS: u16 = 6;
const CAPABILITY_LIST: u16 = 1 << 4;
const MSI: u8 = 5;
const PCIE: u8 = 0x10;
const MSIX: u8 = 0x11;
const ATS: u16 = 0xf;
const PRI: u16 = 0x13;
const PASID: u16 = 0x1b;
/// PCIe Device Control's Enable No Snoop (PCIe Base 6.0, 7.5.3.4).
const NO_SNOOP: u16 = 1 << 11;

/// Whether a passthrough domain was handed out, which is reported once.
static PASSTHROUGH_REPORTED: AtomicBool = AtomicBool::new(false);

pub(super) struct Services<'a> {
    mmio: &'a native_mmio::Source,
    remappers: &'a super::remapping::Remappers,
    acpi: Option<&'static HostAcpi>,
    heap: core::ops::Range<u64>,
    tsc_hz: u64,
    /// The USB4 devices `--usb4-approve` lists.
    usb4_approved: Vec<Uuid>,
    /// A broker for each register window [`NativeServices::acpi_memory`]
    /// reserved, with the window: one device's `_CRS` memory rounded to
    /// pages, which only that broker suballocates.
    brokers: core::cell::RefCell<alloc::vec::Vec<(PhysicalSpan, MemoryBroker)>>,
}

const PAGE: u64 = 4096;

/// The pages memory descriptor `ordinal` of `device` covers, rounded as
/// [`MemoryBroker::reserve`] rounds it.
fn acpi_pages(device: &DeviceResources<'_>, ordinal: usize) -> Option<PhysicalSpan> {
    let Some(Resource::Address(address)) = device
        .descriptors()
        .get(ordinal)
        .map(|descriptor| &descriptor.resource)
    else {
        return None;
    };
    if address.space != Space::Memory || address.length == 0 {
        return None;
    }
    let start = address.minimum & !(PAGE - 1);
    let end = address
        .minimum
        .checked_add(address.length)?
        .checked_add(PAGE - 1)?
        & !(PAGE - 1);
    PhysicalSpan::new(start, end - start).ok()
}

/// A broker refusal as a service refusal.
fn broker_refusal(error: resources::Error) -> ServiceError {
    ServiceError::Refused(match error {
        resources::Error::Conflict => "ACPI memory overlaps a reservation",
        resources::Error::OutsideReservation => "ACPI memory outside its reserved window",
        resources::Error::Unassigned => "ACPI memory resource is not a fixed consumer range",
        resources::Error::ResourceChanged => "ACPI resources changed",
        _ => "ACPI resources could not be read",
    })
}

/// The i8042's interrupts (ISA IRQ 1 and 12), masked while probe owns the
/// controller through the ACPI namespace.
const I8042_IRQS: [u8; 2] = [1, 12];

impl<'a> Services<'a> {
    /// Services over `mmio` and `acpi`, whose DMA domains admit the native
    /// allocator's pages at `heap`. The ACPI namespace is offered only once
    /// the i8042's interrupts are masked, as its port grant requires.
    pub(super) fn new(
        mmio: &'a native_mmio::Source,
        remappers: &'a super::remapping::Remappers,
        acpi: Option<&'static HostAcpi>,
        heap: core::ops::Range<u64>,
        tsc_hz: u64,
        usb4_approved: Vec<Uuid>,
    ) -> Self {
        // SAFETY: the engine programs no PIC or I/O APIC pin of its own.
        let acpi = acpi.filter(|_| match unsafe { mmio.mask_isa(&I8042_IRQS) } {
            Ok(()) => true,
            Err(error) => {
                output::arguments(format_args!(
                    "HOST ACPI devices left out: the i8042 interrupts could not be masked ({error:?})\n"
                ));
                false
            }
        });
        Self {
            mmio,
            remappers,
            acpi,
            heap,
            tsc_hz,
            usb4_approved,
            brokers: core::cell::RefCell::new(alloc::vec::Vec::new()),
        }
    }

    fn config(&self, address: Address) -> Result<OwnedConfig, ServiceError> {
        // SAFETY: probe owns every function it asks for, and the bus's
        // other functions are probe's too.
        let (window, resource) = unsafe { self.mmio.claim_bus(address.segment, address.bus) }
            .map_err(ServiceError::Mapping)?;
        let offset = usize::from(address.device) << 15 | usize::from(address.function) << 12;
        let mapping = self
            .mmio
            .authority()
            .map(
                resource,
                offset,
                FUNCTION_BYTES,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(ServiceError::Mapping)?;
        // SAFETY: the mapping is the function's own configuration page in
        // the claimed bus, which only this owner reaches.
        unsafe { OwnedConfig::attach(address, window, mapping) }
            .map_err(|_| ServiceError::Refused("configuration space mapping refused"))
    }

    fn function(&self, address: Address) -> Result<Function<OwnedConfig>, ServiceError> {
        Function::new(address, self.config(address)?).map_err(|refusal| match refusal.reason {
            FunctionError::Absent => ServiceError::Refused("no function answers at this address"),
            FunctionError::ConfigurationRetry => {
                ServiceError::Refused("PCI function requests configuration retry")
            }
            FunctionError::Access(error) => ServiceError::Config(error),
        })
    }

    /// Gate PCI requester DMA and interrupt controls, then wait for its
    /// outstanding requests. A failed access ends the sequence immediately.
    fn stop(&self, config: &mut OwnedConfig) -> Result<(), ClaimError> {
        let command = read_control(config, COMMAND)?;
        let status = read_control(config, STATUS)?;
        config.write16(COMMAND, command & !BUS_MASTER | INTX_DISABLE)?;
        let mut express = false;
        if status & CAPABILITY_LIST != 0 {
            let found: Vec<_> = config.capabilities().collect::<Result<_, _>>()?;
            for entry in found {
                let (offset, mask) = match entry.id {
                    MSI => (entry.offset + 2, 1),
                    MSIX => (entry.offset + 2, 1 << 15),
                    PCIE => {
                        express = true;
                        (entry.offset + 8, NO_SNOOP)
                    }
                    _ => continue,
                };
                let control = read_control(config, offset)?;
                config.write16(offset, control & !mask)?;
            }
        }
        if express && config.read32(0x100)? != u32::MAX {
            let found: Vec<_> = config.extended_capabilities().collect::<Result<_, _>>()?;
            for entry in found {
                let (offset, mask) = match entry.id {
                    ATS => (entry.offset + 6, 1 << 15),
                    PASID => (entry.offset + 6, 1),
                    PRI => (entry.offset + 4, 1),
                    _ => continue,
                };
                let control = read_control(config, offset)?;
                config.write16(offset, control & !mask)?;
            }
        }
        // A bounded wait must refuse an endpoint that still has requests in
        // flight. Bus-master gating alone is not completion of those requests.
        let start = super::host::rdtsc();
        let limit = (self.tsc_hz / 1000 * 64).max(1);
        stela_drivers::bus::pci::requester::wait_for_pending_transactions(config, || {
            super::host::rdtsc().wrapping_sub(start) >= limit
        })
    }
}

fn read_control(config: &OwnedConfig, offset: u16) -> Result<u16, ClaimError> {
    let value = config.read16(offset)?;
    if value == u16::MAX {
        return Err(ClaimError::ReadFailed { offset });
    }
    Ok(value)
}

// SAFETY: each claimed function's or bridge's configuration page and each BAR
// is mapped once through the owned aperture, which every host processor and engine
// root reaches; a claimed function is stopped before `from_stopped_pci`
// checks it. The bound domain keeps its translation/configuration epoch;
// an unavailable remapper is reported as passthrough. The ACPI namespace is
// offered only with the i8042's interrupts masked; ring 0 reaches the i8042's
// and each claimed i801's ports, which nothing else here uses. Firmware
// memory is the AML provider's own mapping of RAM the map leaves to firmware.
unsafe impl NativeServices for Services<'_> {
    fn embedded_controller(
        &self,
    ) -> Result<Option<stela_drivers::platform::ec::capability::Installed<'static>>, ServiceError>
    {
        self.acpi.map_or(Ok(None), HostAcpi::embedded_controller)
    }
    fn entropy(&self) -> Result<Arc<dyn stela_drivers::entropy::Entropy>, ServiceError> {
        crate::random::source()
    }

    fn prepare_requester(
        &self,
        address: Address,
    ) -> Result<stela_drivers::bus::pci::requester::preparation::PreparingRequester, ServiceError>
    {
        use stela_drivers::bus::pci::requester::preparation::PreparingRequester;
        let role = self.remappers.function_role(address);
        if role != FunctionRole::Physical {
            return Err(ServiceError::Claim(ClaimError::UnsupportedRole(role)));
        }
        let root = self.remappers.preparation(address).map_err(|error| {
            output::arguments(format_args!("UNSUPPORTED Stela cold requester {address}: original DMA drain unavailable ({error:?})\n"));
            ServiceError::Refused("cold requester original DMA drain unavailable")
        })?;
        let mut function = self.function(address)?;
        self.stop(function.config()).map_err(ServiceError::Claim)?;
        // SAFETY: first serialized post-EBS attach through the original owned
        // configuration and selected root. The platform keeps the initial DMA
        // backing, excludes prior firmware/IRQ/work and competing PCI writers,
        // and admits snooped WB DMA. Complete stable inventory supplies role.
        // PCI containment here grants no endpoint engine stop or payload drain;
        // the owning driver must produce that receipt with BARs still kept.
        unsafe { PreparingRequester::new(function, role, root) }
            .map_err(|rejected| ServiceError::Claim(rejected.error))
    }

    fn claim_stopped(&self, address: Address) -> Result<StoppedRequester, ServiceError> {
        let role = self.remappers.function_role(address);
        if role != FunctionRole::Physical {
            return Err(ServiceError::Claim(
                stela_drivers::bus::pci::requester::ClaimError::UnsupportedRole(role),
            ));
        }
        let mut function = self.function(address)?;
        self.stop(function.config()).map_err(ServiceError::Claim)?;
        // SAFETY: bus mastering, interrupts and outstanding requests were
        // stopped above; the complete stable PF/VF inventory supplies role.
        unsafe { StoppedRequester::from_stopped_pci(function, role) }
            .map_err(|(error, _)| ServiceError::Claim(error))
    }

    fn bridge(&self, address: Address) -> Result<Function<OwnedConfig>, ServiceError> {
        let bridge = self.function(address)?;
        if bridge.class[..2] != [6, 4] {
            return Err(ServiceError::Refused("not a PCI-to-PCI bridge"));
        }
        Ok(bridge)
    }

    fn map_bar(&self, address: Address, bar: Bar) -> Result<Mapping, ServiceError> {
        let resource = self.bar_resource(address, bar)?;
        let bytes = usize::try_from(resource.physical_span().bytes())
            .map_err(|_| ServiceError::Refused("BAR too large"))?;
        self.mmio
            .authority()
            .map(
                resource,
                0,
                bytes,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(ServiceError::Mapping)
    }

    fn bar_resource(&self, address: Address, bar: Bar) -> Result<owned::Resource, ServiceError> {
        let Bar::Memory {
            address: base,
            size,
            prefetchable,
            ..
        } = bar
        else {
            return Err(ServiceError::Refused("an I/O BAR has no mapping"));
        };
        // SAFETY: the function's driver owns the BAR it asks for.
        unsafe {
            self.mmio
                .claim_bar(address.segment, base, size, prefetchable)
        }
        .map_err(ServiceError::Mapping)
    }

    fn authority(&self) -> Result<owned::Authority, ServiceError> {
        Ok(self.mmio.authority().clone())
    }

    fn domain(&self, binding: RequesterBinding) -> Result<Arc<dyn DmaDomain>, ServiceError> {
        let address = binding.address();
        let binding = match self.remappers.domain(binding) {
            Ok(domain) => {
                return domain.map_err(|error| {
                    output::arguments(format_args!(
                        "HOST IOMMU domain for {address:?} refused: {error:?}\n"
                    ));
                    ServiceError::Refused("the IOMMU refused the requester's domain")
                });
            }
            Err(binding) => binding,
        };
        if !PASSTHROUGH_REPORTED.swap(true, Ordering::Relaxed) {
            output::arguments(format_args!("no IOMMU: device DMA unrestricted\n"));
        }
        Ok(Arc::new(Passthrough::retaining(self.heap.clone(), binding)))
    }

    fn dma_translated(&self, address: Address) -> bool {
        self.remappers.translates(address)
    }

    fn dma_subtree_translated(&self, address: Address) -> bool {
        self.remappers.translates_subtree(address)
    }

    unsafe fn requesters_arrived(
        &self,
        arrivals: stela_drivers::probe::services::ArrivalInventory<'_>,
    ) -> Result<(), ServiceError> {
        if arrivals
            .functions
            .iter()
            .any(|address| address.segment != arrivals.bridge.segment)
            || !self
                .remappers
                .observe_arrivals(arrivals.bridge, arrivals.functions, arrivals.read32)
                .map_err(ServiceError::Config)?
        {
            return Err(ServiceError::Refused(
                "PCI arrival has no stable complete PF/VF inventory",
            ));
        }
        for &address in arrivals.functions {
            self.remappers.admit(address).map_err(|error| {
                output::arguments(format_args!(
                    "HOST IOMMU requester {address} refused: {error:?}\n"
                ));
                ServiceError::Refused("the IOMMU refused the requester that arrived")
            })?;
        }
        Ok(())
    }

    fn usb4_platform(
        &self,
        location: &str,
        isolated: bool,
    ) -> Result<Box<dyn Platform + Send>, ServiceError> {
        Ok(Box::new(super::usb::Usb4Platform::new(
            location,
            isolated,
            self.usb4_approved.clone(),
            self.tsc_hz,
        )))
    }

    fn pages(&self) -> &'static dyn PageSource {
        &native_memory::SOURCE
    }

    fn interrupts(
        &self,
    ) -> Result<&'static dyn stela_drivers::bus::irq::IrqController, ServiceError> {
        crate::native_irq::service().map_err(|_| ServiceError::Unavailable)
    }

    fn acpi_memory(
        &self,
        device: &DeviceResources<'_>,
        ordinal: usize,
    ) -> Result<owned::Resource, ServiceError> {
        if self.acpi.is_none() {
            return Err(ServiceError::Unavailable);
        }
        let pages = acpi_pages(device, ordinal)
            .ok_or(ServiceError::Refused("no memory resource at that ordinal"))?;
        let mut brokers = self.brokers.borrow_mut();
        let at = match brokers
            .iter()
            .position(|(window, _)| window.start() <= pages.start() && pages.end() <= window.end())
        {
            Some(at) => at,
            None => {
                // SAFETY: probe owns the device whose `_CRS` names the span.
                let root =
                    unsafe { self.mmio.claim_platform(pages) }.map_err(ServiceError::Mapping)?;
                // SAFETY: the broker is the only suballocator of the window,
                // which the aperture reserved outside RAM after EBS.
                let broker =
                    unsafe { MemoryBroker::new(alloc::vec![root]) }.map_err(broker_refusal)?;
                brokers.push((pages, broker));
                brokers.len() - 1
            }
        };
        brokers[at]
            .1
            .reserve(device, ordinal)
            .map(|reservation| reservation.resource().clone())
            .map_err(broker_refusal)
    }

    fn acpi(&self) -> Option<&'static stela_drivers::platform::acpi::Session> {
        self.acpi.map(HostAcpi::session)
    }

    fn firmware_memory(
        &self,
        physical: u64,
        bytes: usize,
    ) -> Result<core::ptr::NonNull<u8>, ServiceError> {
        let acpi = self.acpi.ok_or(ServiceError::Unavailable)?;
        let end = physical
            .checked_add(bytes as u64)
            .filter(|_| bytes != 0)
            .ok_or(ServiceError::Refused(
                "firmware memory range is empty or wraps",
            ))?;
        if !self.mmio.firmware_owned(physical, end) {
            return Err(ServiceError::Refused(
                "firmware memory overlaps RAM the host allocates",
            ));
        }
        acpi.firmware_memory(physical, bytes as u64)
            .ok_or(ServiceError::Refused(
                "firmware memory lies beyond the identity map",
            ))
    }
}
