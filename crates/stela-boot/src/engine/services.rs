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
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use stela_boot_core::passthrough::Passthrough;
use stela_drivers::{
    bus::{
        dma::{mapping::DmaDomain, memory::PageSource},
        mmio::owned::{self, CacheAttribute, Mapping, PhysicalSpan, Protection},
        pci::{
            Address, Bar, ConfigSpace, Function,
            owned::OwnedConfig,
            requester::{FunctionRole, RequesterBinding, StoppedRequester},
        },
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
/// PCIe Device Control's Enable No Snoop, and Device Status's Transactions
/// Pending (PCIe Base 6.0 7.5.3.4, 7.5.3.5).
const NO_SNOOP: u16 = 1 << 11;
const TRANSACTIONS_PENDING: u16 = 1 << 5;

/// Whether a passthrough domain was handed out, which is reported once.
static PASSTHROUGH_REPORTED: AtomicBool = AtomicBool::new(false);

pub(super) struct Services<'a> {
    mmio: &'a native_mmio::Source,
    remappers: &'a super::remapping::Remappers,
    acpi: Option<&'static HostAcpi>,
    heap: core::ops::Range<u64>,
    tsc_hz: u64,
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

    /// Stop the function's DMA and interrupts, as Linux's
    /// `pci_clear_master`, `pci_msi_shutdown`, `pci_msix_shutdown` and
    /// `pci_disable_ats`/`pri`/`pasid` do, then wait for its outstanding
    /// requests (`pci_wait_for_pending_transaction`).
    fn stop(&self, config: &mut OwnedConfig) {
        let command = config.read16(COMMAND);
        config.write16(COMMAND, command & !BUS_MASTER | INTX_DISABLE);
        let mut express = None;
        if config.read16(STATUS) & CAPABILITY_LIST != 0 {
            let found: alloc::vec::Vec<_> = config
                .capabilities()
                .filter_map(Result::ok)
                .map(|entry| (entry.offset, entry.id))
                .collect();
            for (offset, id) in found {
                match id {
                    MSI => {
                        let control = config.read16(offset + 2);
                        config.write16(offset + 2, control & !1);
                    }
                    MSIX => {
                        let control = config.read16(offset + 2);
                        config.write16(offset + 2, control & !(1 << 15));
                    }
                    PCIE => {
                        let control = config.read16(offset + 8);
                        config.write16(offset + 8, control & !NO_SNOOP);
                        express = Some(offset);
                    }
                    _ => {}
                }
            }
        }
        if express.is_some() && config.read32(0x100) != u32::MAX {
            let found: alloc::vec::Vec<_> = config
                .extended_capabilities()
                .filter_map(Result::ok)
                .map(|entry| (entry.offset, entry.id))
                .collect();
            for (offset, id) in found {
                match id {
                    ATS => {
                        let control = config.read16(offset + 6);
                        config.write16(offset + 6, control & !(1 << 15));
                    }
                    PASID => {
                        let control = config.read16(offset + 6);
                        config.write16(offset + 6, control & !1);
                    }
                    PRI => {
                        let control = config.read16(offset + 4);
                        config.write16(offset + 4, control & !1);
                    }
                    _ => {}
                }
            }
        }
        if let Some(offset) = express {
            // Linux waits up to 60 ms in 1, 2, 4 ... ms steps; one bounded
            // wait does the same.
            let start = super::host::rdtsc();
            let limit = self.tsc_hz / 1000 * 64;
            while config.read16(offset + 10) & TRANSACTIONS_PENDING != 0
                && super::host::rdtsc().wrapping_sub(start) < limit
            {
                core::hint::spin_loop();
            }
        }
    }
}

// SAFETY: each claimed function's configuration page and each BAR is mapped
// once through the owned aperture, which every host processor and engine
// root reaches; a claimed function is stopped before `from_stopped_pci`
// checks it. Every domain is the passthrough domain, which is what the
// requesters have with the remapping units off. The ACPI namespace is
// offered only with the i8042's interrupts masked.
unsafe impl NativeServices for Services<'_> {
    fn entropy(&self) -> Result<Arc<dyn stela_drivers::entropy::Entropy>, ServiceError> {
        crate::random::source()
    }

    fn claim_stopped(&self, address: Address) -> Result<StoppedRequester, ServiceError> {
        let mut config = self.config(address)?;
        self.stop(&mut config);
        let function = Function::new(address, config)
            .ok_or(ServiceError::Refused("no function answers at this address"))?;
        // SAFETY: bus mastering, interrupts and outstanding requests were
        // stopped above; probe enumerates physical functions only.
        unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) }
            .map_err(|(error, _)| ServiceError::Claim(error))
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
}
