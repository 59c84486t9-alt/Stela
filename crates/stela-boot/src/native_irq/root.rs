//! External interrupt resources joined to the actual native mapping and CPU
//! owners. MADT and _CRS describe routes; neither can create an MMIO lease or
//! establish ownership of the devices sharing a physical line.
use super::{NativePlatform, ioapic, madt};
use crate::native_clock::ProcessScope;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    marker::PhantomData,
    mem::ManuallyDrop,
    sync::atomic::{AtomicU64, Ordering},
};
use sha2::Digest;
use stela_crypto::Sha256;
use stela_drivers::{
    bus::{
        irq::{IrqError, LineRoute, Platform},
        mmio::owned::{self, Authority, CacheAttribute, Mapping, PhysicalSpan, Protection},
    },
    platform::{
        acpi::resources::{self, DeviceResources},
        work::{Cpu, WorkError},
    },
};

#[derive(Debug)]
pub(crate) enum Error {
    Irq(IrqError),
    Mapping(owned::Error),
    Route(madt::RouteError),
    Resource(resources::Error),
    Cpu(WorkError),
}
static QUARANTINED_MAPPINGS: AtomicU64 = AtomicU64::new(0);
pub(crate) fn quarantined_mappings() -> u64 {
    QUARANTINED_MAPPINGS.load(Ordering::Relaxed)
}
fn quarantine_mapping() {
    let _ = QUARANTINED_MAPPINGS.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
}

/// A concrete installed mapping retained by the IOAPIC unit, including every
/// active or quarantined pin. Raw accesses never re-enter the mapping service
/// (whose address checks and locks require process context) from a hard IRQ.
pub(crate) struct Registers {
    mapping: ManuallyDrop<Mapping>,
    cpu: ManuallyDrop<Arc<dyn Cpu>>,
    scope: ManuallyDrop<Arc<ProcessScope>>,
    mmio: ioapic::Mmio,
}
// SAFETY: only Root constructs this adapter from the actual exclusive UC lease.
// Unit serializes the selector/window with actual same-CPU IRQ exclusion. The
// mapping and native CPU/root lease outlive all raw MMIO accesses and quarantine.
unsafe impl ioapic::Registers for Registers {
    fn read(&self, index: u8) -> u32 {
        ioapic::Registers::read(&self.mmio, index)
    }
    fn write(&self, index: u8, value: u32) {
        ioapic::Registers::write(&self.mmio, index, value);
    }
}
impl Drop for Registers {
    fn drop(&mut self) {
        if self.scope.check().is_err() || self.cpu.in_interrupt() {
            // Preserve the actual mapping AND CPU/root owner on an invalid
            // final-release context. No affine resource is destroyed here.
            quarantine_mapping();
            return;
        }
        // SAFETY: this is the last Unit reference. A programmed Pin retains
        // Unit until complete registry/RemoteIRR/work retirement; a failed or
        // abandoned Pin permanently retains it. No register user remains.
        if unsafe { self.mapping.retire() }.is_err() {
            quarantine_mapping();
            // SAFETY: Process context is qualified. Mapping::drop records native
            // quarantine while retaining its actual resource/table provider;
            // keep the separate descriptor/CPU lease pinned as well.
            unsafe { ManuallyDrop::drop(&mut self.mapping) };
            return;
        }
        // SAFETY: each field is dropped once, here, and never used again.
        unsafe {
            ManuallyDrop::drop(&mut self.mapping);
            ManuallyDrop::drop(&mut self.cpu);
            ManuallyDrop::drop(&mut self.scope);
        }
    }
}
type Unit = ioapic::Unit<Registers, NativePlatform>;
pub(crate) type Source = ioapic::Pin<Registers, NativePlatform>;

/// One actual complete MADT unit inventory. The original Authority supplies
/// registered exclusive resources and all-root UC mapping acknowledgements;
/// this layer never registers an address from a firmware descriptor as owned.
pub(crate) struct Root {
    routing: madt::Routing,
    units: Vec<(madt::Unit, Arc<Unit>)>,
    spans: Vec<(madt::Unit, u16)>,
    cpu: Arc<dyn Cpu>,
    scope: Arc<ProcessScope>,
    madt: &'static [u8],
    madt_hash: [u8; 32],
    _local: PhantomData<*mut ()>,
}
impl Root {
    /// Original process/deferred CPU view, including actual IRQ metadata.
    /// Its process-context save/check intentionally refuses a guest shadow CR3.
    pub(crate) fn cpu(&self) -> Arc<dyn Cpu> {
        self.cpu.clone()
    }

    /// Build a contributor's all-root, actual IRQ-save guard in process
    /// context. The permanent native registry retains its original typed
    /// APIC/IDT/GS/root adapter; no CPU or vector grant is reconstructed.
    pub(crate) fn irq_platform(&self) -> Result<Arc<dyn Platform>, Error> {
        self.scope.check().map_err(Error::Cpu)?;
        if self.cpu.in_interrupt() {
            return Err(Error::Cpu(WorkError::InterruptContext));
        }
        NativePlatform(()).check_cpu().map_err(Error::Irq)?;
        Ok(Arc::new(NativePlatform(())))
    }

    /// # Safety
    /// The main-owned execution grant and Authority belong to this actual
    /// post-EBS CPU/root epoch. `madt` is its retained original table. Every
    /// IOAPIC selector/window has been handed off exclusively, with no firmware,
    /// SMM, other CPU or controller owner; interrupt remapping is off. APIC EOI
    /// broadcast remains enabled until every pin retires. This does not grant
    /// any individual pin: claim separately retains every physical contributor.
    pub(crate) unsafe fn attach(
        execution: &crate::native_clock::DriverExecution<'_>,
        authority: &Authority,
        madt: &'static [u8],
    ) -> Result<Self, Error> {
        let scope = execution.process_scope().map_err(Error::Cpu)?;
        let cpu = scope.cpu().map_err(Error::Cpu)?;
        // SAFETY: actual complete external-controller/main handoff is required
        // by this constructor; adopt joins the existing IDT/APIC owner only.
        unsafe { super::adopt(execution) }.map_err(Error::Irq)?;
        NativePlatform(()).check_cpu().map_err(Error::Irq)?;
        let svr = super::controller().read(0xf0);
        if svr == u32::MAX || svr & (1 << 12) != 0 {
            return Err(Error::Irq(IrqError::Unsupported));
        }
        let routing = madt::Routing::parse(madt, authority.address_space().physical_bits)
            .map_err(Error::Route)?;
        let mut units = Vec::new();
        let mut spans = Vec::new();
        units
            .try_reserve_exact(routing.units.len())
            .map_err(|_| Error::Irq(IrqError::Exhausted))?;
        spans
            .try_reserve_exact(routing.units.len())
            .map_err(|_| Error::Irq(IrqError::Exhausted))?;
        for descriptor in &routing.units {
            let physical = PhysicalSpan::new(descriptor.base, 4096).map_err(Error::Mapping)?;
            let mut mapping = authority
                .map_physical(physical, CacheAttribute::Uncached, Protection::ReadWrite)
                .map_err(Error::Mapping)?;
            let address = match mapping.address(0, 32) {
                Ok(address) => address.as_ptr() as usize,
                Err(error) => {
                    // SAFETY: No IOAPIC access or published source has occurred.
                    let _ = unsafe { mapping.retire() };
                    return Err(Error::Mapping(error));
                }
            };
            // SAFETY: actual original resource-backed, all-root UC mapping.
            let mmio = unsafe { ioapic::Mmio::new(address) }.map_err(Error::Irq)?;
            let registers = Registers {
                mapping: ManuallyDrop::new(mapping),
                cpu: ManuallyDrop::new(cpu.clone()),
                scope: ManuallyDrop::new(scope.clone()),
                mmio,
            };
            // SAFETY: actual exclusive unit handoff is required by attach's
            // caller, and retained original mapping/CPU ownership is above.
            let unit = unsafe {
                ioapic::Unit::attach(
                    registers,
                    NativePlatform(()),
                    descriptor.id,
                    descriptor.gsi_base,
                )
            }
            .map_err(Error::Irq)?;
            spans.push((*descriptor, unit.pins()));
            units.push((*descriptor, unit));
        }
        // Validate complete actual hardware spans and every inter-unit overlap
        // even before any consumer asks for a route. No guessed pin capacity.
        for (unit, _) in &spans {
            routing
                .owner(
                    LineRoute {
                        gsi: unit.gsi_base,
                        polarity: stela_drivers::bus::irq::Polarity::High,
                        trigger: stela_drivers::bus::irq::Trigger::Level,
                    },
                    &spans,
                )
                .or_else(|error| {
                    // An NMI pin at a unit's base is valid inventory, but can never
                    // be claimed by a normal consumer.
                    if error == madt::RouteError::NmiConflict {
                        Ok(*unit)
                    } else {
                        Err(error)
                    }
                })
                .map_err(Error::Route)?;
        }
        Ok(Self {
            routing,
            units,
            spans,
            cpu,
            scope,
            madt,
            madt_hash: Sha256::digest(madt).into(),
            _local: PhantomData,
        })
    }

    pub(crate) fn resolve<'r, 'd, 'a>(
        &'r self,
        device: &'d DeviceResources<'a>,
        ordinal: usize,
        pin_index: usize,
    ) -> Result<ResolvedLine<'r, 'd, 'a>, Error> {
        self.scope.check().map_err(Error::Cpu)?;
        if self.cpu.in_interrupt() {
            return Err(Error::Cpu(WorkError::InterruptContext));
        }
        if Sha256::digest(self.madt).as_slice() != self.madt_hash {
            return Err(Error::Route(madt::RouteError::InvalidTable));
        }
        device.revalidate().map_err(Error::Resource)?;
        let line =
            super::crs::line(device.descriptors(), ordinal, pin_index).map_err(Error::Irq)?;
        let owner = self
            .routing
            .owner(line, &self.spans)
            .map_err(Error::Route)?;
        let unit = &self
            .units
            .iter()
            .find(|(descriptor, _)| *descriptor == owner)
            .ok_or(Error::Irq(IrqError::Route))?
            .1;
        Ok(ResolvedLine {
            root: self,
            device,
            unit,
            line,
        })
    }
}

/// Borrows the exact root and original namespace inspection. A different
/// snapshot, integer GSI, cloned AML handle or copied descriptor cannot be
/// substituted between resolution and actual complete-group ownership.
pub(crate) struct ResolvedLine<'r, 'd, 'a> {
    root: &'r Root,
    device: &'d DeviceResources<'a>,
    unit: &'r Arc<Unit>,
    line: LineRoute,
}
impl ResolvedLine<'_, '_, '_> {
    /// # Safety
    /// `devices` owns EVERY physical contributor to this exact line (including
    /// SCI/GPE/INTx aliases), stopped/drained from its previous owner. Its fixed
    /// callback group must have identical membership. Namespace/resource
    /// mutation and pin-sharing changes are excluded until full retirement.
    /// Contributors remain in their qualified powered state; wake capability
    /// metadata supplies no wake-enable, suspend or power-transition grant.
    pub(crate) unsafe fn claim(self, devices: Box<dyn ioapic::Devices>) -> Result<Source, Error> {
        // A failed context check cannot authorize release of device/root owners
        // in a foreign or hard-IRQ context. Keep them retained on that failure.
        let mut devices = ManuallyDrop::new(devices);
        self.root.scope.check().map_err(Error::Cpu)?;
        if self.root.cpu.in_interrupt() {
            return Err(Error::Cpu(WorkError::InterruptContext));
        }
        // SAFETY: Remaining refusals occur on the qualified process CPU before any
        // programming; ordinary final release is safe for this stopped group.
        let devices = unsafe { ManuallyDrop::take(&mut devices) };
        if Sha256::digest(self.root.madt).as_slice() != self.root.madt_hash {
            return Err(Error::Route(madt::RouteError::InvalidTable));
        }
        self.device.revalidate().map_err(Error::Resource)?;
        // SAFETY: caller supplies the complete actual stopped sharer group;
        // original CRS, actual MADT owner and hardware pin bounds were checked.
        unsafe { self.unit.claim(self.line, devices) }.map_err(Error::Irq)
    }
}
