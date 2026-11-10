//! The native MMIO check's IOAPIC root: every MADT unit mapped through the
//! owned MMIO authority, its firmware lines contained and rechecked. Only the
//! `diagnostics` build has a consumer, `native_mmio::diagnostic::check`.
use super::{NativePlatform, contain_firmware_lines, ioapic, madt, plan_firmware_lines};
use crate::native_clock::ProcessScope;
use alloc::{sync::Arc, vec::Vec};
use core::{marker::PhantomData, mem::ManuallyDrop};
use stela_drivers::{
    bus::{
        irq::{IrqError, Platform},
        mmio::owned::{self, Authority, CacheAttribute, Mapping, PhysicalSpan, Protection},
    },
    platform::work::{Cpu, WorkError},
};

#[derive(Debug)]
#[expect(
    dead_code,
    reason = "the native MMIO check prints the payloads through Debug"
)]
pub(crate) enum Error {
    Irq(IrqError),
    Mapping(owned::Error),
    Route(madt::RouteError),
    Cpu(WorkError),
}

/// A concrete installed mapping kept by the IOAPIC unit, including every
/// active or quarantined pin. Raw accesses never re-enter the mapping service
/// (whose address checks and locks require process context) from a hard IRQ.
pub(crate) struct Registers {
    mapping: ManuallyDrop<Mapping>,
    cpu: ManuallyDrop<Arc<dyn Cpu>>,
    scope: ManuallyDrop<Arc<ProcessScope>>,
    mmio: ioapic::Mmio,
}
// SAFETY: only Root constructs this adapter from the exclusive UC lease.
// Unit serializes the selector/window with same-CPU IRQ exclusion. The
// mapping and native CPU/root lease outlive all raw MMIO accesses and quarantine.
unsafe impl ioapic::Registers for Registers {
    fn read(&self, index: u8) -> u32 {
        ioapic::Registers::read(&self.mmio, index)
    }
    fn write(&self, index: u8, value: u32) {
        ioapic::Registers::write(&self.mmio, index, value);
    }
    fn write_eoi(&self, vector: u8) {
        ioapic::Registers::write_eoi(&self.mmio, vector);
    }
}
impl Drop for Registers {
    fn drop(&mut self) {
        if self.scope.check().is_err() || self.cpu.in_interrupt() {
            // Preserve the mapping AND CPU/root owner on an invalid
            // final-release context. No affine resource is destroyed here.
            return;
        }
        // SAFETY: this is the last Unit reference. A programmed Pin keeps
        // Unit until complete registry/RemoteIRR/work retirement; a failed or
        // abandoned Pin permanently keeps it. No register user remains.
        if unsafe { self.mapping.retire() }.is_err() {
            // SAFETY: Process context is checked. Mapping::drop records native
            // quarantine while keeping its resource/table provider;
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

/// One complete MADT unit inventory. The original Permission supplies
/// registered exclusive resources and all-root UC mapping acknowledgements;
/// this layer never registers an address from a firmware descriptor as owned.
pub(crate) struct Root {
    /// Keeps each unit and its register mapping until the root drops.
    _units: Vec<(madt::Unit, Arc<Unit>)>,
    firmware_routes: Vec<ioapic::FirmwareRoutes<Registers, NativePlatform>>,
    _local: PhantomData<*mut ()>,
}
impl Root {
    /// # Safety
    /// The main-owned execution grant and Permission belong to this
    /// post-EBS CPU/root epoch. `madt` is its original table. Every
    /// IOAPIC selector/window has been handed off exclusively, with no firmware,
    /// SMM, other CPU or controller owner; interrupt remapping is off. APIC EOI
    /// broadcast remains enabled until every pin retires. Former firmware
    /// destinations have no running AP or alternate receiver, and all their
    /// contributors/backing stay owned through independent retirement. This
    /// does not grant a pin or acknowledge contributor and work retirement.
    pub(crate) unsafe fn attach(
        execution: &crate::native_clock::DriverExecution<'_>,
        authority: &Authority,
        madt: &'static [u8],
        domain: Arc<dyn stela_drivers::bus::irq::posted_msi::NotificationDomain>,
    ) -> Result<Self, Error> {
        domain
            .check()
            .map_err(|error| Error::Irq(IrqError::Delivery(error)))?;
        let scope = execution.process_scope().map_err(Error::Cpu)?;
        let cpu = scope.cpu().map_err(Error::Cpu)?;
        let routing =
            madt::parse(madt, authority.address_space().physical_bits).map_err(Error::Route)?;
        if routing.has_ioapic_nmis() {
            return Err(Error::Route(madt::RouteError::NmiConflict));
        }
        // SAFETY: complete external-controller/main handoff is required
        // by this constructor; adopt joins the existing IDT/APIC owner only.
        unsafe { super::adopt(execution) }.map_err(Error::Irq)?;
        NativePlatform(()).check_cpu().map_err(Error::Irq)?;
        let svr = super::controller().read(0xf0);
        if svr == u32::MAX || svr & (1 << 12) != 0 {
            return Err(Error::Irq(IrqError::Unsupported));
        }
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
            let address = match mapping.address(0, 68) {
                Ok(address) => address.as_ptr() as usize,
                Err(error) => {
                    // SAFETY: No IOAPIC access or published source has occurred.
                    let _ = unsafe { mapping.retire() };
                    return Err(Error::Mapping(error));
                }
            };
            // SAFETY: original resource-backed, all-root UC mapping.
            let mmio = unsafe { ioapic::Mmio::new(address) }.map_err(Error::Irq)?;
            let registers = Registers {
                mapping: ManuallyDrop::new(mapping),
                cpu: ManuallyDrop::new(cpu.clone()),
                scope: ManuallyDrop::new(scope.clone()),
                mmio,
            };
            // SAFETY: exclusive unit handoff is required by attach's
            // caller, and kept original mapping/CPU ownership is above.
            let unit = unsafe {
                ioapic::Unit::attach(
                    registers,
                    NativePlatform(()),
                    domain.clone(),
                    super::CONTROLLER.identity(),
                    descriptor.id,
                    descriptor.gsi_base,
                )
            }
            .map_err(Error::Irq)?;
            spans.push((*descriptor, unit.pins()));
            units.push((*descriptor, unit));
        }
        routing.validate_units(&spans).map_err(Error::Route)?;
        // SAFETY: the original complete MADT/controller roster was validated above.
        let routes = unsafe { plan_firmware_lines(&units) }.map_err(Error::Irq)?;
        // Keep all original plans and controllers if any mask may have applied.
        let mut routes = ManuallyDrop::new(routes);
        // SAFETY: same exclusive roster, with the entire original plan kept.
        unsafe { contain_firmware_lines(&routes) }.map_err(Error::Irq)?;
        // SAFETY: containment succeeded. Transfer the original plans once
        // into the returned root so it can recheck the same routes.
        let firmware_routes = unsafe { ManuallyDrop::take(&mut routes) };
        Ok(Self {
            _units: units,
            firmware_routes,
            _local: PhantomData,
        })
    }

    /// Recheck all original routes before any contributor is published.
    pub(crate) fn recheck_firmware_lines(&self) -> Result<(), Error> {
        for routes in &self.firmware_routes {
            routes.verify_contained().map_err(Error::Irq)?;
        }
        Ok(())
    }
}
