//! Original ECAM scopes. Temporary bus maps and kept read-only function
//! views are private to their consumers and never enter physical lookup.
use super::*;
use crate::native_mmio::ecam::EcamInventory;
use core::{mem::ManuallyDrop, ops::RangeInclusive};
use stela_drivers::bus::{mmio::owned::Mapping, pci::Address};
mod containment;
pub(super) use containment::PciSlots;

struct ConfigScope {
    pending: ManuallyDrop<Box<Pending>>,
    close: Option<AdmissionClose>,
}

struct Pending {
    assignment: Option<Assignment<Reservation>>,
    resource: Option<Resource>,
    mapping: Option<Mapping>,
}

impl ConfigScope {
    /// # Safety
    /// The caller holds this original configuration extent and exclusion.
    unsafe fn open(source: &Source, span: PhysicalSpan) -> Result<Self, Error> {
        let bytes = usize::try_from(span.bytes()).map_err(|_| Error::InvalidRange)?;
        let (resource, assignment) = source.reservation(span, ResourceKind::Registers)?;
        let close = assignment.admission_close();
        let mut scope = Self {
            pending: ManuallyDrop::new(Box::new(Pending {
                assignment: Some(assignment),
                resource: Some(resource.clone()),
                mapping: None,
            })),
            close: Some(close),
        };
        scope.pending.mapping = Some(source.authority.map(
            resource,
            0,
            bytes,
            CacheAttribute::Uncached,
            Protection::ReadOnly,
        )?);
        Ok(scope)
    }

    /// # Safety
    /// Every accepted mapping user has stopped, with no escaping aliases.
    unsafe fn retire(&mut self) -> Result<(), Error> {
        self.close
            .as_ref()
            .expect("original configuration gate")
            .close();
        if let Some(mapping) = &mut self.pending.mapping {
            // SAFETY: the original scope has no remaining mapping users.
            unsafe { mapping.retire() }?;
            self.pending.mapping = None;
        }
        drop(self.pending.resource.take());
        self.close
            .take()
            .expect("original configuration gate")
            .dismiss();
        let assignment = self
            .pending
            .assignment
            .take()
            .expect("original configuration assignment");
        match assignment.into_original() {
            Ok(_) => Ok(()),
            Err(refusal) => {
                self.pending.assignment = Some(refusal.owner);
                Err(Error::Assignment(refusal.error))
            }
        }
    }
}

impl Drop for ConfigScope {
    fn drop(&mut self) {
        if self.pending.assignment.is_none() {
            // SAFETY: acknowledged map withdrawal and original assignment
            // return left no provider obligation in this allocation.
            unsafe { ManuallyDrop::drop(&mut self.pending) };
        }
    }
}

/// The original source lends a read-only bus at a time. A mapped bus is
/// withdrawn and acknowledged before a different bus is admitted.
pub(crate) struct ConfigInventory<'a> {
    source: &'a Source,
    windows: &'a [EcamWindow],
    geometry: EcamInventory<'a>,
    mapped: Option<((u16, u8), ConfigScope)>,
}

impl ConfigInventory<'_> {
    pub(crate) fn read32(&mut self, address: Address, offset: u16) -> Result<u32, Error> {
        if address.device >= 32
            || address.function >= 8
            || offset > 4092
            || !offset.is_multiple_of(4)
        {
            return Err(Error::InvalidRange);
        }
        let key = (address.segment, address.bus);
        if !self
            .mapped
            .as_ref()
            .is_some_and(|(current, _)| *current == key)
        {
            self.withdraw()?;
            let index = self
                .windows
                .iter()
                .position(|window| {
                    window.segment == address.segment
                        && (window.start_bus..=window.end_bus).contains(&address.bus)
                })
                .ok_or(Error::OutsideResource)?;
            let (_, span) = self.geometry.subset(
                index,
                address.bus..=address.bus,
                self.source.platform.wire().roots(),
            )?;
            // SAFETY: the caller owns the original complete captured buses.
            // Only this bounded read observes the newly mapped bus.
            let scope = unsafe { ConfigScope::open(self.source, span) }?;
            self.mapped = Some((key, scope));
        }
        let (_, scope) = self.mapped.as_ref().expect("current read-only bus");
        let offset = (usize::from(address.device) << 15)
            | (usize::from(address.function) << 12)
            | usize::from(offset);
        scope
            .pending
            .mapping
            .as_ref()
            .expect("original map")
            .read32(offset)
    }

    pub(crate) fn check_bridge(
        &self,
        address: Address,
        downstream: RangeInclusive<u8>,
    ) -> Result<(), Error> {
        self.geometry
            .check_bridge(self.source.platform.wire().roots(), address, downstream)
    }

    fn withdraw(&mut self) -> Result<(), Error> {
        if let Some((_, mut scope)) = self.mapped.take() {
            // SAFETY: only synchronous reads, with no external map views.
            unsafe { scope.retire() }?;
        }
        Ok(())
    }
}

impl Source {
    /// # Safety
    /// The boot owns all captured configuration buses, excluding firmware,
    /// reset, topology and SR-IOV writers through the observation and its use.
    pub(crate) unsafe fn with_config_inventory<T>(
        &self,
        body: impl FnOnce(&[EcamWindow], &mut ConfigInventory<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let wire = self.platform.wire();
        let windows = stela_runtime::pc::acpi::mcfg(wire.mcfg()).map_err(failed)?;
        if windows.is_empty() {
            return Err(Error::Unavailable);
        }
        let bits = self.platform.space.physical_bits;
        let original = EcamInventory::validate(&windows, bits)?;
        let windows = original.root_windows(wire.roots())?;
        let geometry = EcamInventory::validate(&windows, bits)?;
        for (index, window) in windows.iter().enumerate() {
            for bus in window.start_bus..=window.end_bus {
                let (_, span) = geometry.subset(index, bus..=bus, wire.roots())?;
                if !wire.excludes_memory(span.start(), span.end()) {
                    return Err(Error::OutsideResource);
                }
            }
        }
        let mut reader = ConfigInventory {
            source: self,
            windows: &windows,
            geometry,
            mapped: None,
        };
        let result = body(&windows, &mut reader);
        reader.withdraw()?;
        result
    }

    fn config_page(&self, address: Address) -> Result<(EcamWindow, PhysicalSpan), Error> {
        let wire = self.platform.wire();
        let windows = stela_runtime::pc::acpi::mcfg(wire.mcfg()).map_err(failed)?;
        let inventory = super::super::ecam::EcamInventory::validate(
            &windows,
            self.platform.space.physical_bits,
        )?;
        let (window, span) = inventory.function(address, wire.roots())?;
        if !wire.excludes_memory(span.start(), span.end()) {
            return Err(Error::OutsideResource);
        }
        Ok((window, span))
    }

    /// Map one exact read-only function for a kept native observer.
    /// # Safety
    /// The original firmware and competing configuration writers are excluded
    /// through this function's observation and subsequent map retirement.
    pub(crate) unsafe fn observe_config_page(
        &self,
        address: Address,
    ) -> Result<(EcamWindow, Mapping), Error> {
        let (window, span) = self.config_page(address)?;
        let mut reservations = self
            .reservations
            .try_borrow_mut()
            .map_err(|_| Error::Busy)?;
        reservations.try_reserve(1).map_err(|_| Error::Exhausted)?;
        let (resource, assignment) = self.reservation(span, ResourceKind::Registers)?;
        reservations.push(assignment);
        drop(reservations);
        let mapping = self.authority.map(
            resource,
            0,
            PAGE as usize,
            CacheAttribute::Uncached,
            Protection::ReadOnly,
        )?;
        Ok((window, mapping))
    }

    /// # Safety
    /// This boot holds the original function stable and excludes competing
    /// writers until the scope withdraws the mapping.
    pub(super) unsafe fn read_config_identity(&self, address: Address) -> Result<u32, Error> {
        let (_, span) = self.config_page(address)?;
        // SAFETY: the caller keeps this exact original configuration extent.
        let mut scope = unsafe { ConfigScope::open(self, span) }?;
        let result = scope
            .pending
            .mapping
            .as_ref()
            .expect("original map")
            .read32(0);
        // SAFETY: the synchronous observation has no aliases.
        unsafe { scope.retire() }?;
        result
    }
}
