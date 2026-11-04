//! Original ECAM scopes. Temporary bus maps and kept read-only function
//! views are private to their consumers and never enter physical lookup.
use super::*;
use core::mem::ManuallyDrop;
use stela_drivers::bus::{mmio::owned::Mapping, pci::Address};

struct BusScope {
    pending: ManuallyDrop<Box<Pending>>,
    close: Option<AdmissionClose>,
}

struct Pending {
    assignment: Option<Assignment<Reservation>>,
    resource: Option<Resource>,
    mapping: Option<Mapping>,
}

impl BusScope {
    /// # Safety
    /// Every accepted mapping user has stopped, with no escaping aliases.
    unsafe fn retire(&mut self) -> Result<(), Error> {
        self.close.as_ref().expect("original bus gate").close();
        if let Some(mapping) = &mut self.pending.mapping {
            // SAFETY: the original scope has no remaining mapping users.
            unsafe { mapping.retire() }?;
            self.pending.mapping = None;
        }
        drop(self.pending.resource.take());
        self.close.take().expect("original bus gate").dismiss();
        let assignment = self
            .pending
            .assignment
            .take()
            .expect("original bus assignment");
        match assignment.into_original() {
            Ok(_) => Ok(()),
            Err(refusal) => {
                self.pending.assignment = Some(refusal.owner);
                Err(Error::Assignment(refusal.error))
            }
        }
    }
}

impl Drop for BusScope {
    fn drop(&mut self) {
        if self.pending.assignment.is_none() {
            // SAFETY: acknowledged map withdrawal and original assignment
            // return left no provider obligation in this allocation.
            unsafe { ManuallyDrop::drop(&mut self.pending) };
        }
    }
}

impl Source {
    /// Map one exact read-only function for a kept native observer.
    /// # Safety
    /// The original firmware and competing configuration writers are excluded
    /// through this function's observation and subsequent map retirement.
    pub(crate) unsafe fn observe_config_page(
        &self,
        address: Address,
    ) -> Result<(EcamWindow, Mapping), Error> {
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
    /// This boot owns every function on the selected bus for this scope.
    /// The body uses only this mapping and ends all pointers and aliases
    /// before returning. A failed withdrawal permanently keeps its owners.
    pub(super) unsafe fn with_config_bus<T>(
        &self,
        segment: u16,
        bus: u8,
        bytes: usize,
        protection: Protection,
        body: impl FnOnce(&Mapping) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let wire = self.platform.wire();
        let windows = stela_runtime::pc::acpi::mcfg(wire.mcfg()).map_err(failed)?;
        let inventory = super::super::ecam::EcamInventory::validate(
            &windows,
            self.platform.space.physical_bits,
        )?;
        let index = windows
            .iter()
            .position(|window| {
                window.segment == segment && (window.start_bus..=window.end_bus).contains(&bus)
            })
            .ok_or(Error::OutsideResource)?;
        let (_, span) = inventory.subset(index, bus..=bus, wire.roots())?;
        if !wire.excludes_memory(span.start(), span.end()) {
            return Err(Error::OutsideResource);
        }
        let (resource, assignment) = self.reservation(span, ResourceKind::Registers)?;
        let close = assignment.admission_close();
        let mut scope = BusScope {
            pending: ManuallyDrop::new(Box::new(Pending {
                assignment: Some(assignment),
                resource: Some(resource.clone()),
                mapping: None,
            })),
            close: Some(close),
        };
        let mapping =
            self.authority
                .map(resource, 0, bytes, CacheAttribute::Uncached, protection)?;
        let result = body(scope.pending.mapping.insert(mapping));
        // SAFETY: the caller's body ended every use before returning.
        unsafe { scope.retire() }?;
        result
    }
}
