//! Original ECAM scopes. Temporary bus maps and kept read-only function
//! views are private to their consumers and never enter physical lookup.
use super::*;
use core::mem::ManuallyDrop;
use stela_drivers::bus::{mmio::owned::Mapping, pci::Address};

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

impl Source {
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
        // SAFETY: this closure performs one synchronous read with no aliases.
        unsafe { self.with_config_scope(span, Protection::ReadOnly, |mapping| mapping.read32(0)) }
    }

    /// # Safety
    /// This boot owns every function on the captured buses, and firmware
    /// has stopped interrupt work before native probing or AP startup.
    pub(crate) unsafe fn mask_pci_intx(&self) -> Result<(), Error> {
        let wire = self.platform.wire();
        let windows = stela_runtime::pc::acpi::mcfg(wire.mcfg()).map_err(failed)?;
        let inventory = super::super::ecam::EcamInventory::validate(
            &windows,
            self.platform.space.physical_bits,
        )?;
        for (index, window) in windows.iter().enumerate() {
            for bus in window.start_bus..=window.end_bus {
                let (_, span) = inventory.subset(index, bus..=bus, wire.roots())?;
                if !wire.excludes_memory(span.start(), span.end()) {
                    return Err(Error::OutsideResource);
                }
                // SAFETY: this exact bus is held exclusively by the caller.
                // The containment loop ends all accesses before returning.
                unsafe {
                    self.with_config_scope(span, Protection::ReadWrite, |mapping| {
                        mask_bus_intx(mapping)
                    })
                }?;
            }
        }
        Ok(())
    }

    /// # Safety
    /// The caller proved the original configuration extent and exclusivity.
    /// The body uses only this map and ends all pointers and aliases on return.
    unsafe fn with_config_scope<T>(
        &self,
        span: PhysicalSpan,
        protection: Protection,
        body: impl FnOnce(&Mapping) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let bytes = usize::try_from(span.bytes()).map_err(|_| Error::InvalidRange)?;
        let (resource, assignment) = self.reservation(span, ResourceKind::Registers)?;
        let close = assignment.admission_close();
        let mut scope = ConfigScope {
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
        // A failed writable scope may already have changed a command word.
        // Keep the original mapping and assignment closed to further users
        // until a source can account for that effect.
        if protection == Protection::ReadWrite && result.is_err() {
            return result;
        }
        // SAFETY: the caller's body ended every use before returning.
        unsafe { scope.retire() }?;
        result
    }
}

/// Stop legacy interrupt contributors through the private containment map.
/// A disappearing function or failed command readback refuses SCI admission.
/// # Safety
/// The mapping is the original exclusive writable UC lease for this bus.
unsafe fn mask_bus_intx(mapping: &Mapping) -> Result<(), Error> {
    const INTX_DISABLE: u16 = 1 << 10;
    for device in 0..32usize {
        let first = device << 15;
        let first_identity = mapping.read32(first)?;
        if first_identity & 0xffff == 0xffff {
            continue;
        }
        let functions = if mapping.read32(first + 12)? & (0x80 << 16) != 0 {
            8
        } else {
            1
        };
        for function in 0..functions {
            let offset = first | function << 12;
            let identity = if function == 0 {
                first_identity
            } else {
                mapping.read32(offset)?
            };
            if identity & 0xffff == 0xffff {
                continue;
            }
            let command = mapping.address(offset + 4, 2)?.as_ptr().cast::<u16>();
            // SAFETY: the exclusive UC mapping covers the aligned 16-bit
            // command register. The adjacent W1C status is a separate word.
            let original = u16::from_le(unsafe { command.read_volatile() });
            if original == u16::MAX {
                return Err(Error::InvalidPlatformReply);
            }
            let expected = original | INTX_DISABLE;
            if expected != original {
                // SAFETY: the same private command register is still live.
                unsafe { command.write_volatile(expected.to_le()) };
            }
            // SAFETY: readback of that same aligned command register.
            let actual = u16::from_le(unsafe { command.read_volatile() });
            if actual != expected || mapping.read32(offset)? != identity {
                return Err(Error::InvalidPlatformReply);
            }
        }
    }
    Ok(())
}
