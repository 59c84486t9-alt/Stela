//! Original standalone HPET page, under the activated BSP and aperture.
use super::*;
use crate::native_clock::hpet::Descriptor;
use stela_drivers::{bus::mmio::owned::ResourceId, platform::work::WorkError};

pub(crate) struct Hpet {
    descriptor: Descriptor,
    platform: Arc<platform::Platform>,
    authority: Authority,
    admission: assignment::AdmissionClose,
    registration: Option<ResourceId>,
    mapping: owned::Mapping,
    unmapped: bool,
}

impl Hpet {
    pub(crate) fn descriptor(&self) -> Descriptor {
        self.descriptor
    }

    pub(crate) fn mapping(&self) -> &owned::Mapping {
        &self.mapping
    }

    pub(crate) fn check(&self) -> Result<(), WorkError> {
        self.platform.check().map_err(|_| WorkError::Unavailable)
    }

    /// # Safety
    /// The counter is settled and every original reader and raw pointer has
    /// ended. No access may resume. Failure keeps the original reservation.
    pub(crate) unsafe fn retire_mapping(&mut self) -> Result<(), WorkError> {
        self.check()?;
        self.admission.close();
        if !self.unmapped {
            // SAFETY: forwarded original counter/controller drain.
            unsafe { self.mapping.retire() }.map_err(|_| WorkError::Unavailable)?;
            self.unmapped = true;
        }
        if let Some(id) = self.registration {
            self.authority
                .unregister_resource(id)
                .map_err(|_| WorkError::Unavailable)?;
            self.registration = None;
        }
        Ok(())
    }
}

impl Source {
    /// # Safety
    /// After EBS the standalone BSP owns the complete captured HPET and
    /// rounded page, including drained firmware/SMM and comparator, route,
    /// reset and decode exclusion until shutdown.
    pub(crate) unsafe fn take_hpet(&self) -> Result<Hpet, Error> {
        self.platform.check()?;
        let mut slot = self
            .hpet_assignment
            .try_borrow_mut()
            .map_err(|_| Error::Mapping(owned::Error::Busy))?;
        if slot.is_some() {
            return Err(Error::ResourceConflict);
        }
        let descriptor = self.platform.hpet()?;
        let registers = descriptor.registers();
        let span = PhysicalSpan::new(registers.start(), PAGE as u64).map_err(Error::Mapping)?;
        let mut assignment = Assignment::from_owned(RegisterReservation {
            platform: self.platform.clone(),
            _span: span,
        });
        let resource = Resource::new(Box::new(RegisterBacking {
            platform: self.platform.clone(),
            span,
            retention: assignment.retain(),
        }));
        let id = match self.authority.register_resource(resource.clone()) {
            Ok(id) => id,
            Err(refusal) => {
                let error = refusal.error;
                drop(refusal.into_resource());
                drop(resource);
                if assignment.close().is_ok() {
                    let _ = assignment.into_original();
                }
                return Err(Error::Mapping(error));
            }
        };
        let mapping = match self.authority.map(
            resource,
            0,
            registers.bytes() as usize,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        ) {
            Ok(mapping) => mapping,
            Err(error) => {
                // An uncertain publication refuses unregistering and keeps
                // the original assignment quarantined.
                if self.authority.unregister_resource(id).is_ok() && assignment.close().is_ok() {
                    let _ = assignment.into_original();
                }
                return Err(Error::Mapping(error));
            }
        };
        let admission = assignment.admission_close();
        *slot = Some(assignment);
        Ok(Hpet {
            descriptor,
            platform: self.platform.clone(),
            authority: self.authority.clone(),
            admission,
            registration: Some(id),
            mapping,
            unmapped: false,
        })
    }
}
