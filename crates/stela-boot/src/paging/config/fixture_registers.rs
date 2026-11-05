//! Counted register aliases for the isolated post-EBS diagnostic fixture.
use super::*;
use core::mem::ManuallyDrop;
use stela_drivers::bus::mmio::owned::ResourceId;

/// The original register assignment and its mapping/registration stages.
/// Abandonment closes admission and keeps every actual owner and mapper token.
pub(crate) struct FixtureRegisters {
    pending: ManuallyDrop<Box<Pending>>,
    close: Option<assignment::AdmissionClose>,
}

struct Pending {
    authority: Authority,
    assignment: Option<Assignment<RegisterReservation>>,
    resource: Option<Resource>,
    registration: Option<ResourceId>,
    mapping: Option<owned::Mapping>,
}

impl FixtureRegisters {
    /// # Safety
    /// The exact diagnostic controller and all DMA, IRQ, work and posted-write
    /// users have stopped. No access to these registers can resume.
    pub(crate) unsafe fn retire(&mut self) -> Result<(), owned::Error> {
        if let Some(close) = &self.close {
            close.close();
        }
        if let Some(mapping) = &mut self.pending.mapping {
            // SAFETY: the caller supplies the original fixture drain.
            unsafe { mapping.retire() }?;
            self.pending.mapping = None;
        }
        if let Some(id) = self.pending.registration {
            self.pending.authority.unregister_resource(id)?;
            self.pending.registration = None;
        }
        drop(self.pending.resource.take());
        if let Some(close) = self.close.take() {
            close.dismiss();
        }
        let Some(assignment) = self.pending.assignment.take() else {
            return Ok(());
        };
        match assignment.into_original() {
            Ok(_) => Ok(()),
            Err(refusal) => {
                self.pending.assignment = Some(refusal.owner);
                Err(owned::Error::Assignment(refusal.error))
            }
        }
    }
}

impl Drop for FixtureRegisters {
    fn drop(&mut self) {
        if self.pending.assignment.is_none() {
            // SAFETY: the original assignment was explicitly returned after
            // map retirement and lookup withdrawal. No source effect remains.
            unsafe { ManuallyDrop::drop(&mut self.pending) };
        }
    }
}

impl Source {
    /// The private permit comes from the post-EBS fixture's actual requester,
    /// BAR and interrupt/remapper inventory revalidation.
    pub(crate) fn fixture_registers(
        &self,
        permit: &crate::native_dma::diagnostic::RegisterSpan<'_>,
    ) -> Result<FixtureRegisters, Error> {
        let range = permit.for_source(self).ok_or(Error::ResourceInventory)?;
        let bytes = range
            .end
            .checked_sub(range.start)
            .ok_or(Error::ResourceInventory)?;
        let span = PhysicalSpan::new(range.start, bytes).map_err(Error::Mapping)?;
        self.exclude_ecam(span)?;
        let bytes = usize::try_from(bytes).map_err(|_| Error::ResourceInventory)?;
        self.platform.identity_device(span)?;

        let assignment = Assignment::from_owned(RegisterReservation {
            platform: self.platform.clone(),
            _span: span,
        });
        let close = assignment.admission_close();
        let mut registers = FixtureRegisters {
            pending: ManuallyDrop::new(Box::new(Pending {
                authority: self.authority.clone(),
                assignment: Some(assignment),
                resource: None,
                registration: None,
                mapping: None,
            })),
            close: Some(close),
        };
        let resource = Resource::new(Box::new(RegisterBacking {
            platform: self.platform.clone(),
            span,
            retention: registers
                .pending
                .assignment
                .as_ref()
                .expect("parked register assignment")
                .retain(),
        }));
        registers.pending.resource = Some(resource.clone());
        let registration = match self.authority.register_resource(resource.clone()) {
            Ok(registration) => registration,
            Err(refusal) => {
                let error = refusal.error;
                // The exact resource is already kept by the parked owner.
                drop(refusal.into_resource());
                return Err(Error::Mapping(error));
            }
        };
        registers.pending.registration = Some(registration);
        let mapping = self
            .authority
            .map(
                resource,
                0,
                bytes,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(Error::Mapping)?;
        registers.pending.mapping = Some(mapping);
        Ok(registers)
    }
}
