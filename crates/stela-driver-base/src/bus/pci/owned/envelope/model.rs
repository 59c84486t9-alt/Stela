//! In-place retirement for original hosted custody.
use super::*;
use crate::bus::pci::owned::grant::DriverCustody;
use core::any::TypeId;

impl Envelope<DriverGrant> {
    fn model_parts(&mut self) -> (&mut DriverGrant, Option<&mut Mapping>) {
        match self.phase_mut() {
            Phase::Pending { grant, mapping } => (grant, mapping.as_mut()),
            Phase::Attached(region) => {
                let (grant, mapping) = region.kept_parts();
                (grant, Some(mapping))
            }
        }
    }
}

impl ConfigParts<DriverGrant> {
    /// # Safety
    /// The caller owns the actual hosted retirement and every user has ended.
    /// The finalizer must acknowledge withdrawal of the same source in place.
    pub(in crate::bus::pci::owned) unsafe fn finish_model<P: DriverCustody>(
        mut self,
        preflight: impl FnOnce(&P, Option<&Mapping>) -> Result<(), MappingError>,
        finish: impl FnOnce(&mut P) -> Result<(), MappingError>,
    ) -> Result<(), (MappingError, Self)> {
        let needs_retirement = self.0.close.is_some();
        let (grant, mapping) = self.0.model_parts();
        let custody = grant.model_custody_mut();
        if (*custody).type_id() != TypeId::of::<P>() {
            return Err((MappingError::InvalidPlatformReply, self));
        }
        // SAFETY: exact concrete type of this borrowed original custody.
        let source = unsafe { &mut *(core::ptr::from_mut(custody).cast::<P>()) };
        if needs_retirement {
            if let Err(error) = preflight(source, mapping.as_deref()) {
                return Err((error, self));
            }
            // SAFETY: caller supplied complete original user retirement.
            if let Err(error) = unsafe { self.retire() } {
                return Err((error, self));
            }
        }
        let (grant, _) = self.0.model_parts();
        // SAFETY: same type-checked custody, still in its original allocation.
        let source = unsafe { &mut *(core::ptr::from_mut(grant.model_custody_mut()).cast::<P>()) };
        if let Err(error) = finish(source) {
            return Err((error, self));
        }
        // SAFETY: the exact source finalizer acknowledged empty custody, and
        // all mapping and operation retention has already ended.
        unsafe { grant.release_model_custody() };
        // SAFETY: this consumed envelope has an empty source and retired map.
        drop(unsafe { ManuallyDrop::take(&mut self.0.phase) });
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::bus::pci::owned) fn into_test_parts(mut self) -> (DriverGrant, Mapping) {
        if let Some(close) = self.0.close.take() {
            close.dismiss();
        }
        // SAFETY: the test consumes the envelope once and explicitly recovers
        // the actual individual fixture inputs for negative pairing controls.
        let mut phase = unsafe { ManuallyDrop::take(&mut self.0.phase) };
        match phase.take().expect("original fixture phase") {
            Phase::Attached(region) => region.into_test_parts(),
            Phase::Pending { grant, mapping } => (grant, mapping.expect("fixture map")),
        }
    }
}
