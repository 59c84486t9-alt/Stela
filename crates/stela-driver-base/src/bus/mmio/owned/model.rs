//! Hosted actual RAM/allocation-pool assignment for isolated fixtures only.
//! Affine control remains OUTSIDE resource inventories; backing pins contain
//! only the same original retention/product, never that control or a Source.
use super::Error;
use crate::bus::pci::assignment::{
    self, Assignment, OpaqueUse, PhysicalAssignment, Retention, UseKind,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

struct Product<P> {
    allocation: P,
    check: fn(&P) -> Result<(), assignment::Error>,
}
// SAFETY: unsafe from_owned admits only actual isolated hosted RAM/pool and
// original pure model guard. Native owners and control/view backedges forbidden.
unsafe impl<P: Clone + Send + Sync + 'static> PhysicalAssignment for Product<P> {
    fn parent(&self) -> Option<&assignment::Parent> {
        None
    }
    fn check_control(&self) -> Result<(), assignment::Error> {
        (self.check)(&self.allocation)
    }
}
/// Retention ONLY. Never stores or lends the affine Assignment/fixture control.
/// Copies retain the SAME actual allocation and count gate, not BAR metadata.
pub struct MappingRetention<P: Clone + Send + Sync + 'static> {
    original: Retention<Product<P>>,
    context_pin: P,
    check: fn(&P) -> Result<(), assignment::Error>,
    closed: Arc<AtomicBool>,
}
impl<P: Clone + Send + Sync + 'static> Clone for MappingRetention<P> {
    fn clone(&self) -> Self {
        Self {
            original: self.original.clone(),
            context_pin: self.context_pin.clone(),
            check: self.check,
            closed: self.closed.clone(),
        }
    }
}
impl<P: Clone + Send + Sync + 'static> MappingRetention<P> {
    /// Pure original model context, independent of closed IO admission. This
    /// supplies no unmap/IRQ/DMA/assignment completion or mutable control.
    pub fn check_context(&self) -> Result<(), Error> {
        (self.check)(&self.context_pin).map_err(Error::Assignment)
    }
    /// Negative admission observation only; every real access must still use
    /// begin_use atomically with the SAME actual assignment gate.
    pub fn check_admission(&self) -> Result<(), Error> {
        self.check_context()?;
        if self.closed.load(Ordering::Acquire) {
            Err(Error::Assignment(assignment::Error::Closed))
        } else {
            Ok(())
        }
    }
    pub fn begin_use(&self, kind: UseKind) -> Result<OpaqueUse, Error> {
        self.check_admission()?;
        self.original
            .begin_use(kind)
            .map(|usage| usage.erase())
            .map_err(Error::Assignment)
    }
    pub fn begin_mapping(&self) -> Result<OpaqueUse, Error> {
        self.begin_use(UseKind::Mapping)
    }
    /// Same actual assignment count for fixture diagnostics only. It never
    /// proves DMA/IRQ/unmap completion or grants control/operation access.
    pub fn uses(&self) -> usize {
        self.original.uses()
    }
    /// Actual original Arc identity, never a new source/permission/receipt.
    pub fn same_owner(&self, other: &Self) -> bool {
        self.original.same_assignment(&other.original)
    }
}
/// Unique !Send model reservation/control, never stored in ResourceBacking.
/// Default abandonment closes admission and retains the actual original RAM.
pub struct MappingOwner<P: Clone + Send + Sync + 'static> {
    original: Option<Assignment<Product<P>>>,
    context_pin: Option<P>,
    check: fn(&P) -> Result<(), assignment::Error>,
    closed: Arc<AtomicBool>,
    failure: Option<Error>,
}
impl<P: Clone + Send + Sync + 'static> MappingOwner<P> {
    /// # Safety
    /// P owns the ACTUAL hosted CPU RAM/allocation pool and original isolated
    /// reservation/reset guard. No firmware, device or guest exists. P and its
    /// Clone may only retain this same model allocation; no dummy span/label,
    /// counter, Arc<()>, new allocation or unrelated owner substitutes for it.
    /// No transitive Authority, Resource, Mapping/View, Source, driver control
    /// or callback to one may create a backedge. Split actual allocation pools
    /// from reentrant provider bookkeeping. Check is pure bounded actual model
    /// context validation, without allocation, IO, reentry, waiting or unwind.
    /// This may NEVER wrap a real native/affine physical owner.
    pub unsafe fn from_owned(
        allocation: P,
        check: fn(&P) -> Result<(), assignment::Error>,
    ) -> Self {
        Self {
            original: Some(Assignment::from_owned(Product {
                allocation: allocation.clone(),
                check,
            })),
            context_pin: Some(allocation),
            check,
            closed: Arc::new(AtomicBool::new(false)),
            failure: None,
        }
    }
    /// Retain the SAME actual assignment's metadata-only close handle.
    /// No model/native context check, entry, allocation or hardware effect is
    /// performed. The handle cannot lend this unique controller or reopen IO.
    pub fn admission_close(&self) -> Result<assignment::AdmissionClose, Error> {
        Ok(self
            .original
            .as_ref()
            .ok_or(Error::Retired)?
            .admission_close())
    }
    pub fn retention(&self) -> Result<MappingRetention<P>, Error> {
        Ok(MappingRetention {
            original: self.original.as_ref().ok_or(Error::Retired)?.retain(),
            context_pin: self.context_pin.as_ref().ok_or(Error::Retired)?.clone(),
            check: self.check,
            closed: self.closed.clone(),
        })
    }
    pub fn record_retention(&mut self, error: Error) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
    }
    /// Diagnostic copy only; not permission or completion.
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }
    pub fn uses(&self) -> usize {
        self.original.as_ref().map_or(0, Assignment::uses)
    }
    /// Close BEFORE model source mutation. Busy still leaves real admission
    /// closed and every existing mapping/operation count held.
    pub fn close(&mut self) -> Result<(), Error> {
        self.closed.store(true, Ordering::Release);
        let result = self
            .original
            .as_mut()
            .ok_or(Error::Retired)?
            .close()
            .map_err(Error::Assignment);
        if let Err(error) = result {
            self.record_retention(error);
        }
        result
    }
    /// Metadata-only infallible denial. Never a cleanup/reset/join receipt.
    pub fn abandon_admission(&mut self) {
        self.closed.store(true, Ordering::Release);
        if let Some(original) = &mut self.original {
            original.abandon_admission();
        }
    }
    /// Return SAME actual model product only after source-owned retirement.
    /// Retentions (including config epochs) must actually have ended too.
    /// Failure restores the SAME affine controller and never reopens admission.
    ///
    /// # Safety
    /// Owning fixture ended every producer, raw-pointer tail, callback and
    /// non-MMIO alias. Registry native/model unmap/TLB/cache obligations really
    /// acknowledged. Counts alone never prove those effects or release rights.
    /// No future actor can use this retired model epoch.
    pub unsafe fn retire(&mut self) -> Result<P, Error> {
        self.close()?;
        let original = self.original.take().ok_or(Error::Retired)?;
        match original.into_original() {
            Ok(product) => {
                drop(self.context_pin.take());
                Ok(product.allocation)
            }
            Err(refusal) => {
                let error = Error::Assignment(refusal.error);
                self.original = Some(refusal.owner);
                self.record_retention(error);
                Err(error)
            }
        }
    }
}
impl<P: Clone + Send + Sync + 'static> Drop for MappingOwner<P> {
    fn drop(&mut self) {
        self.abandon_admission();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4096))]
    struct Pages([u8; 4096]);

    #[test]
    fn close_projection_uses_original_gate_without_entering_model_context() {
        let ram = Arc::new(Pages([0; 4096]));
        let allowed = Arc::new(AtomicBool::new(true));
        // SAFETY: actual isolated hosted RAM, one external controller, no
        // source/provider/control backedge, device or mutable/raw user exists.
        let mut owner = unsafe {
            MappingOwner::from_owned((ram.clone(), allowed.clone()), |pin| {
                if pin.1.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err(assignment::Error::Context)
                }
            })
        };
        let retained = owner.retention().unwrap();
        let usage = retained.begin_mapping().unwrap();
        assert_eq!(owner.uses(), 1);
        allowed.store(false, Ordering::Release);
        // Capture and close must not invoke the deliberately denied context.
        let close = owner.admission_close().unwrap();
        close.close();
        allowed.store(true, Ordering::Release);
        assert!(matches!(
            retained.begin_mapping(),
            Err(Error::Assignment(assignment::Error::Closed))
        ));
        assert_eq!(owner.uses(), 1, "accepted use remains held");
        // SAFETY: this RAM-only gate control issued no mapping/native effect,
        // raw pointer or callback; its accepted original user has now ended.
        assert!(unsafe { usage.release() }.is_ok());
        close.dismiss();
        drop(retained);
        // SAFETY: all original RAM fixture users ended above; no mapper or
        // independent alias exists and the exact close projection was dismissed.
        let original = unsafe { owner.retire() }.unwrap();
        assert!(Arc::ptr_eq(&original.0, &ram));
        assert_eq!(ram.0[0], 0);
        assert!(matches!(owner.admission_close(), Err(Error::Retired)));
    }
}
