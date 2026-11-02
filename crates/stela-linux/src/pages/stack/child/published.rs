//! Private original child stack ownership stage.
use super::*;
impl<'catalog, 'runtime, P: Provider, const N: usize>
    PublishedChildStackLease<'catalog, 'runtime, P, N>
{
    pub fn assigned(&self) -> stela_driver_base::platform::work::AssignedGeneral {
        self.native.assigned()
    }
    /// Existing exact native physical-return observation. This constructorless
    /// query grants no source/descriptor/RCU retirement, current or CPU/root
    /// permission. Final pin disposal still requires its actual successor.
    pub fn physically_returned(&self) -> Result<bool, AdmissionError> {
        self.native
            .physically_returned()
            .map_err(AdmissionError::Work)
    }
    /// # Safety
    /// Actual original source final task/stack/alias/RCU disposal and producer
    /// closure joined for this exact child. Native physical return is checked
    /// independently; page ref counters cannot stand in for source retirement.
    pub unsafe fn retire_descriptors(
        &mut self,
        entered: &dyn EnteredProcess,
    ) -> Result<(), AdmissionError> {
        if self.ticket.is_none() {
            return Ok(());
        }
        if !self
            .native
            .physically_returned()
            .map_err(AdmissionError::Work)?
        {
            return Err(AdmissionError::Work(WorkError::Pending));
        }
        canonical_scope(self.catalog, entered)?;
        let ticket = self.ticket.unwrap();
        // SAFETY: real original source/native joins above, exact retained marker.
        let status = unsafe { stela_linux_page_stack_retire(&ticket, self.target.as_ptr()) };
        if status != 0 {
            return Err(AdmissionError::Catalog(Error::Native(status)));
        }
        self.ticket = None;
        entered.check().map_err(AdmissionError::Work)
    }
    /// # Safety
    /// All original users really ended, descriptors retired separately above,
    /// exact native binding detached and caller is actual off-all-stacks owner.
    #[expect(clippy::result_large_err, reason = "exact published native/C owner")]
    pub unsafe fn release(self) -> Result<(), (Self, AdmissionError)> {
        if self.ticket.is_some() {
            return Err((self, AdmissionError::Work(WorkError::Pending)));
        }
        let Self {
            catalog,
            native,
            ticket,
            target,
        } = self;
        // SAFETY: original source/descriptor/RCU and native prerequisites joined.
        match unsafe { native.release() } {
            Ok(()) => Ok(()),
            Err((native, error)) => Err((
                Self {
                    catalog,
                    native,
                    ticket,
                    target,
                },
                AdmissionError::Work(error),
            )),
        }
    }
}
