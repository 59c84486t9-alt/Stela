//! Private original child stack ownership stage.
use super::*;
impl<'catalog, 'runtime, P: Provider, const N: usize>
    DormantChildStackLease<'catalog, 'runtime, P, N>
{
    pub fn assigned(&self) -> stela_driver_base::platform::work::AssignedGeneral {
        self.native.assigned()
    }
    /// # Safety
    /// Actual original tasklist/PID/resource publication and first source wake
    /// completed for this exact retained child; keep the whole graph on failure.
    #[expect(clippy::result_large_err, reason = "exact dormant original graph")]
    pub unsafe fn activate(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<PublishedChildStackLease<'catalog, 'runtime, P, N>, (Self, AdmissionError)> {
        if let Err(error) = canonical_scope(self.catalog, entered) {
            return Err((self, error));
        }
        let Self {
            catalog,
            native,
            ticket,
            target,
        } = self;
        // SAFETY: exact original first-wake publication contract above.
        match unsafe { native.activate(entered) } {
            Ok(native) => Ok(PublishedChildStackLease {
                catalog,
                native,
                ticket: Some(ticket),
                target,
            }),
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
