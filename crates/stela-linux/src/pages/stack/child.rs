//! One affine owner across actual original-child descriptor/native phases.
use super::*;
mod dormant;
mod prepared;
mod published;
use core::ptr::NonNull;
use stela_driver_base::platform::work::{
    Callback, DormantGeneralStack, OwnedPinnedGeneral, PublishedGeneralStack, scheduling,
};
unsafe extern "C" {
    fn stela_linux_page_stack_source_context(owner: *const crate::owner::RawOwner) -> c_int;
    fn stela_linux_page_stack_lend(
        ticket: *const NativeTicket,
        target: *const c_void,
        base: *mut *mut c_void,
    ) -> c_int;
    fn stela_linux_page_stack_prepare_publish(
        ticket: *const NativeTicket,
        target: *const c_void,
    ) -> c_int;
    fn stela_linux_page_stack_publish(ticket: *const NativeTicket, target: *const c_void);
    fn stela_linux_page_stack_retire(ticket: *const NativeTicket, target: *const c_void) -> c_int;
}
#[must_use = "cancel only after actual original reverse unwind; Drop retains"]
pub struct PreparedChildStackLease<'catalog, 'runtime, P: Provider, const N: usize> {
    catalog: &'catalog Catalog<P>,
    native: OwnedPinnedGeneral<'runtime, N>,
    ticket: Option<NativeTicket>,
    target: Option<NonNull<c_void>>,
    base: Option<NonNull<u8>>,
}
#[must_use = "activate only through original first wake after actual source publication"]
pub struct DormantChildStackLease<'catalog, 'runtime, P: Provider, const N: usize> {
    catalog: &'catalog Catalog<P>,
    native: DormantGeneralStack<'runtime, N>,
    ticket: NativeTicket,
    target: NonNull<c_void>,
}
#[must_use = "join actual source/native lifetimes before descriptors and pin retire"]
pub struct PublishedChildStackLease<'catalog, 'runtime, P: Provider, const N: usize> {
    catalog: &'catalog Catalog<P>,
    native: PublishedGeneralStack<'runtime, N>,
    ticket: Option<NativeTicket>,
    target: NonNull<c_void>,
}
fn canonical_scope<P: Provider>(
    catalog: &Catalog<P>,
    entered: &dyn EnteredProcess,
) -> Result<(), AdmissionError> {
    entered.check().map_err(AdmissionError::Work)?;
    let context = catalog
        .context
        .as_ref()
        .ok_or(AdmissionError::Catalog(Error::InvalidReservation))?;
    let ContextEntry::Canonical { owner, .. } = &context.entry else {
        return Err(AdmissionError::Catalog(Error::InvalidReservation));
    };
    // SAFETY: SAME retained canonical RawOwner + actual ExecutionPin/CodePin.
    // This source metadata validator permits original locked IF0 context; no
    // legacy entry, current construction, wait or page allocation occurs.
    let status = unsafe { stela_linux_page_stack_source_context(*owner) };
    if status != 0 {
        return Err(AdmissionError::Catalog(Error::Native(status)));
    }
    Ok(())
}
impl<'catalog, 'runtime, P: Provider, const N: usize> StackAdmission<'catalog, 'runtime, P, N> {
    /// Consume the actual admitted marker/pin into original-child escrow.
    /// No CPU address, C payload, task/current or runnable job is published.
    #[expect(clippy::result_large_err, reason = "exact original prepared owner")]
    pub fn reconstruct_child(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<PreparedChildStackLease<'catalog, 'runtime, P, N>, (Self, AdmissionError)> {
        if self.ticket.is_none() {
            return Err((self, AdmissionError::Catalog(Error::InvalidReservation)));
        }
        if let Err(error) = canonical_scope(self.catalog, entered) {
            return Err((self, error));
        }
        let Self {
            catalog,
            prepared,
            ticket,
        } = self;
        match prepared.reconstruct(entered) {
            Ok(native) => Ok(PreparedChildStackLease {
                catalog,
                native,
                ticket,
                target: None,
                base: None,
            }),
            Err((prepared, error)) => Err((
                Self {
                    catalog,
                    prepared,
                    ticket,
                },
                AdmissionError::Work(error),
            )),
        }
    }
}
impl<P: Provider, const N: usize> core::fmt::Debug for PreparedChildStackLease<'_, '_, P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedChildStackLease")
            .field("generation", &self.catalog.generation)
            .finish_non_exhaustive()
    }
}
impl<P: Provider, const N: usize> core::fmt::Debug for DormantChildStackLease<'_, '_, P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DormantChildStackLease")
            .field("generation", &self.catalog.generation)
            .finish_non_exhaustive()
    }
}
impl<P: Provider, const N: usize> core::fmt::Debug for PublishedChildStackLease<'_, '_, P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublishedChildStackLease")
            .field("generation", &self.catalog.generation)
            .finish_non_exhaustive()
    }
}
