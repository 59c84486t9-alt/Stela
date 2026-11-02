//! Private original child stack ownership stage.
use super::*;
impl<'catalog, 'runtime, P: Provider, const N: usize>
    PreparedChildStackLease<'catalog, 'runtime, P, N>
{
    /// Lend actual stable descriptors to original alloc_thread_stack_node.
    /// # Safety
    /// target is the exact retained original copy_process factory child under
    /// this parent's serialized transaction, never an arbitrary descriptor or
    /// current constructor. This lease remains owned until original reverse
    /// unwind or full source/native retirement. Do not zero/reseed these bytes.
    /// install synchronously writes the actual original factory stack field;
    /// it performs no fallible setup, wait, switch, reentry or native loan. Any
    /// unwind keeps the whole graph; it never means an unexposed allocation.
    pub unsafe fn lend<R>(
        &mut self,
        entered: &dyn EnteredProcess,
        target: NonNull<c_void>,
        install: impl FnOnce(NonNull<u8>, usize) -> R,
    ) -> Result<R, AdmissionError> {
        if self.target.is_some() {
            return Err(AdmissionError::AlreadyAdmitted);
        }
        self.native
            .inspect_pin(entered, |_| ())
            .map_err(AdmissionError::Work)?;
        canonical_scope(self.catalog, entered)?;
        let ticket = self
            .ticket
            .as_ref()
            .ok_or(AdmissionError::Catalog(Error::InvalidReservation))?;
        let bytes = crate::task::stack_requirement()
            .map_err(AdmissionError::Work)?
            .usable_bytes();
        let mut base = core::ptr::null_mut();
        // SAFETY: exact owning marker/pin/source child, current canonical owner,
        // output lives through bounded call; no pointer is interpreted as task.
        let status = unsafe { stela_linux_page_stack_lend(ticket, target.as_ptr(), &mut base) };
        if status != 0 {
            return Err(AdmissionError::Catalog(Error::Native(status)));
        }
        // Preserve accepted C custody BEFORE any fallible scope/post-call check.
        self.target = Some(target);
        self.base = NonNull::new(base.cast());
        let base = self
            .base
            .expect("accepted native stack source returned NULL");
        // The actual original factory installs tsk->stack before any ordinary
        // error can escape. No postcheck may disguise accepted descriptor refs.
        // Installer is bounded metadata by this unsafe producer's contract.
        Ok(install(base, bytes))
    }
    /// # Safety
    /// Original copy helpers reached their genuine nofail point. rank is the
    /// actual selected source policy/effective priority, and code/context/source
    /// graph are retained before entering native publication. After acceptance
    /// no original reverse unwind or ordinary no-publication errno is permitted.
    #[expect(
        clippy::result_large_err,
        reason = "exact original child/pin/marker owner"
    )]
    pub unsafe fn publish_dormant(
        self,
        entered: &dyn EnteredProcess,
        rank: scheduling::Snapshot,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<DormantChildStackLease<'catalog, 'runtime, P, N>, (Self, AdmissionError)> {
        if let Err(error) = canonical_scope(self.catalog, entered) {
            return Err((self, error));
        }
        let (Some(ticket), Some(target)) = (self.ticket, self.target) else {
            return Err((self, AdmissionError::Catalog(Error::InvalidReservation)));
        };
        // SAFETY: exact admitted/lent child graph; bounded source lock context.
        let status = unsafe { stela_linux_page_stack_prepare_publish(&ticket, target.as_ptr()) };
        if status != 0 {
            return Err((self, AdmissionError::Catalog(Error::Native(status))));
        }
        let Self {
            catalog,
            native,
            ticket: kept_ticket,
            target: kept_target,
            base,
        } = self;
        // SAFETY: actual source nofail boundary; graph/code kept before publisher.
        match unsafe { native.publish_dormant(entered, rank, callback, context) } {
            Ok(native) => {
                // No fallible call or allocation separates accepted native work
                // from the source's private nofail descriptor transition. Its
                // actual tasklist/PID visibility must follow in the same source
                // nofail transaction, before original wake_up_new_task.
                // SAFETY: exact same source/current/exclusion and retained graph.
                unsafe {
                    stela_linux_page_stack_publish(&ticket, target.as_ptr());
                }
                Ok(DormantChildStackLease {
                    catalog,
                    native,
                    ticket,
                    target,
                })
            }
            Err((native, error)) => Err((
                Self {
                    catalog,
                    native,
                    ticket: kept_ticket,
                    target: kept_target,
                    base,
                },
                AdmissionError::Work(error),
            )),
        }
    }
    /// # Safety
    /// Original reverse unwind actually removed every unpublished source task,
    /// stack/page/alias/RCU user, including original free_thread_stack logical
    /// page release after any lend. Cancellation never normalizes live refs.
    #[expect(clippy::result_large_err, reason = "exact original native/C owner")]
    pub unsafe fn cancel(
        mut self,
        entered: &dyn EnteredProcess,
    ) -> Result<(), (Self, AdmissionError)> {
        if let Some(ticket) = self.ticket {
            if let Err(error) = canonical_scope(self.catalog, entered) {
                return Err((self, error));
            }
            // SAFETY: actual source reverse unwind and exact owned unpublished marker.
            let status = unsafe { stela_linux_page_stack_cancel(&ticket) };
            if status != 0 {
                return Err((self, AdmissionError::Catalog(Error::Native(status))));
            }
            self.ticket = None;
        }
        let Self {
            catalog,
            native,
            ticket,
            target,
            base,
        } = self;
        // SAFETY: source users joined and exact C marker already removed above.
        match unsafe { native.cancel(entered) } {
            Ok(()) => Ok(()),
            Err((native, error)) => Err((
                Self {
                    catalog,
                    native,
                    ticket,
                    target,
                    base,
                },
                AdmissionError::Work(error),
            )),
        }
    }
}
