//! Actual nofail source publication and its later first runnable wake.
use super::*;
impl<'factory, 'kernel, 'catalog, 'runtime, K: KernelThreadPlatform, P: Provider, const N: usize>
    Child<'factory, 'kernel, 'catalog, 'runtime, K, P, N>
{
    /// # Safety
    /// Actual original copy_process reached its nofail tasklist/PID publication
    /// point for this child. rank comes from its original policy/effective rank,
    /// not a default. Callback, module/code, data and source graph are retained
    /// BEFORE this call and through unknown publication/native return tails.
    /// No ordinary original bad_fork rollback follows native acceptance.
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) unsafe fn publish_dormant(
        self,
        entered: &dyn EnteredProcess,
        rank: scheduling::Snapshot,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<Self, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        match this.take_state() {
            State::Prepared {
                lease,
                exposure: Exposure::Lent,
            } => {
                // SAFETY: exact original source nofail/publication contract.
                match unsafe { lease.publish_dormant(entered, rank, callback, context) } {
                    Ok(lease) => {
                        this.keep(State::Dormant(lease));
                        Ok(ManuallyDrop::into_inner(this))
                    }
                    Err((lease, error)) => {
                        this.keep(State::Prepared {
                            lease,
                            exposure: Exposure::Lent,
                        });
                        Err(ManuallyDrop::into_inner(this).fail(Error::Pages(error)))
                    }
                }
            }
            state => {
                this.keep(state);
                Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase))
            }
        }
    }
    /// No job/worker/order allocation: this activates the exact pre-reserved
    /// dormant job only at original wake_up_new_task after real C visibility.
    /// # Safety
    /// Actual source tasklist/PID/resource publication and its first wake have
    /// completed for this exact owned child. Uncertainty keeps the whole graph.
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) unsafe fn activate(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<Self, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        match this.take_state() {
            // SAFETY: actual original visibility + first wake is the caller
            // contract; exact owned lease validates native state/epoch separately.
            State::Dormant(lease) => match unsafe { lease.activate(entered) } {
                Ok(lease) => {
                    this.keep(State::Published(lease));
                    Ok(ManuallyDrop::into_inner(this))
                }
                Err((lease, error)) => {
                    this.keep(State::Dormant(lease));
                    Err(ManuallyDrop::into_inner(this).fail(Error::Pages(error)))
                }
            },
            state => {
                this.keep(state);
                Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase))
            }
        }
    }
    /// Existing native assignment only; never a current/source/stack grant.
    pub(crate) fn assigned(&self) -> Option<AssignedGeneral> {
        match &*self.state {
            State::Dormant(lease) => Some(lease.assigned()),
            State::Published(lease) => Some(lease.assigned()),
            _ => None,
        }
    }
    /// Observe only this exact kept Published native/page owner. No event bit,
    /// source pointer or task metadata can manufacture native completion.
    pub(crate) fn physically_returned(&self) -> Result<bool, Error> {
        match &*self.state {
            State::Published(lease) => lease.physically_returned().map_err(Error::Pages),
            _ => Err(Error::WrongPhase),
        }
    }
    /// # Safety
    /// Actual source final task/stack/page/alias/RCU users and producer closure
    /// joined. Exact native physical return is separately checked by the lease.
    pub(crate) unsafe fn retire_descriptors(
        &mut self,
        entered: &dyn EnteredProcess,
    ) -> Result<(), Error> {
        let State::Published(lease) = &mut *self.state else {
            return Err(Error::WrongPhase);
        };
        // SAFETY: caller provides genuine source retirement, never refcount or
        // ticket inference; same owned lease independently checks native join.
        unsafe { lease.retire_descriptors(entered) }.map_err(Error::Pages)
    }
    /// # Safety
    /// Source descriptors already retired, original C/task/RCU lifetimes joined,
    /// native binding detached, and this is actual taskless architectural
    /// dispatcher successor (outside ALL constructor stacks), not a C reaper.
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) unsafe fn release(
        self,
    ) -> Result<RetiredMetadata<N>, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        match this.take_state() {
            // SAFETY: actual original joins, descriptor retirement and
            // off-all-stacks dispatcher are this method's required contract.
            State::Published(lease) => match unsafe { lease.release() } {
                Ok(()) => {
                    // Only the actual source metadata owner remains. Its final
                    // release is parent's distinct original-record operation.
                    Ok(RetiredMetadata {
                        binding: this.take_binding(),
                        generation: this.identity.generation,
                    })
                }
                Err((lease, error)) => {
                    this.keep(State::Published(lease));
                    Err(ManuallyDrop::into_inner(this).fail(Error::Pages(error)))
                }
            },
            state => {
                this.keep(state);
                Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase))
            }
        }
    }
}
/// Exact native/page/source release joined; metadata still must be explicitly
/// retired by its actual owner. Default abandonment retains it.
pub(crate) struct RetiredMetadata<const N: usize> {
    binding: ManuallyDrop<Arc<TaskBinding<N>>>,
    generation: u64,
}

impl<const N: usize> RetiredMetadata<N> {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    /// Moves only metadata retention, never an additional retirement grant.
    pub(crate) fn into_metadata(self) -> Arc<TaskBinding<N>> {
        ManuallyDrop::into_inner(self.binding)
    }
}
