//! Short native metadata steps. No process permit survives a method return.
use super::*;
impl<'factory, 'kernel, 'catalog, 'runtime, K: KernelThreadPlatform, P: Provider, const N: usize>
    Child<'factory, 'kernel, 'catalog, 'runtime, K, P, N>
{
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) fn reserve(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<Self, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        let state = this.take_state();
        if !matches!(state, State::Born) {
            this.keep(state);
            return Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase));
        }
        let requirement = match super::super::stack_requirement() {
            Ok(value) => value,
            Err(error) => {
                this.keep(State::Born);
                return Err(ManuallyDrop::into_inner(this).fail(Error::Work(error)));
            }
        };
        match this.factory.runtime.reserve_general(entered, requirement) {
            Err(error) => {
                this.keep(State::Born);
                Err(ManuallyDrop::into_inner(this).fail(Error::Admission(error)))
            }
            Ok(reservation) => match reservation.into_owned() {
                Ok(owner) => {
                    this.keep(State::Owned(owner));
                    Ok(ManuallyDrop::into_inner(this))
                }
                Err(failure) => {
                    let error = failure.error;
                    this.keep(State::TransferFailed(failure));
                    Err(ManuallyDrop::into_inner(this).fail(Error::Work(error)))
                }
            },
        }
    }
    /// # Safety
    /// Every original old task/page/alias/RCU user of the selected real idle
    /// worker actually retired. Native release/return receipts alone are not
    /// this foreign-user proof; no source stack has been lent in this attempt.
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) unsafe fn prepare(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<Self, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        match this.take_state() {
            // SAFETY: original old foreign-user retirement is this method's
            // explicit caller contract; native owner proves identity/return.
            State::Owned(owner) => match unsafe { owner.prepare_stack(entered) } {
                Ok(owner) => {
                    this.keep(State::Preparing(owner));
                    Ok(ManuallyDrop::into_inner(this))
                }
                Err((owner, error)) => {
                    this.keep(State::Preparing(owner));
                    Err(ManuallyDrop::into_inner(this).fail(Error::Work(error)))
                }
            },
            state => {
                this.keep(state);
                Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase))
            }
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) fn pin(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<Self, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        match this.take_state() {
            State::Preparing(owner) => match owner.pin(entered) {
                Ok(owner) => {
                    this.keep(State::Pinned(owner));
                    Ok(ManuallyDrop::into_inner(this))
                }
                Err((owner, error)) => {
                    this.keep(State::Preparing(owner));
                    Err(ManuallyDrop::into_inner(this).fail(Error::Pin(error)))
                }
            },
            state => {
                this.keep(state);
                Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase))
            }
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) fn admit(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<Self, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        match this.take_state() {
            State::Pinned(owner) => {
                let catalog = this.factory.catalog;
                this.keep(State::Admission(catalog.prepare_stack(owner)));
            }
            state => {
                this.keep(state);
                return Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase));
            }
        }
        let State::Admission(owner) = &mut *this.state else {
            unreachable!()
        };
        match owner.admit(entered) {
            Ok(()) => Ok(ManuallyDrop::into_inner(this)),
            Err(error) => Err(ManuallyDrop::into_inner(this).fail(Error::Pages(error))),
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) fn reconstruct(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<Self, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        match this.take_state() {
            State::Admission(owner) => match owner.reconstruct_child(entered) {
                Ok(lease) => {
                    this.keep(State::Prepared {
                        lease,
                        exposure: Exposure::Unlent,
                    });
                    Ok(ManuallyDrop::into_inner(this))
                }
                Err((owner, error)) => {
                    this.keep(State::Admission(owner));
                    Err(ManuallyDrop::into_inner(this).fail(Error::Pages(error)))
                }
            },
            state => {
                this.keep(state);
                Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase))
            }
        }
    }
    /// Lend/install in the SAME actual original factory record. No error can
    /// be returned after descriptor acceptance but before tsk->stack install.
    /// # Safety
    /// Original source constructor/current/root remains owned, no resource wait,
    /// reentry or switch occurs in the synchronous C metadata installer.
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) unsafe fn lend(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<Self, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        let target = this.identity.target;
        let task = this.binding.task;
        let owner = this.factory.kernel.raw();
        let State::Prepared { lease, exposure } = &mut *this.state else {
            return Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase));
        };
        if *exposure != Exposure::Unlent {
            return Err(ManuallyDrop::into_inner(this).fail(Error::WrongPhase));
        }
        *exposure = Exposure::Lending;
        // SAFETY: actual private source identity and same retained prepared
        // descriptor/native owner; C installer performs no fallible setup.
        let result = unsafe {
            lease.lend(entered, target, |base, bytes| {
                stela_linux_task_child_install_stack(
                    task.as_ptr(),
                    owner,
                    base.as_ptr().cast(),
                    bytes,
                );
            })
        };
        match result {
            Ok(()) => {
                *exposure = Exposure::Lent;
                Ok(ManuallyDrop::into_inner(this))
            }
            Err(error) => {
                // This exact lease API returns ordinary Err only BEFORE C
                // acceptance. Accepted descriptors preserve target/base and
                // installer is void; panic leaves Lending + whole graph kept.
                *exposure = Exposure::Unlent;
                Err(ManuallyDrop::into_inner(this).fail(Error::Pages(error)))
            }
        }
    }
}
