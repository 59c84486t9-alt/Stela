//! Short native metadata steps. No process permit survives a method return.
use super::*;
impl<'factory, 'kernel, 'catalog, 'runtime, K: KernelThreadPlatform, P: Provider, const N: usize>
    Child<'factory, 'kernel, 'catalog, 'runtime, K, P, N>
{
    /// Run the constructor's preparation steps under one metadata borrow.
    ///
    /// # Safety
    /// The caller owns the original constructor and the entered process for
    /// this child, including the old-user retirement and C lending contracts.
    pub(crate) unsafe fn prepare_prefix(
        &mut self,
        entered: &dyn EnteredProcess,
    ) -> Result<(), Error> {
        self.reserve(entered)?;
        // SAFETY: the caller owns this constructor and its retired old user.
        unsafe { self.prepare(entered) }?;
        self.pin(entered)?;
        self.admit(entered)?;
        self.reconstruct(entered)?;
        // SAFETY: reconstruction produced this exact child for synchronous C lending.
        unsafe { self.lend(entered) }
    }

    fn reserve(&mut self, entered: &dyn EnteredProcess) -> Result<(), Error> {
        let state = self.take_state();
        if !matches!(state, State::Born) {
            self.keep(state);
            return Err(Error::WrongPhase);
        }
        let requirement = match super::super::stack_requirement() {
            Ok(value) => value,
            Err(error) => {
                self.keep(State::Born);
                return Err(Error::Work(error));
            }
        };
        match self.factory.runtime.reserve_general(entered, requirement) {
            Err(error) => {
                self.keep(State::Born);
                Err(Error::Admission(error))
            }
            Ok(reservation) => match reservation.into_owned() {
                Ok(owner) => {
                    self.keep(State::Owned(owner));
                    Ok(())
                }
                Err(failure) => {
                    let error = failure.error;
                    self.keep(State::TransferFailed(failure));
                    Err(Error::Work(error))
                }
            },
        }
    }
    /// # Safety
    /// Every original old task/page/alias/RCU user of the selected real idle
    /// worker actually retired. Native release/return receipts alone are not
    /// this foreign-user proof; no source stack has been lent in this attempt.
    unsafe fn prepare(&mut self, entered: &dyn EnteredProcess) -> Result<(), Error> {
        match self.take_state() {
            // SAFETY: original old foreign-user retirement is this method's
            // explicit caller contract; native owner proves identity/return.
            State::Owned(owner) => match unsafe { owner.prepare_stack(entered) } {
                Ok(owner) => {
                    self.keep(State::Preparing(owner));
                    Ok(())
                }
                Err((owner, error)) => {
                    self.keep(State::Preparing(owner));
                    Err(Error::Work(error))
                }
            },
            state => {
                self.keep(state);
                Err(Error::WrongPhase)
            }
        }
    }
    fn pin(&mut self, entered: &dyn EnteredProcess) -> Result<(), Error> {
        match self.take_state() {
            State::Preparing(owner) => match owner.pin(entered) {
                Ok(owner) => {
                    self.keep(State::Pinned(owner));
                    Ok(())
                }
                Err((owner, error)) => {
                    self.keep(State::Preparing(owner));
                    Err(Error::Pin(error))
                }
            },
            state => {
                self.keep(state);
                Err(Error::WrongPhase)
            }
        }
    }
    fn admit(&mut self, entered: &dyn EnteredProcess) -> Result<(), Error> {
        match self.take_state() {
            State::Pinned(owner) => {
                let catalog = self.factory.catalog;
                self.keep(State::Admission(catalog.prepare_stack(owner)));
            }
            state => {
                self.keep(state);
                return Err(Error::WrongPhase);
            }
        }
        let State::Admission(owner) = &mut *self.state else {
            unreachable!()
        };
        owner.admit(entered).map_err(Error::Pages)
    }
    fn reconstruct(&mut self, entered: &dyn EnteredProcess) -> Result<(), Error> {
        match self.take_state() {
            State::Admission(owner) => match owner.reconstruct_child(entered) {
                Ok(lease) => {
                    self.keep(State::Prepared {
                        lease,
                        exposure: Exposure::Unlent,
                    });
                    Ok(())
                }
                Err((owner, error)) => {
                    self.keep(State::Admission(owner));
                    Err(Error::Pages(error))
                }
            },
            state => {
                self.keep(state);
                Err(Error::WrongPhase)
            }
        }
    }
    /// Lend/install in the SAME actual original factory record. No error can
    /// be returned after descriptor acceptance but before tsk->stack install.
    /// # Safety
    /// Original source constructor/current/root remains owned, no resource wait,
    /// reentry or switch occurs in the synchronous C metadata installer.
    unsafe fn lend(&mut self, entered: &dyn EnteredProcess) -> Result<(), Error> {
        let target = self.identity.target;
        let task = self.binding.task;
        let owner = self.factory.kernel.raw();
        let State::Prepared { lease, exposure } = &mut *self.state else {
            return Err(Error::WrongPhase);
        };
        if *exposure != Exposure::Unlent {
            return Err(Error::WrongPhase);
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
                Ok(())
            }
            Err(error) => {
                // This exact lease API returns ordinary Err only BEFORE C
                // acceptance. Accepted descriptors preserve target/base and
                // installer is void; panic leaves Lending + whole graph kept.
                *exposure = Exposure::Unlent;
                Err(Error::Pages(error))
            }
        }
    }
}
