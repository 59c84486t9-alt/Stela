use super::*;
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>
    RequestHandle<K, P, N>
{
    /// Exact retained native/page owner query. NOT terminal event/source flag.
    /// Child::physically_returned is a REQUIRED narrow forwarding dependency;
    /// no success stub, callback-presence readiness or ticket inference here.
    pub(crate) fn physically_returned(&self) -> Result<bool, Error> {
        let _mutation = self.request.mutation()?;
        // SAFETY: short exclusive metadata observation; no original body/wait.
        let state = unsafe { &*self.request.state.get().cast::<Owned<K, P, N>>() };
        match state {
            Owned::Child(child) => child.physically_returned().map_err(Error::Native),
            _ => Err(Error::WrongPhase),
        }
    }
    /// # Safety
    /// Real original process supervisor/current, no native borrowed permit,
    /// registry reader, child-state/queue/RefCell borrow over source waits.
    pub(crate) unsafe fn reap_source(&self) -> Result<(), Error> {
        if !self.physically_returned()? {
            return Err(Error::Work(WorkError::Pending));
        }
        let request = &self.request;
        // The observation guard above returned BEFORE possibly waiting C.
        // SAFETY: the exact native ticket physically returned and the caller owns the source reap.
        unsafe {
            request
                .binding()
                .reap_source(&request.broker.kernel, request.generation())
        }
        .map_err(source_error)
    }
    /// # Safety
    /// Same genuine source supervisor after actual reap; original RCU barrier
    /// may wait. No native loan or mutable child/registry guard survives here.
    pub(crate) unsafe fn join_source(&self) -> Result<(), Error> {
        let request = &self.request;
        // SAFETY: the caller has reaped this source and holds no segment loan across the join.
        unsafe {
            request
                .binding()
                .join_source(&request.broker.kernel, request.generation())
        }
        .map_err(source_error)
    }
    /// # Safety
    /// Actual source join succeeded and every original task/page/alias/RCU user
    /// retired, not a bit/refcount. Owned lease checks native physical return
    /// and independently checks every actual C descriptor reference.
    pub(crate) unsafe fn retire_descriptors(&self) -> Result<(), Error> {
        let request = &self.request;
        // SAFETY: the closure performs a bounded descriptor transition after the source join.
        let result = unsafe {
            request.broker.kernel.platform().with_process(|entered| {
                let _mutation = request.mutation()?;
                // SAFETY: short exclusive same-owner canonical descriptor action.
                let state = &mut *request.state.get().cast::<Owned<K, P, N>>();
                match state {
                    Owned::Child(child) => child.retire_descriptors(entered).map_err(Error::Native),
                    _ => Err(Error::WrongPhase),
                }
            })
        };
        result.map_err(Error::Work)?
    }
    /// # Safety
    /// Actual taskless native architectural successor outside ALL constructor
    /// stacks after real C/source/page/RCU joins. This cannot run on C reaper.
    /// Binding owner is retained, never finally dropped in IF0/source hook.
    pub(crate) unsafe fn release_native(&self) -> Result<(), Error> {
        let request = &self.request;
        let mut mutation = request.mutation()?;
        let state = mutation.take();
        let Owned::Child(child) = state else { fatal() };
        let Some(assigned) = child.assigned() else {
            mutation.put(Owned::Child(child));
            return Err(Error::WrongPhase);
        };
        let child = ManuallyDrop::new(child);
        // SAFETY: same short mutation, detached owner is immutable once stored.
        if unsafe { &**request.detached.get() }.is_none() {
            // SAFETY: the dispatcher has joined physical return and owns the assigned binding.
            match unsafe { request.broker.runtime.detach_binding(assigned.context_id()) } {
                // SAFETY: the mutation guard gives exclusive access to the empty detached slot.
                Ok(binding) => unsafe {
                    **request.detached.get() = Some(binding);
                },
                Err(error) => {
                    mutation.put(Owned::Child(ManuallyDrop::into_inner(child)));
                    return Err(Error::Work(error));
                }
            }
        }
        // SAFETY: the taskless dispatcher holds the joined child and its detached owner.
        match unsafe { ManuallyDrop::into_inner(child).release() } {
            Ok(receipt) => {
                mutation.put(Owned::Retired(receipt));
                Ok(())
            }
            Err(failure) => {
                let factory::Failure { error, child } = failure;
                request.fault(error);
                mutation.put(Owned::Child(child));
                Err(Error::WrongPhase)
            }
        }
    }
}
fn source_error(error: super::super::ResourceBootstrapError) -> Error {
    match error {
        super::super::ResourceBootstrapError::Native(value) => Error::Source(value),
        super::super::ResourceBootstrapError::Work(error) => Error::Work(error),
    }
}
