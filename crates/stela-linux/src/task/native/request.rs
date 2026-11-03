use super::*;
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Request<K, P, N> {
    pub(super) fn mutation(&self) -> Result<Mutation<'_, K, P, N>, Error> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Busy)?;
        Ok(Mutation { request: self })
    }
    pub(super) fn notify(&self, event: u8) {
        self.events.fetch_or(event, Ordering::Release);
        self.broker.delivery.record();
    }
    pub(super) fn binding(&self) -> &Arc<TaskBinding<N>> {
        // SAFETY: immutable after LIVE publication until real final joins.
        unsafe { (&*self.binding.get().cast::<Option<Arc<TaskBinding<N>>>>()).as_ref() }
            .unwrap_or_else(|| fatal())
    }
    pub(super) fn record(&self) -> *mut CTask {
        self.record.load(Ordering::Acquire)
    }
    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
    pub(super) fn check(&self, owner: *const RawOwner, generation: Option<u64>) -> bool {
        owner == self.broker.kernel.raw()
            && generation.is_none_or(|v| v != 0 && v == self.generation())
    }
    pub(super) fn fault(&self, error: factory::Error) {
        // SAFETY: short exclusive mutation. Retain earlier diagnostics too;
        // none of their possible owners may finally drop in source/IF0 hooks.
        let old = unsafe { &mut **self.fault.get() }.replace(error);
        let _old = ManuallyDrop::new(old);
    }
    pub(super) fn errno(&self) -> i32 {
        let Ok(_mutation) = self.mutation() else {
            fatal()
        };
        // Only called AFTER successful affine NoPublication; this mapping is
        // the genuine original errno boundary, not cancellation classification.
        // SAFETY: the mutation guard pins this diagnostic for the errno projection.
        let fault = unsafe { &**self.fault.get() };
        match fault {
            Some(factory::Error::Admission(reason)) => work_errno(reason.error()),
            Some(factory::Error::Work(error)) => work_errno(*error),
            Some(factory::Error::Source(value)) if *value < 0 => *value,
            Some(factory::Error::WrongPhase) => -22,
            _ => -5,
        }
    }
    pub(super) fn advance(
        &self,
        step: impl FnOnce(
            OwnedChild<K, P, N>,
        ) -> Result<
            OwnedChild<K, P, N>,
            factory::Failure<'static, 'static, 'static, 'static, K, P, N>,
        >,
    ) -> Result<(), Error> {
        let mut mutation = self.mutation()?;
        let Owned::Child(child) = mutation.take() else {
            fatal()
        };
        let child = ManuallyDrop::new(child);
        match step(ManuallyDrop::into_inner(child)) {
            Ok(child) => {
                mutation.put(Owned::Child(child));
                Ok(())
            }
            Err(failure) => {
                let factory::Failure { error, child } = failure;
                self.fault(error);
                mutation.put(Owned::Child(child));
                Err(Error::WrongPhase)
            }
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "the transition returns the affine child directly to its request on refusal"
    )]
    pub(super) unsafe fn prefix(&self) -> Result<(), Error> {
        // One bounded native metadata loan. No original resource, fork,
        // kthread or WQ body can park or wait inside any of these leaf steps.
        // SAFETY: every transition in this loan is bounded metadata work.
        let result = unsafe {
            self.broker
                .kernel
                .platform()
                .with_process(|entered| self.advance(|child| child.prepare_prefix(entered)))
        };
        match result {
            Ok(outcome) => outcome,
            Err(error) => {
                let _mutation = self.mutation()?;
                self.fault(factory::Error::Work(error));
                Err(Error::Work(error))
            }
        }
    }
    pub(super) unsafe fn cancel(&self) -> Result<(), Error> {
        let mut mutation = self.mutation()?;
        let state = mutation.take();
        if let Owned::NoPublication(receipt) = state {
            mutation.put(Owned::NoPublication(receipt));
            return Ok(());
        }
        let Owned::Child(child) = state else { fatal() };
        // Keep the child outside the closure so admission refusal returns the
        // same owner to the request without consuming the cancellation state.
        let mut kept = ManuallyDrop::new(Some(child));
        // SAFETY: the same creator holds the mutation guard. Cancellation is
        // bounded metadata work and checks the source unwind receipt itself.
        let result = unsafe {
            self.broker.kernel.platform().with_process(|entered| {
                let child = kept.take().unwrap_or_else(|| fatal());
                match child.cancel_unpublished(entered) {
                    Ok(receipt) => {
                        mutation.put(Owned::NoPublication(receipt));
                        Ok(())
                    }
                    Err(factory::Failure { error, child }) => {
                        self.fault(error);
                        mutation.put(Owned::Child(child));
                        Err(Error::WrongPhase)
                    }
                }
            })
        };
        match result {
            Ok(outcome) => outcome,
            Err(error) => {
                let child = kept.take().unwrap_or_else(|| fatal());
                mutation.put(Owned::Child(child));
                Err(Error::Work(error))
            }
        }
    }
    pub(super) unsafe fn prepare_thread(
        &self,
        entry: Option<NativeEntry>,
        argument: *mut c_void,
    ) -> i32 {
        let Ok(_mutation) = self.mutation() else {
            return -16;
        };
        if entry.is_none() || self.prepared.load(Ordering::Acquire) {
            return -22;
        }
        // SAFETY: source-authenticated callback/argument ownership is retained
        // through actual original child/module lifetime. No call/publication.
        unsafe {
            *self.entry.get() = entry.map(|run| (run, argument));
        }
        self.prepared.store(true, Ordering::Release);
        0
    }
    pub(super) unsafe fn publish(&self, rank: &Rank) {
        if !self.prepared.load(Ordering::Acquire) {
            fatal();
        }
        let Ok(snapshot) = rank.snapshot() else {
            fatal()
        };
        // SAFETY: separate heap Context exists BEFORE any native/C publication,
        // never the address of movable Child; no owning backpointer.
        let context = unsafe { &**self.context.get() }
            .as_deref()
            .unwrap_or_else(|| fatal());
        let pointer = ptr::from_ref(context).cast_mut().cast::<c_void>();
        // SAFETY: the exact callback context is retained and publication performs bounded metadata work.
        let result = unsafe {
            self.broker.kernel.platform().with_process(|entered| {
                self.advance(|child| {
                    child.publish_dormant(entered, snapshot, run::<K, P, N> as Callback, pointer)
                })
            })
        };
        if !matches!(result, Ok(Ok(()))) {
            fatal();
        }
    }
    pub(super) unsafe fn activate(&self) {
        // SAFETY: the process segment is borrowed only for the bounded activation transition.
        let result = unsafe {
            self.broker
                .kernel
                .platform()
                .with_process(|entered| self.advance(|child| child.activate(entered)))
        };
        if !matches!(result, Ok(Ok(()))) {
            fatal();
        }
    }
}
fn work_errno(error: WorkError) -> i32 {
    match error {
        WorkError::Full => -12,
        WorkError::Unavailable => -95,
        WorkError::Busy | WorkError::Pending => -16,
        WorkError::Closed => -108,
        _ => -5,
    }
}
unsafe extern "C" fn run<
    K: KernelThreadPlatform + 'static,
    P: Provider + 'static,
    const N: usize,
>(
    context: *mut c_void,
) {
    if context.is_null() {
        fatal();
    }
    // SAFETY: stable Box retained by registry through actual native return and
    // every source/IRQ callback-tail join; no self owning Arc/reference cycle.
    let request = unsafe {
        (&*context.cast::<CallbackContext<K, P, N>>())
            .request
            .as_ref()
    };
    if request.entered.swap(true, Ordering::AcqRel) || !request.prepared.load(Ordering::Acquire) {
        fatal();
    }
    let binding = request.binding();
    if binding.bind_current(request.broker.runtime).is_err() {
        fatal();
    }
    // No mutation guard, registry reader, RefCell/queue borrow or transient
    // EnteredProcess survives this genuine original possibly-waiting body.
    // SAFETY: the original callback retains the request and has bound the exact current context.
    let result = unsafe {
        binding.run_scoped(
            request.broker.runtime,
            stela_linux_task_run_original,
            request.record().cast(),
        )
    };
    let _ = result;
    fatal(); // real do_exit/native terminate must never return.
}
