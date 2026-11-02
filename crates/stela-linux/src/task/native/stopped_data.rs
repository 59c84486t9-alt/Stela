//! Exact stopped metric publication before genuine source-task join.
use super::*;
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Request<K, P, N> {
    fn take_data_stop(&self) -> Result<StoppedDataState, Error> {
        let _mutation = self.mutation()?;
        // SAFETY: one actual PID1 consumer; move the affine owner OUT before
        // any original put/destructor/RCU code that may wait or notify us.
        Ok(unsafe {
            mem::replace(
                &mut *self.data_stop.get().cast::<StoppedDataState>(),
                StoppedDataState::Transitioning,
            )
        })
    }
    fn keep_data_stop(&self, state: StoppedDataState) {
        let state = ManuallyDrop::new(state);
        let Ok(_mutation) = self.mutation() else {
            // Actual owner remains retained even on impossible reentrant
            // mutation; do not drop a stop token or invent successful cleanup.
            fatal()
        };
        // SAFETY: fresh short metadata guard, no original C or wait in scope.
        unsafe {
            *self.data_stop.get().cast::<StoppedDataState>() = ManuallyDrop::into_inner(state);
        }
    }
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>
    RequestHandle<K, P, N>
{
    /// # Safety
    /// Actual original PID1 process after exact physical-return observation
    /// and scheduler-ref reap. Source callbacks only atomically record/wake.
    /// No caller registry/state/queue/RefCell/native loan spans this method's
    /// original release_source call. It is never a native dispatcher operation.
    pub(super) unsafe fn stop_source_data(&self) -> Result<(), Error> {
        let request = &self.request;
        let state = ManuallyDrop::new(request.take_data_stop()?);
        let stopped = match ManuallyDrop::into_inner(state) {
            StoppedDataState::Unclaimed => {
                // SAFETY: fresh bounded process metadata ONLY. Actual native
                // physical-return and IRQ-reader stop token are created by the
                // frozen producer, not terminal/source bits or stop presence.
                let result = unsafe {
                    request.broker.kernel.platform().with_process(|_entered| {
                        request.binding().stop_data(request.broker.runtime)
                    })
                };
                match result {
                    Ok(Ok(owner)) => owner,
                    Ok(Err(error)) => {
                        // The producer can quarantine accepted token on a
                        // corrupt identity refusal. An errno proves no stage.
                        request.keep_data_stop(StoppedDataState::Uncertain);
                        return Err(Error::Work(error));
                    }
                    Err(error) => {
                        // Outer admission error means body NEVER ran.
                        request.keep_data_stop(StoppedDataState::Unclaimed);
                        return Err(Error::Work(error));
                    }
                }
            }
            StoppedDataState::Stopped(owner) => owner,
            StoppedDataState::SourceReleased(owner) => {
                return unsafe { self.finish_data_stop(owner) };
            }
            StoppedDataState::Finished => {
                request.keep_data_stop(StoppedDataState::Finished);
                return Ok(());
            }
            state => {
                request.keep_data_stop(state);
                return Err(Error::WrongPhase);
            }
        };
        // Retain actual affine owner before possible source C destructor/
        // wait. There is NO mutation, row reader or EnteredProcess here.
        let stopped = ManuallyDrop::new(stopped);
        // SAFETY: genuine PID1 source current, stopped native/IRQ token kept;
        // source release cannot be inferred from publication flags or errno.
        match unsafe { ManuallyDrop::into_inner(stopped).release_source(&request.broker.kernel) } {
            Ok(owner) => unsafe { self.finish_data_stop(owner) },
            Err((owner, error)) => {
                request.keep_data_stop(StoppedDataState::Stopped(owner));
                Err(data_error(error))
            }
        }
    }
    /// Source C put and callback tail returned BEFORE entering this scope.
    unsafe fn finish_data_stop(&self, owner: StoppedTaskData) -> Result<(), Error> {
        let request = &self.request;
        // Captured by mutable reference, NOT moved into a possibly uninvoked
        // closure: outer Err returns the same exact owner to request storage.
        let mut kept = ManuallyDrop::new(Some(owner));
        // SAFETY: fresh bounded native metadata scope; no source body/wait.
        let result = unsafe {
            request.broker.kernel.platform().with_process(|entered| {
                let owner = kept.take().unwrap_or_else(|| fatal());
                // SAFETY: exact affine owner after actual C source release/tail.
                match owner.finish(entered) {
                    Ok(()) => Ok(()),
                    Err((owner, error)) => {
                        *kept = Some(owner);
                        Err(error)
                    }
                }
            })
        };
        match result {
            Ok(Ok(())) => {
                if kept.is_some() {
                    fatal();
                }
                request.keep_data_stop(StoppedDataState::Finished);
                Ok(())
            }
            Ok(Err(error)) | Err(error) => {
                // An ordinary outer Err AFTER a consumed body would violate
                // with_process's no-body-on-Err contract; never fabricate owner.
                let owner = kept.take().unwrap_or_else(|| fatal());
                request.keep_data_stop(StoppedDataState::SourceReleased(owner));
                Err(Error::Work(error))
            }
        }
    }
}
fn data_error(error: super::super::ResourceBootstrapError) -> Error {
    match error {
        super::super::ResourceBootstrapError::Work(error) => Error::Work(error),
        super::super::ResourceBootstrapError::Native(error) => Error::Source(error),
    }
}
