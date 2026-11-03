//! Actual PID1 source disposal and its distinct taskless native successor.
//! Every retry below is triggered by an actual event, never periodic polling.
use super::*;
const NEED_REAP: u8 = 0;
const NEED_JOIN: u8 = 1;
const NEED_DATA_STOP: u8 = 5;
const NEED_DISPATCH: u8 = 2;
const DISPATCH_DONE: u8 = 3;
const BLOCKED: u8 = 4;
unsafe extern "C" {
    fn stela_linux_task_source_broker_wake(owner: *const RawOwner) -> i32;
    fn stela_linux_task_child_tails_joined(
        task: *mut CTask,
        owner: *const RawOwner,
        generation: u64,
    ) -> i32;
}
enum Progress {
    Keep,
    Finalize,
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Mounted<K, P, N> {
    /// Deliver ONLY an actual recorded service event from real canonical
    /// source process context after all passive/IRQ leaf scopes have ended.
    /// # Safety
    /// Genuine Initial/Managed source current, never bare, no transient native
    /// permit/RefCell/C-lock/leaf callback. C independently authenticates it.
    pub(crate) unsafe fn service_delivery(&self) -> Result<bool, Error> {
        let event = self.broker.delivery.epoch.load(Ordering::Acquire);
        if self.broker.delivery.blocked_until.load(Ordering::Acquire) == event {
            return Ok(false);
        }
        if !self.broker.delivery.pending.swap(false, Ordering::AcqRel) {
            return Ok(false);
        }
        // SAFETY: the caller supplies the retained owner in authenticated source process context.
        let value = unsafe { stela_linux_task_source_broker_wake(self.broker.kernel.raw()) };
        if value != 0 {
            self.broker.delivery.pending.store(true, Ordering::Release);
            self.broker
                .delivery
                .blocked_until
                .store(event, Ordering::Release);
            return Err(Error::Source(value));
        }
        Ok(true)
    }
    /// # Safety
    /// Actual taskless native dispatcher AFTER physical return, outside every
    /// constructor stack and source callback/borrow. No C process body here.
    pub(crate) unsafe fn dispatcher_step(&self) -> Result<bool, Error> {
        // SAFETY: the caller has joined physical return and is in the taskless dispatcher.
        unsafe { self.broker.dispatcher_step() }
    }
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Broker<K, P, N> {
    pub(super) fn pending(&self) -> bool {
        if self.managed.pending() {
            return true;
        }
        for slot in &self.slots {
            if slot.finalize_pending.load(Ordering::Acquire) {
                return true;
            }
            let read = slot.read();
            if !read.pointer.is_null()
                // SAFETY: the read guard pins the non-null request for this event check.
                && unsafe { &*read.pointer }.events.load(Ordering::Acquire) != 0
            {
                return true;
            }
        }
        false
    }
    pub(super) unsafe fn process_one(&self) -> i32 {
        // First consume an actual last-reader/observer release event. No scan
        // retries a waiting owner merely because a timer/service tick happened.
        for slot in &self.slots {
            if !slot.finalize_pending.swap(false, Ordering::AcqRel) {
                continue;
            }
            // SAFETY: PID1 exclusively owns these affine retirement slots.
            return unsafe { self.finish_slot(slot) };
        }
        let event = match self.next_event() {
            Ok(Some(event)) => event,
            // Actual PID1 now consumes one managed source constructor request
            // after native/source retirement work; no native loan spans C.
            // SAFETY: PID1 is in source process context without a native segment loan.
            Ok(None) => return unsafe { self.managed.process_one() },
            Err(_) => return -5,
        };
        let Event { kind, request } = event;
        // SAFETY: the event handle pins the exact request throughout the PID1 source operation.
        let result = unsafe { request.process_event(kind) };
        match result {
            Ok(Progress::Keep) => {
                // SAFETY: the registry or retiring slot still owns the request.
                unsafe { request.put() };
                1
            }
            Ok(Progress::Finalize) => {
                let slot = request.request.slot;
                // SAFETY: Finalize certifies joined native return and source producer tails.
                match unsafe { request.unpublish() } {
                    Ok(retiring) => {
                        // Actual source/native joins precede unpublish. Store
                        // the affine retiring control BEFORE any reader check.
                        // SAFETY: PID1 is the only writer of the retiring slot.
                        unsafe {
                            **slot.retiring.get() = Some(retiring);
                        }
                        // SAFETY: PID1 owns retirement and has installed the affine retiring control.
                        unsafe { self.finish_slot(slot) }
                    }
                    Err(request) => {
                        // SAFETY: the registry or retiring slot still owns the request.
                        unsafe { request.put() };
                        -16
                    }
                }
            }
            Err(error) => {
                // SAFETY: the registry or retiring slot still owns the request.
                unsafe { request.put() };
                process_errno(error)
            }
        }
    }
    unsafe fn finish_slot(&self, slot: &Slot<K, P, N>) -> i32 {
        // Single actual PID1 receiver. Callback/dispatcher only touch atomic
        // flags, never these affine source/native finalization controls.
        // SAFETY: only PID1 accesses the retiring slot.
        if let Some(retiring) = unsafe { &mut **slot.retiring.get() }.take() {
            // SAFETY: the retiring handle follows the actual tail joins and checks independent readers.
            match unsafe { retiring.finish() } {
                // SAFETY: PID1 exclusively installs the final metadata before releasing it.
                Ok(metadata) => unsafe {
                    **slot.final_metadata.get() = Some(metadata);
                },
                Err(retiring) => {
                    // SAFETY: PID1 restores the same affine control for the next event.
                    unsafe {
                        **slot.retiring.get() = Some(retiring);
                    }
                    // Expected retained wait, not a supervisor-fatal error.
                    // Only actual last-reader/observer release enqueues retry;
                    // consumed finalize_pending is NOT set again here.
                    return 0;
                }
            }
        }
        // SAFETY: only PID1 takes final metadata, and the borrow ends before release.
        if let Some(metadata) = unsafe { &mut **slot.final_metadata.get() }.take() {
            // SAFETY: PID1 has joined the original producer tails and holds no native loan.
            match unsafe { metadata.release() } {
                Ok(()) => 1,
                Err(metadata) => {
                    // SAFETY: PID1 restores the exact metadata that release returned.
                    unsafe {
                        **slot.final_metadata.get() = Some(metadata);
                    }
                    // Unexpected external binding retention has no fabricated
                    // progress event. Retain+report; lifecycle owner must join
                    // the actual producer, not infer completion from Arc count.
                    -16
                }
            }
        } else {
            0
        }
    }
    unsafe fn dispatcher_step(&self) -> Result<bool, Error> {
        for slot in &self.slots {
            if !slot.dispatch_pending.swap(false, Ordering::AcqRel) {
                continue;
            }
            let read = slot.read();
            if read.pointer.is_null() {
                fatal();
            }
            // SAFETY: the read guard pins the registry Arc while acquiring another reference.
            unsafe { Arc::increment_strong_count(read.pointer) };
            // SAFETY: this takes the additional strong reference acquired above.
            let arc = unsafe { Arc::from_raw(read.pointer) };
            drop(read);
            let handle = RequestHandle {
                request: ManuallyDrop::new(arc),
                _affine: PhantomData,
            };
            // SAFETY: the taskless dispatcher runs after the actual physical return and holds the exact handle.
            let result = unsafe { handle.release_native() };
            match result {
                Ok(()) => {
                    handle
                        .request
                        .service_stage
                        .store(DISPATCH_DONE, Ordering::Release);
                    handle.request.notify(NATIVE_RELEASED);
                    // SAFETY: the registry retains the request after the dispatcher notification.
                    unsafe { handle.put() };
                    return Ok(true);
                }
                Err(error) => {
                    handle
                        .request
                        .service_stage
                        .store(BLOCKED, Ordering::Release);
                    handle.request.notify(FAILED);
                    // SAFETY: the registry retains the request after the dispatcher notification.
                    unsafe { handle.put() };
                    return Err(error);
                }
            }
        }
        Ok(false)
    }
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>
    RequestHandle<K, P, N>
{
    unsafe fn process_event(&self, kind: EventKind) -> Result<Progress, Error> {
        let request = &self.request;
        if kind.0 & SOURCE_TAIL != 0 {
            request.source_tail_seen.store(true, Ordering::Release);
        }
        if kind.0 & FAILED != 0 {
            return Err(Error::WrongPhase);
        }
        // The short guard ends BEFORE any original process/RCU operation.
        let owned_kind = {
            let _mutation = request.mutation()?;
            // SAFETY: the mutation guard excludes other accesses to owned state.
            match unsafe { &*request.state.get().cast::<Owned<K, P, N>>() } {
                Owned::NoPublication(_) => 1,
                Owned::Retired(_) => 2,
                Owned::Child(_) => 0,
                _ => return Err(Error::WrongPhase),
            }
        };
        if owned_kind == 0 {
            let stage = request.service_stage.load(Ordering::Acquire);
            if stage == NEED_REAP {
                if kind.0 & TERMINAL_RETURNED == 0 {
                    return Ok(Progress::Keep);
                }
                // This exact query, not terminal-event presence, checks actual
                // native ticket/physical successor before source ref disposal.
                if !self.physically_returned()? {
                    return Err(Error::Work(WorkError::Pending));
                }
                // Do not retry a partially executed original source destructor.
                request.service_stage.store(BLOCKED, Ordering::Release);
                // SAFETY: the exact native ticket has physically returned before source ref disposal.
                unsafe { self.reap_source() }?;
                request
                    .service_stage
                    .store(NEED_DATA_STOP, Ordering::Release);
            }
            if request.service_stage.load(Ordering::Acquire) == NEED_DATA_STOP {
                // SourceData still holds its own original task reference after
                // scheduler-ref reap. Stop actual native IRQ/read publication,
                // put that real source reference with NO native/state/row loan,
                // then consume the stopped token under a fresh bounded loan.
                // SAFETY: PID1 stopped the scheduler reference and owns the source-data handoff.
                if let Err(error) = unsafe { self.stop_source_data() } {
                    request.service_stage.store(BLOCKED, Ordering::Release);
                    return Err(error);
                }
                request.service_stage.store(NEED_JOIN, Ordering::Release);
            }
            if request.service_stage.load(Ordering::Acquire) == NEED_JOIN {
                // SAFETY: PID1 holds the request and has stopped native data publication.
                match unsafe { self.join_source() } {
                    Ok(()) => {}
                    Err(Error::Source(-11)) => return Ok(Progress::Keep),
                    Err(error) => {
                        request.service_stage.store(BLOCKED, Ordering::Release);
                        return Err(error);
                    }
                }
                // Original join may block; it returned before this fresh loan.
                // SAFETY: the original source join returned before native descriptor retirement.
                if let Err(error) = unsafe { self.retire_descriptors() } {
                    request.service_stage.store(BLOCKED, Ordering::Release);
                    return Err(error);
                }
                request
                    .service_stage
                    .store(NEED_DISPATCH, Ordering::Release);
                request.slot.dispatch_pending.store(true, Ordering::Release);
                if request.broker.wake.raise().is_err() {
                    fatal();
                }
            }
            return Ok(Progress::Keep);
        }
        // Actual NoPub or RetiredMetadata provides native ownership closure.
        // Source-tail event and source query concern ONLY actual source tails.
        if !request.source_tail_seen.load(Ordering::Acquire) {
            return Ok(Progress::Keep);
        }
        // SAFETY: the retained request supplies the exact source identity and generation.
        let value = unsafe {
            stela_linux_task_child_tails_joined(
                request.record(),
                request.broker.kernel.raw(),
                request.generation(),
            )
        };
        if value != 0 {
            return Err(Error::Source(value));
        }
        Ok(Progress::Finalize)
    }
}
fn process_errno(error: Error) -> i32 {
    match error {
        Error::Source(value) if value < 0 => value,
        Error::Work(WorkError::Pending) | Error::Busy => -11,
        Error::Work(WorkError::Busy) => -16,
        _ => -5,
    }
}
