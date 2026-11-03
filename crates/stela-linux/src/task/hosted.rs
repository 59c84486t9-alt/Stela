//! Original C task ABI on the actual hosted continuation's guarded stack.
use super::*;
use alloc::rc::Rc;
use core::cell::{Cell, RefCell};
use stela_driver_base::platform::work::kernel_domain::{
    DomainRef, HostedRuntime, HostedSwitchBinding, HostedWake,
};

/// A hosted bare task used for compatibility and negative admission controls.
/// Original Initial and managed children require their source constructors.
pub struct HostedTaskBinding<const N: usize> {
    task: NonNull<CTask>,
    runtime: NonNull<HostedRuntime<N>>,
    wake: RefCell<Option<HostedWake>>,
    detached: Cell<bool>,
    released: bool,
}

impl<const N: usize> HostedTaskBinding<N> {
    const OPS: TaskOps = TaskOps {
        is_current: Self::is_current,
        wake_target: Self::wake_target,
        service_reserved: Self::service_reserved,
        rank: Self::rank,
    };
    const SCOPE_OPS: ScopeOps = ScopeOps {
        park: Self::park,
        yield_now: Self::yield_now,
        reschedule: Self::reschedule,
        reschedule_requested: Self::reschedule_requested,
        terminate: Self::terminate,
    };

    /// # Safety
    /// This is the sole !SMP C archive owner thread for the fixture. The
    /// canonical heap and actual pinned executor/container stay alive through
    /// every callback, detach and final release, including abandoned failures.
    pub unsafe fn new_bare(runtime: Pin<&HostedRuntime<N>>) -> Result<Rc<Self>, WorkError> {
        DomainRef::borrow_hosted(runtime)?.dispatcher_successor()?;
        // SAFETY: caller supplies the original heap and serialized dispatcher.
        let task = NonNull::new(unsafe { stela_linux_task_allocate() }).ok_or(WorkError::Full)?;
        Ok(Rc::new(Self {
            task,
            runtime: NonNull::from(runtime.get_ref()),
            wake: RefCell::new(None),
            detached: Cell::new(false),
            released: false,
        }))
    }

    fn runtime(&self) -> Pin<&HostedRuntime<N>> {
        // SAFETY: the constructor retains the exact pinned executor lifetime.
        unsafe { Pin::new_unchecked(self.runtime.as_ref()) }
    }

    pub fn bind_current(self: &Rc<Self>) -> Result<HostedWake, WorkError> {
        if self.detached.get() || self.wake.borrow().is_some() {
            return Err(WorkError::Busy);
        }
        self.runtime().bind_current(self.clone())
    }

    /// # Safety
    /// Body and context stay valid through every real suspension. The source
    /// body cannot unwind, retire the executor or retain the scoped capability.
    pub unsafe fn run_scoped(
        &self,
        body: unsafe extern "C" fn(*mut c_void),
        context: *mut c_void,
    ) -> Result<(), WorkError> {
        let runtime = self.runtime();
        let actual = runtime.current_wake()?;
        if self.wake.borrow().as_ref().map(HostedWake::sequence) != Some(actual.sequence()) {
            return Err(WorkError::InvalidTicket);
        }
        // SAFETY: exact active assignment on the same runtime, scoped body.
        unsafe { run_scope(self.task, &Self::SCOPE_OPS, runtime, body, context) }
    }

    /// # Safety
    /// Original producer/waiter/lease users have actually joined. This must
    /// run on the sole dispatcher, after successful detach if ever attached.
    pub unsafe fn release_quiescent(self: Rc<Self>) -> Result<(), Rc<Self>> {
        if DomainRef::borrow_hosted(self.runtime())
            .and_then(|domain| domain.dispatcher_successor())
            .is_err()
            || (self.wake.borrow().is_some() && !self.detached.get())
        {
            return Err(self);
        }
        let mut binding = Rc::try_unwrap(self)?;
        // SAFETY: exact unique bare record plus caller's original joins.
        unsafe { stela_linux_task_release(binding.task.as_ptr()) };
        binding.released = true;
        Ok(())
    }

    unsafe extern "C" fn is_current(binding: *mut c_void, view: *const TaskContext) -> bool {
        // SAFETY: the C stack record borrows the retained original Rc.
        let this = unsafe { &*binding.cast::<Self>() };
        let Ok(actual) = DomainRef::borrow_hosted(this.runtime()).and_then(|d| d.current_context())
        else {
            return false;
        };
        if view.is_null()
            || this.wake.borrow().as_ref().map(HostedWake::sequence) != Some(actual.sequence)
        {
            return false;
        }
        // SAFETY: actual checked host thread and RSP before source observation.
        let view = unsafe { &*view };
        actual.queue_id == view.queue_id
            && actual.context_id == view.context_id
            && actual.sequence == view.sequence
    }

    unsafe extern "C" fn wake_target(binding: *mut c_void, expected: u64) -> i32 {
        // SAFETY: C retains this exact binding until producer joins.
        let this = unsafe { &*binding.cast::<Self>() };
        let wake = this.wake.borrow();
        let Some(wake) = wake.as_ref().filter(|wake| wake.sequence() == expected) else {
            return -116;
        };
        match wake.wake() {
            Ok(()) => 0,
            Err(WorkError::Closed) => -116,
            Err(_) => -1,
        }
    }

    unsafe extern "C" fn service_reserved(_: *mut c_void) -> bool {
        // Attach admits only ordinary hosted stacks for this bare record.
        false
    }

    unsafe extern "C" fn rank(
        _: *mut c_void,
        _: u64,
        _: *const Rank,
        _: *const Rank,
        _: bool,
    ) -> i32 {
        -95 // Hosted rank publication has no provider yet.
    }

    unsafe extern "C" fn park(scope: *mut c_void) -> i32 {
        // SAFETY: run_scope retains this exact pinned borrow through resume.
        match unsafe { &*scope.cast::<Pin<&HostedRuntime<N>>>() }.park_if_blocked() {
            Ok(ParkOutcome::Skipped) => 0,
            Ok(ParkOutcome::Resumed) => 1,
            Err(WorkError::Busy) => -16,
            Err(_) => -22,
        }
    }

    unsafe extern "C" fn yield_now(scope: *mut c_void) -> i32 {
        // SAFETY: same live stack scope as park.
        scope_status(unsafe { &*scope.cast::<Pin<&HostedRuntime<N>>>() }.yield_now())
    }

    unsafe extern "C" fn reschedule(scope: *mut c_void) -> i32 {
        // SAFETY: same live stack scope as park.
        scope_status(unsafe { &*scope.cast::<Pin<&HostedRuntime<N>>>() }.reschedule())
    }

    unsafe extern "C" fn reschedule_requested(scope: *mut c_void) -> bool {
        // SAFETY: same live stack scope as park.
        let runtime = unsafe { &*scope.cast::<Pin<&HostedRuntime<N>>>() };
        runtime.reschedule_requested().unwrap_or_else(|_| {
            // SAFETY: an invalid current query must stop before the C caller proceeds.
            unsafe { core::arch::asm!("ud2", options(noreturn)) }
        })
    }

    unsafe extern "C" fn terminate(_: *mut c_void) -> ! {
        // SAFETY: bare source may not retire an original child. Preserve the
        // current stack and owners if it reaches this impossible boundary.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }
}

fn scope_status(result: Result<(), WorkError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(WorkError::Busy) => -16,
        Err(_) => -22,
    }
}

// SAFETY: the original hosted thread owns all task state. The hooks call the
// same bounded C ABI as native, with checked hosted current and retained roots.
unsafe impl<const N: usize> HostedSwitchBinding for HostedTaskBinding<N> {
    unsafe fn attach(&self, context: &TaskContext) -> Result<(), WorkError> {
        if self.detached.get() || self.wake.borrow().is_some() {
            return Err(WorkError::Busy);
        }
        let runtime = self.runtime();
        if runtime.service_current()? {
            return Err(WorkError::Unavailable);
        }
        let wake = runtime.current_wake()?;
        if wake.sequence() != context.sequence {
            return Err(WorkError::InvalidTicket);
        }
        // SAFETY: checked live stack, immutable ops and retained Rc receiver.
        status(unsafe {
            stela_linux_task_attach(
                self.task.as_ptr(),
                context,
                &Self::OPS,
                core::ptr::from_ref(self).cast_mut().cast(),
            )
        })?;
        *self.wake.borrow_mut() = Some(wake);
        Ok(())
    }

    unsafe fn still_blocked(&self, context: &TaskContext) -> Result<bool, WorkError> {
        // SAFETY: actual current and original source-prepared wait.
        match unsafe { stela_linux_task_still_blocked(self.task.as_ptr(), context) } {
            0 => Ok(false),
            1 => Ok(true),
            -16 => Err(WorkError::Busy),
            _ => Err(WorkError::CorruptContext),
        }
    }

    unsafe fn leave(&self, context: &TaskContext, reason: LeaveReason) -> Result<(), WorkError> {
        // SAFETY: exact outgoing stack and source-prepared suspension.
        status(unsafe { stela_linux_task_leave(self.task.as_ptr(), context, reason as u32) })
    }

    unsafe fn arrive(&self, context: &TaskContext, new_job: bool) -> Result<(), WorkError> {
        if new_job {
            // Old signal/OS execution owners remain kept by the same runtime.
            *self.wake.borrow_mut() = Some(self.runtime().current_wake()?);
        }
        // SAFETY: actual destination stack with its exact current assignment.
        status(unsafe { stela_linux_task_arrive(self.task.as_ptr(), context, new_job) })
    }

    unsafe fn complete(&self, context: &TaskContext) -> Result<(), WorkError> {
        // SAFETY: actual finishing stack; C checks that the source scope ended.
        status(unsafe { stela_linux_task_complete(self.task.as_ptr(), context) })
    }

    unsafe fn detach(&self, context: &TaskContext) -> Result<(), WorkError> {
        // SAFETY: the actual dispatcher and independently joined users.
        status(unsafe { stela_linux_task_detach(self.task.as_ptr(), context) })?;
        self.detached.set(true);
        Ok(())
    }
}

impl<const N: usize> Drop for HostedTaskBinding<N> {
    fn drop(&mut self) {
        if !self.released {
            QUARANTINED.fetch_add(1, Ordering::Relaxed);
        }
    }
}
