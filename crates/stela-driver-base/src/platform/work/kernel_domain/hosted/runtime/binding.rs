//! Hosted continuation hooks use actual host stack/current observations.
use super::*;
use crate::platform::work::{LeaveReason, ParkOutcome, WakeSignal};

/// A retained foreign context attached to one hosted stack.
///
/// # Safety
/// Keep all reachable source/code/storage owners through quiescent detach.
/// Hooks are bounded, cannot unwind, allocate, dispatch, suspend or release
/// owners. They may check current metadata and publish a same-thread wake. Attach, leave and detach refusals are transactional.
/// Leave commits only a source-prepared suspension. Arrive restores foreign
/// current on the resumed stack. Complete requires the source body to have
/// exited already. Context views are borrowed for one call.
pub unsafe trait HostedSwitchBinding {
    /// # Safety
    /// Actual current stack, checked original host thread, no queue guard.
    unsafe fn attach(&self, context: &TaskContext) -> Result<(), WorkError>;
    /// # Safety
    /// Same stack after original prepare. Observe the condition only.
    unsafe fn still_blocked(&self, context: &TaskContext) -> Result<bool, WorkError>;
    /// # Safety
    /// Same stack after original prepare, with all source owners retained.
    unsafe fn leave(&self, context: &TaskContext, reason: LeaveReason) -> Result<(), WorkError>;
    /// # Safety
    /// Actual resumed stack before foreign code continues.
    unsafe fn arrive(&self, context: &TaskContext, new_job: bool) -> Result<(), WorkError>;
    /// # Safety
    /// Actual finishing stack after the foreign scope exited.
    unsafe fn complete(&self, context: &TaskContext) -> Result<(), WorkError>;
    /// # Safety
    /// Actual taskless dispatcher, with this stack idle and source users joined.
    unsafe fn detach(&self, context: &TaskContext) -> Result<(), WorkError>;
}

/// A wake for one accepted hosted job. Foreign threads publish through the
/// hosted event transport. This handle checks the actual owning thread.
#[derive(Clone)]
pub struct HostedWake {
    execution: Arc<super::super::HostedExecution>,
    signal: Arc<WakeSignal>,
    sequence: u64,
}

impl HostedWake {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn wake(&self) -> Result<(), WorkError> {
        self.execution.check_current()?;
        if self.signal.sequence.load(Ordering::Acquire) != self.sequence {
            return Err(WorkError::Closed);
        }
        self.signal.pending.store(true, Ordering::Release);
        Ok(())
    }
}

impl<const N: usize> HostedRuntime<N> {
    pub fn bind_current(
        self: Pin<&Self>,
        binding: Rc<dyn HostedSwitchBinding>,
    ) -> Result<HostedWake, WorkError> {
        let context = self.current_context()?;
        let index = self.current.get();
        // SAFETY: checked current index on the original thread.
        if unsafe { (*self.task(index)).binding.is_some() } {
            return Err(WorkError::Busy);
        }
        // SAFETY: this exact live stack is executing with no queue guard.
        unsafe { binding.attach(&context)? };
        // SAFETY: the successful hook returned without a switch or a borrow.
        let task = unsafe { &mut *self.task(index) };
        task.binding = Some(binding);
        self.current_wake()
    }

    pub fn current_wake(&self) -> Result<HostedWake, WorkError> {
        let context = self.current_context()?;
        // SAFETY: current_context verified this exact executing stack.
        let task = unsafe { &*self.task(self.current.get()) };
        Ok(HostedWake {
            execution: Arc::clone(&self.queue.execution),
            signal: task.signal.clone(),
            sequence: context.sequence,
        })
    }

    /// # Safety
    /// Actual foreign task/IRQ/wait references have joined. The handle names
    /// the exact stack to detach, and its binding has not been replaced.
    pub unsafe fn detach_binding(
        self: Pin<&Self>,
        wake: &HostedWake,
    ) -> Result<Rc<dyn HostedSwitchBinding>, WorkError> {
        self.dispatcher_successor()?;
        for index in 0..self.count {
            // SAFETY: actual original dispatcher, all continuations stopped.
            let task = unsafe { &*self.task(index) };
            if !Arc::ptr_eq(&task.signal, &wake.signal) {
                continue;
            }
            if task.state != TaskState::Idle {
                return Err(WorkError::Busy);
            }
            let binding = task.binding.as_ref().ok_or(WorkError::Unavailable)?;
            let view = self.context_view(task, task.frame.saved_stack_pointer());
            // SAFETY: actual stopped stack and caller-supplied source joins.
            unsafe { binding.detach(&view)? };
            // SAFETY: all shared observations and the hook borrow have ended.
            return unsafe { (*self.task(index)).binding.take() }.ok_or(WorkError::CorruptContext);
        }
        Err(WorkError::InvalidTicket)
    }

    pub fn yield_now(self: Pin<&Self>) -> Result<(), WorkError> {
        self.suspend(LeaveReason::Yield).map(|_| ())
    }

    pub fn reschedule(self: Pin<&Self>) -> Result<(), WorkError> {
        self.suspend(LeaveReason::Reschedule).map(|_| ())
    }

    pub fn service_current(&self) -> Result<bool, WorkError> {
        self.current_context()?;
        // SAFETY: the checked current task remains live on this stack.
        Ok(unsafe { (*self.task(self.current.get())).lane == Lane::Service })
    }

    /// Park after preparing the original source wait. A concurrent cooperative
    /// wake or a cleared predicate leaves the current source scope intact.
    pub fn park_if_blocked(self: Pin<&Self>) -> Result<ParkOutcome, WorkError> {
        self.suspend(LeaveReason::Blocked)
    }

    fn suspend(self: Pin<&Self>, reason: LeaveReason) -> Result<ParkOutcome, WorkError> {
        let view = self.current_context()?;
        let index = self.current.get();
        let now = self.queue.execution.now_ns()?;
        {
            // SAFETY: checked current stack. No task borrow spans the switch.
            let task = unsafe { &*self.task(index) };
            if reason == LeaveReason::Blocked {
                let binding = task.binding.as_ref().ok_or(WorkError::Unavailable)?;
                // SAFETY: source-prepared condition on the same checked stack.
                if !unsafe { binding.still_blocked(&view)? }
                    || task.signal.pending.swap(false, Ordering::AcqRel)
                {
                    return Ok(ParkOutcome::Skipped);
                }
            }
            {
                let mut guard = self.queue.lock()?;
                let board = &mut guard.state().scheduling;
                board.can_suspend(task.id, view.sequence, reason)?;
                board.account(now)?;
            }
            if let Some(binding) = &task.binding {
                // SAFETY: pure scheduler preflight completed and its guard
                // ended. The exact source-prepared stack is still current.
                unsafe { binding.leave(&view, reason)? };
            }
            let result = self.queue.lock().and_then(|mut guard| {
                guard
                    .state()
                    .scheduling
                    .suspend(task.id, view.sequence, reason)
            });
            require(result);
            // SAFETY: the shared task and binding loans have ended. This is
            // the actual outgoing stack before control returns to dispatcher.
            unsafe {
                (*self.task(index)).state = if reason == LeaveReason::Blocked {
                    TaskState::Blocked
                } else {
                    TaskState::Runnable
                };
            }
        }
        self.depart(index);
        self.arrive(index, false);
        Ok(ParkOutcome::Resumed)
    }

    pub(super) fn arrive(&self, index: usize, new_job: bool) {
        // SAFETY: only this exact task has resumed on the original thread.
        let task = unsafe { &*self.task(index) };
        if let Some(binding) = &task.binding {
            let view = require(self.current_context());
            // SAFETY: actual resumed stack and callback-scoped view.
            require(unsafe { binding.arrive(&view, new_job) });
        }
    }

    pub(super) fn complete_binding(&self, index: usize) {
        // SAFETY: the job returned on its exact current stack.
        let task = unsafe { &*self.task(index) };
        if let Some(binding) = &task.binding {
            let view = require(self.current_context());
            // SAFETY: completion requires the source already exited, verified
            // by the hook. No task or queue transition is committed yet.
            require(unsafe { binding.complete(&view) });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::work::{Kind, kernel_domain::HostedExecution};
    use core::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum State {
        New,
        Entered,
        Parked,
        Exited,
        Completed,
        Detached,
    }

    struct Binding(Cell<State>);
    impl Binding {
        fn transition(&self, previous: State, next: State) -> Result<(), WorkError> {
            if self.0.get() != previous {
                return Err(WorkError::CorruptContext);
            }
            self.0.set(next);
            Ok(())
        }
    }

    // SAFETY: fixture hooks only observe and commit bounded in-place metadata.
    // The owning test keeps the original binding until quiescent detach.
    unsafe impl HostedSwitchBinding for Binding {
        unsafe fn attach(&self, _: &TaskContext) -> Result<(), WorkError> {
            self.transition(State::New, State::Entered)
        }
        unsafe fn still_blocked(&self, _: &TaskContext) -> Result<bool, WorkError> {
            Ok(self.0.get() == State::Entered)
        }
        unsafe fn leave(&self, _: &TaskContext, reason: LeaveReason) -> Result<(), WorkError> {
            assert_eq!(reason, LeaveReason::Blocked);
            self.transition(State::Entered, State::Parked)
        }
        unsafe fn arrive(&self, _: &TaskContext, new_job: bool) -> Result<(), WorkError> {
            assert!(!new_job);
            self.transition(State::Parked, State::Entered)
        }
        unsafe fn complete(&self, _: &TaskContext) -> Result<(), WorkError> {
            self.transition(State::Exited, State::Completed)
        }
        unsafe fn detach(&self, _: &TaskContext) -> Result<(), WorkError> {
            self.transition(State::Completed, State::Detached)
        }
    }

    struct Wait<'a> {
        runtime: Pin<&'a HostedRuntime<4>>,
        binding: Rc<Binding>,
        wake: RefCell<Option<HostedWake>>,
    }
    unsafe extern "C" fn wait(context: *mut c_void) {
        // SAFETY: test keeps this context and its runtime through the return.
        let wait = unsafe { &*context.cast::<Wait<'_>>() };
        let wake = wait.runtime.bind_current(wait.binding.clone()).unwrap();
        // A publication before the final park check must preserve current.
        wake.wake().unwrap();
        assert_eq!(
            wait.runtime.park_if_blocked().unwrap(),
            ParkOutcome::Skipped
        );
        assert_eq!(wait.binding.0.get(), State::Entered);
        *wait.wake.borrow_mut() = Some(wake);
        assert_eq!(
            wait.runtime.park_if_blocked().unwrap(),
            ParkOutcome::Resumed
        );
        wait.binding
            .transition(State::Entered, State::Exited)
            .unwrap();
    }

    #[test]
    fn hosted_park_preserves_foreign_scope_until_real_wake_and_detach() {
        let queue = HostedQueue::new(HostedExecution::new(), Arc::new(())).unwrap();
        // SAFETY: bounded callback on the original thread, no shadow stacks.
        let executor = unsafe { HostedExecutor::new(queue.clone(), 16) }.unwrap();
        let runtime = executor.runtime();
        let context = Wait {
            runtime,
            binding: Rc::new(Binding(Cell::new(State::New))),
            wake: RefCell::new(None),
        };
        // SAFETY: context stays alive until callback return, and the static
        // callback is bounded by the executor's stack.
        let ticket = unsafe {
            queue.execute(
                Kind::General,
                wait,
                ptr::from_ref(&context).cast_mut().cast(),
            )
        }
        .unwrap();
        assert!(runtime.step().unwrap());
        assert_eq!(context.binding.0.get(), State::Parked);
        assert!(!runtime.step().unwrap());
        assert!(!queue.completed(ticket).unwrap());
        let wake = context.wake.borrow_mut().take().unwrap();
        wake.wake().unwrap();
        assert!(runtime.step().unwrap());
        assert_eq!(context.binding.0.get(), State::Completed);
        assert!(queue.completed(ticket).unwrap());
        assert_eq!(wake.wake(), Err(WorkError::Closed));
        queue.close().unwrap();
        assert_eq!(runtime.retire(), Err(WorkError::Busy));
        // SAFETY: the sole callback completed and has no remaining users.
        drop(unsafe { runtime.detach_binding(&wake) }.unwrap());
        assert_eq!(context.binding.0.get(), State::Detached);
        runtime.retire().unwrap();
        // SAFETY: the only producer stopped and the callback joined.
        unsafe { queue.retire() }.unwrap();
    }
}
