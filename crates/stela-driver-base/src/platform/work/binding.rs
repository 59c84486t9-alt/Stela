//! The executing job's identity: current-role checks, stack bindings and wake
//! and scheduling handles.

use super::*;

impl<const N: usize> Runtime<N> {
    pub(super) unsafe fn task(&self, index: usize) -> *mut Task {
        // SAFETY: Immutable Vec allocation: take no Rust reference across a switch.
        unsafe { (&mut *self.tasks.get()).as_mut_ptr().add(index) }
    }

    pub fn queue(&self) -> &Arc<Queue<N>> {
        &self.queue
    }

    pub(super) fn domain(&self) -> Option<&Arc<service::Domain<N>>> {
        // SAFETY: same-CPU access; one setup publication precedes all jobs.
        unsafe { (&*self.service_domain.get()).as_ref() }
    }

    /// Check CPU/current/RSP before identifying the firmware continuation.
    pub fn firmware_current(&self) -> Result<bool, WorkError> {
        self.current_id()?;
        // SAFETY: current_id validated the current index, state and kept stack.
        Ok(unsafe { (*self.task(self.current.get())).lane } == Lane::Firmware)
    }

    /// Constructor role after validating CPU, current job and real RSP.
    /// The tag is observation, never an execution or native service capability.
    pub fn firmware_role_current(&self) -> Result<Option<FirmwareRole>, WorkError> {
        self.current_id()?;
        // SAFETY: current_id validated the current index/state/kept stack.
        Ok(self
            .layout
            .role(unsafe { (*self.task(self.current.get())).lane }))
    }

    /// Check CPU/current/RSP before identifying the reserved service.
    pub fn service_current(&self) -> Result<bool, WorkError> {
        self.current_id()?;
        // SAFETY: current_id validated the continuation.
        let task = unsafe { &*self.task(self.current.get()) };
        Ok(task.signal.service)
    }

    pub fn current_id(&self) -> Result<ContextId, WorkError> {
        let id = self.queue.current_id()?;
        let i = self.current.get();
        if i == NONE {
            return Err(WorkError::Unavailable);
        }
        // SAFETY: `i` is the current task's valid index; no switch occurs while this
        // borrow lives.
        let task = unsafe { &(*self.task(i)) };
        if task.state != TaskState::Running
            || task.id != id
            || !task.stack.bounds.contains(&context::stack_pointer())
        {
            return Err(WorkError::CorruptContext);
        }
        Ok(task.id)
    }

    pub(super) fn context_view(&self, index: usize, active: bool) -> TaskContext {
        // SAFETY: callers check CPU/exclusion and a valid index.
        let task = unsafe { &*self.task(index) };
        TaskContext {
            queue_id: self.queue.id,
            context_id: task.id.get(),
            sequence: task.job.map_or(0, |(_, job)| job.sequence),
            stack_start: task.stack.bounds.start,
            stack_end: task.stack.bounds.end,
            guard_start: task.stack.guard.start,
            guard_end: task.stack.guard.end,
            stack_pointer: if active {
                context::stack_pointer()
            } else {
                task.frame.saved_stack_pointer()
            },
        }
    }

    pub fn current_context(&self) -> Result<TaskContext, WorkError> {
        self.current_id()?;
        Ok(self.context_view(self.current.get(), true))
    }

    /// Attach a preallocated binding on this executing stack.
    /// No hook runs on a dispatcher/IRQ stack. Failure does not install the
    /// binding. This call consumes the supplied Arc; keep a separate clone
    /// before calling if it must be reused after failure. Process-context
    /// failure drops that Arc after restoring any saved IRQ flags. IRQ/foreign-
    /// CPU rejection quarantines the supplied roots instead of releasing them.
    pub fn bind_current(
        self: Pin<&Self>,
        binding: Arc<dyn SwitchBinding>,
    ) -> Result<WakeHandle<N>, WorkError> {
        if let Err(error) = self.current_id() {
            if self.queue.process().is_err() {
                // Rejection on IRQ/foreign CPU is not final owner-release
                // permission. Preserve the supplied binding's roots there.
                core::mem::forget(binding);
                quarantine();
            }
            return Err(error);
        }
        let flags = self.queue.cpu.save_disable()?;
        let index = self.current.get();
        let result = (|| {
            // SAFETY: current is validated and IF remains disabled throughout.
            if unsafe { (*self.task(index)).binding.is_some() } {
                return Err(WorkError::Busy);
            }
            let view = self.context_view(index, true);
            // SAFETY: current task is held and IF0 protects its job assignment.
            let task = unsafe { &*self.task(index) };
            if view.sequence == 0 || task.signal.sequence.load(Ordering::Acquire) != view.sequence {
                return Err(WorkError::CorruptContext);
            }
            // SAFETY: the unsafe binding promises transactional/no-switch hooks.
            unsafe { binding.attach(&view)? };
            let handle = WakeHandle {
                queue: ManuallyDrop::new(self.queue.clone()),
                signal: ManuallyDrop::new(task.signal.clone()),
                id: task.id,
                sequence: view.sequence,
            };
            // SAFETY: exclusive checked CPU; prior immutable borrow's last use is above.
            unsafe {
                (*self.task(index)).binding = Some(binding.clone());
            }
            Ok(handle)
        })();
        // SAFETY: no hook/lock is live and flags came from save_disable above.
        unsafe { self.queue.cpu.restore(flags) };
        result
    }

    pub fn wake_handle(self: Pin<&Self>) -> Result<WakeHandle<N>, WorkError> {
        self.current_id()?;
        // SAFETY: current task is validated; this method never switches.
        let task = unsafe { &*self.task(self.current.get()) };
        if task.binding.is_none() {
            return Err(WorkError::Unavailable);
        }
        let sequence = task.job.ok_or(WorkError::CorruptContext)?.1.sequence;
        if sequence == 0 || task.signal.sequence.load(Ordering::Acquire) != sequence {
            return Err(WorkError::CorruptContext);
        }
        Ok(WakeHandle {
            queue: ManuallyDrop::new(self.queue.clone()),
            signal: ManuallyDrop::new(task.signal.clone()),
            id: task.id,
            sequence,
        })
    }

    /// Capture scheduling permission for this job in the optional domain.
    /// The handle keeps only immutable queue/signal/generation metadata.
    pub fn scheduling_handle(
        self: Pin<&Self>,
    ) -> Result<scheduling::SchedulingHandle<N>, WorkError> {
        self.current_id()?;
        if self.domain().is_none() || self.firmware_role_current()?.is_some() {
            return Err(WorkError::Unavailable);
        }
        let wake = self.wake_handle()?;
        let handle = scheduling::SchedulingHandle { wake };
        handle.snapshot()?;
        Ok(handle)
    }

    pub(super) fn arrive(&self, index: usize, new_job: bool) {
        self.valid();
        let view = self.context_view(index, true);
        // SAFETY: current task on its real destination stack at IF0.
        if let Some(binding) = unsafe { &(*self.task(index)).binding } {
            // SAFETY: no lock/switch borrow; the hook restores foreign state.
            let result = unsafe { binding.arrive(&view, new_job) };
            if let Err(error) = result {
                self.queue.cpu.fatal(error);
            }
        }
    }

    /// # Safety
    /// Real foreign producers/task/wake references are quiescent. The kept
    /// binding validates this at detach; copied metadata is not lifetime proof.
    /// Returned owner is released only in process context after IF restoration.
    pub unsafe fn detach_binding(
        self: Pin<&Self>,
        id: ContextId,
    ) -> Result<Arc<dyn SwitchBinding>, WorkError> {
        self.queue.process()?;
        if self.current.get() != NONE {
            return Err(WorkError::WouldDeadlock);
        }
        let flags = self.queue.cpu.save_disable()?;
        let result = (|| {
            // SAFETY: dispatcher owns all task state with IF=0; vector never resizes.
            let index = unsafe { (&*self.tasks.get()).iter().position(|task| task.id == id) }
                .ok_or(WorkError::Unavailable)?;
            // SAFETY: index comes from this vector.
            let task = unsafe { &*self.task(index) };
            if task.state != TaskState::Idle || task.job.is_some() {
                return Err(WorkError::Pending);
            }
            let binding = task.binding.as_ref().ok_or(WorkError::Unavailable)?;
            let view = self.context_view(index, false);
            if !(view.stack_start..view.stack_end).contains(&view.stack_pointer) {
                return Err(WorkError::CorruptContext);
            }
            // SAFETY: unsafe caller supplies real quiescence; failure is transactional.
            unsafe { binding.detach(&view)? };
            // SAFETY: no task/hook is running; take moves owner without dropping it.
            match unsafe { (*self.task(index)).binding.take() } {
                Some(binding) => Ok(binding),
                None => self.queue.cpu.fatal(WorkError::CorruptContext),
            }
        })();
        // SAFETY: no owner is dropped by moving the Result; no queue lock is held.
        unsafe { self.queue.cpu.restore(flags) };
        result
    }

    pub(super) fn valid(&self) {
        if let Err(e) = self.current_id() {
            self.queue.cpu.fatal(e)
        }
    }
}
