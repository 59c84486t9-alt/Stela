//! Service and firmware lanes: starting them, joining their queues, draining
//! and retirement.

use super::*;

impl<const N: usize> Runtime<N> {
    pub fn attach_service_domain(
        self: Pin<&Self>,
        domain: Arc<service::Domain<N>>,
    ) -> Result<(), WorkError> {
        self.queue.process()?;
        if self.retired.get() {
            return Err(WorkError::Closed);
        }
        if self.current.get() != NONE || self.service_started.get() || self.domain().is_some() {
            return Err(WorkError::Busy);
        }
        // SAFETY: immutable constructor role, on checked dispatcher.
        if unsafe { (*self.task(2)).lane } != Lane::Service {
            return Err(WorkError::Unavailable);
        }
        // Enabling a sidecar cannot reinterpret already suspended task frames.
        // Queued, unassigned jobs are fine: they enter NORMAL on assign.
        // SAFETY: checked taskless dispatcher owns the task vector;
        // no continuation runs and this bounded read invokes no callback/switch.
        if unsafe {
            (&*self.tasks.get())
                .iter()
                .any(|task| task.job.is_some() || task.state != TaskState::Idle)
        } {
            return Err(WorkError::Busy);
        }
        let mut scheduling = self.queue.lock()?;
        // register performs only immutable CPU/queue identity checks; no clock,
        // idle/event provider, C callback or inline switch is invoked here.
        domain.register(self)?;
        scheduling.state().scheduling.clock = Some(domain.scheduling_clock());
        scheduling.state().scheduling.enabled = true;
        drop(scheduling);
        // SAFETY: first publication before jobs; no callback/drop/borrow crosses it.
        unsafe { *self.service_domain.get() = Some(domain) };
        Ok(())
    }

    /// Start the optional reserved service once, on its distinct stack.
    /// The ordinary General/Notify queue cannot submit into this private lane.
    ///
    /// # Safety
    /// The queue's owner covers callback/code/context through
    /// stop, drain and join. The callback binds its real task and supplied clock
    /// domain before driver admission, never unwinds or returns with an entered
    /// owner. Reservation alone supplies no timer/IRQ-work/RT service or clock.
    pub unsafe fn start_service(
        self: Pin<&Self>,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<Ticket, WorkError> {
        self.queue.process()?;
        if self.retired.get() {
            return Err(WorkError::Closed);
        }
        if self.current.get() != NONE || self.service_started.get() {
            return Err(WorkError::Busy);
        }
        // SAFETY: all runtimes have at least four tasks; immutable lane metadata
        // belongs to this checked dispatcher and is never caller role bits.
        if unsafe { (*self.task(2)).lane } != Lane::Service {
            return Err(WorkError::Unavailable);
        }
        let ticket = self.queue.enqueue_lane(Lane::Service, callback, context)?;
        self.service_started.set(true);
        Ok(ticket)
    }

    /// Start the independently reserved firmware continuation once. Its lane
    /// cannot be consumed by General/Notify work or the Linux service domain.
    /// Reservation supplies no AML, SCI, hardware or Linux entry permission.
    ///
    /// # Safety
    /// The kept owner covers callback/code/context until stop,
    /// drain and join. The callback never unwinds or returns with a live foreign
    /// entry; every suspended frame remains on its owned stack until resumed.
    pub unsafe fn start_firmware(
        self: Pin<&Self>,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<Ticket, WorkError> {
        self.queue.process()?;
        if self.retired.get() {
            return Err(WorkError::Closed);
        }
        if self.current.get() != NONE || self.firmware_started.get() {
            return Err(WorkError::Busy);
        }
        // SAFETY: all runtimes keep at least four tasks. The checked taskless
        // dispatcher reads immutable constructor metadata without invoking work.
        if unsafe { (*self.task(3)).lane } != Lane::Firmware {
            return Err(WorkError::Unavailable);
        }
        let ticket = self.queue.enqueue_lane(Lane::Firmware, callback, context)?;
        self.firmware_started.set(true);
        Ok(ticket)
    }

    /// Observe the constructor's protected GPE admission budget.
    /// None means the legacy layout has no protected pending guarantee. This
    /// copy neither synchronizes IRQs nor grants provider/progress permission.
    pub fn protected_gpe_budget(&self) -> Result<Option<GpeQueueBudget>, WorkError> {
        self.queue.process()?;
        if self.retired.get() || self.queue.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        Ok(self.layout.protected_gpe())
    }

    /// Check CPU/policy/lifetime/current-role eligibility for a firmware
    /// queue join before a caller mutates C handler state. This does not capture
    /// a flush boundary, run/accept work, attest progress or synchronize an IRQ.
    /// A successful check is not a future execution or provider capability.
    pub fn check_firmware_join(&self, queue: FirmwareQueue) -> Result<(), WorkError> {
        self.queue.process()?;
        if self.retired.get() || self.queue.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        if !self.layout.firmware_roles() {
            return Err(WorkError::Unavailable);
        }
        let current = self.current.get();
        if current != NONE {
            self.current_id()?;
            // SAFETY: current frame was checked; its immutable lane is
            // fixed before publication and is never changed by a callback/IRQ.
            if unsafe { (*self.task(current)).lane == queue.lane() } {
                return Err(WorkError::WouldDeadlock);
            }
        }
        Ok(())
    }

    /// Join only the selected firmware queue's jobs accepted before this call.
    /// Ordinary callbacks queued later, including same-queue chains, belong to
    /// a later flush boundary. This matches pinned Linux flush_workqueue;
    /// it is distinct from final close/drain and does not close admission.
    ///
    /// The OSL caller must synchronize the real SCI hardirq first, then join
    /// Gpe and Notify in that order with separate captures: GPE work may enqueue
    /// Notify work. This method alone grants no IRQ/provider capability.
    /// Joining from the selected queue refuses self-deadlock. Pending/TimedOut
    /// keep every admitted callback/context. Only NativeFirmware16 has these
    /// distinct queues; legacy constructor contracts remain unchanged.
    pub fn join_firmware(
        self: Pin<&Self>,
        queue: FirmwareQueue,
        deadline: u64,
    ) -> Result<(), WorkError> {
        self.check_firmware_join(queue)?;
        let lane = queue.lane();
        let boundary = self.queue.lock()?.state().next;
        loop {
            let current = self.current.get();
            if current != NONE {
                self.current_id()?;
            }
            let (pending, progress) = {
                let mut guard = self.queue.lock()?;
                let state = guard.state();
                let pending = state
                    .jobs
                    .iter()
                    .flatten()
                    .any(|job| job.lane == lane && job.sequence < boundary);
                // SAFETY: real queue guard holds IF0, current was checked and
                // no task borrow survives the snapshot or any later switch.
                (pending, unsafe { self.peer_progress(current, state) })
            };
            if !pending {
                return Ok(());
            }
            if self.queue.cpu.ticks() >= deadline {
                return Err(WorkError::TimedOut);
            }
            if current == NONE {
                if !self.step()? {
                    return Err(WorkError::Pending);
                }
            } else {
                if !progress {
                    return Err(WorkError::Pending);
                }
                self.yield_now()?;
            }
        }
    }

    /// Drain every admitted job. From a callback, exclude only that active job;
    /// ordered Notify/foreground jobs behind it are a real cycle and refuse.
    /// Callers of mandatory-void OSL drains must fail closed on an error.
    pub fn drain(self: Pin<&Self>, deadline: u64) -> Result<(), WorkError> {
        self.queue.process()?;
        let origin = self.current.get();
        let _draining = if origin != NONE {
            self.current_id()?;
            // SAFETY: `origin` is the running task, verified by current_id above.
            unsafe {
                (*self.task(origin)).draining = true;
            }
            Some(DrainFlag {
                // SAFETY: the task list outlives this drain, so the flag pointer stays valid.
                task: unsafe { core::ptr::addr_of_mut!((*self.task(origin)).draining) },
            })
        } else {
            None
        };
        loop {
            let current = self.current.get();
            if origin != NONE
                // SAFETY: other tasks are suspended while this one runs; only their flags are read.
                && unsafe {
                    (&*self.tasks.get())
                        .iter()
                        .enumerate()
                        .any(|(i, t)| i != origin && t.draining && t.job.is_some())
                }
            {
                return Err(WorkError::WouldDeadlock);
            }
            let own = if current == NONE {
                None
            } else {
                self.current_id()?;
                // SAFETY: `current` is the running task, verified by current_id above.
                unsafe { (*self.task(current)).job.map(|(_, j)| j) }
            };
            let (pending, peer_progress) = {
                let mut g = self.queue.lock()?;
                let s = g.state();
                let pending = s
                    .jobs
                    .iter()
                    .flatten()
                    .any(|j| Some(j.sequence) != own.map(|j| j.sequence));
                if let Some(own) = own
                    && own.lane != Lane::General
                    && s.jobs
                        .iter()
                        .flatten()
                        .any(|j| j.lane == own.lane && j.sequence != own.sequence)
                {
                    return Err(WorkError::WouldDeadlock);
                }
                // SAFETY: checked same-CPU queue guard holds IF0; no task
                // reference survives the snapshot or any later switch.
                let peer_progress = unsafe { self.peer_progress(current, s) };
                (pending, peer_progress)
            };
            if !pending {
                return Ok(());
            }
            if self.queue.cpu.ticks() >= deadline {
                return Err(WorkError::TimedOut);
            }
            if current == NONE {
                if !self.step()? {
                    return Err(WorkError::Pending);
                }
            } else {
                // Queued work behind blocked eligible continuations cannot
                // progress by repeatedly yielding this drain to itself.
                if !peer_progress {
                    return Err(WorkError::Pending);
                }
                self.yield_now()?;
            }
        }
    }

    /// # Safety
    /// External IRQ/work/reset and driver users have stopped and cannot
    /// concurrently enqueue, resume or mutate this executor. Owner,
    /// CPU/process permission and stack backing remain valid throughout the call.
    /// Current/suspended callbacks, reservations, escrows and bindings are checked
    /// before retirement; Pending/Closed keeps them. Timeout/failed drain is
    /// not retirement permission. Idle dispatcher continuation frames do not
    /// attest execution of an original terminal C lifecycle.
    pub unsafe fn retire(self: Pin<&Self>) -> Result<(), WorkError> {
        self.queue.process()?;
        if self.queue.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        if self.pending_reservations.get() != 0 || self.owned_escrows.get() != 0 {
            return Err(WorkError::Pending);
        }
        if self.domain().is_some_and(|domain| !domain.retired()) {
            return Err(WorkError::Pending);
        }
        if self.current.get() != NONE {
            return Err(WorkError::Pending);
        }
        // SAFETY: covered by this function's own safety contract.
        if unsafe {
            (&*self.tasks.get())
                .iter()
                .any(|t| t.state != TaskState::Idle || t.binding.is_some())
        } {
            return Err(WorkError::Pending);
        }
        self.queue.close()?;
        // SAFETY: covered by this function's own safety contract.
        unsafe { self.queue.retire()? };
        self.retired.set(true);
        Ok(())
    }
}
