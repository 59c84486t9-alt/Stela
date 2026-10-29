//! Affine actual-worker/job reservation under a borrowed entered process guard.
use super::*;
mod owned;
pub use owned::{ColdStackPreparation, OwnedGeneralEscrow};
/// Actual borrowed platform process-entry authority, independent of task IDs.
///
/// # Safety
/// The view borrows a genuine entered process guard for its entire lifetime.
/// check validates actual CPU/root/process generation before mutable service
/// access; neither RootIdentity nor a caller integer substitutes for that guard.
/// It is nonblocking/nonallocating and valid with local IRQs saved/disabled:
/// no AML, queue callback, allocator, RestoreRoot reacquisition or wait. There
/// is no permissive default. A borrowed authority must not escape across Guest.
pub unsafe trait EnteredProcess {
    fn check(&self) -> Result<(), WorkError>;
}
#[derive(Clone, Copy)]
struct Creator {
    queue: u64,
    context: u64,
    sequence: u64,
}
impl Creator {
    fn of(view: TaskContext) -> Self {
        Self {
            queue: view.queue_id,
            context: view.context_id,
            sequence: view.sequence,
        }
    }
    fn matches(self, view: TaskContext) -> bool {
        self.queue == view.queue_id
            && self.context == view.context_id
            && self.sequence == view.sequence
    }
}
/// Receipt for actual assigned deferred work, not child startup or C current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignedGeneral {
    ticket: Ticket,
    context: ContextId,
}
impl AssignedGeneral {
    pub fn ticket(self) -> Ticket {
        self.ticket
    }
    pub fn context_id(self) -> ContextId {
        self.context
    }
}
/// Non-Send, non-Clone short-lived reservation. Drop rolls back only under its
/// matching actual entered scope; uncertain ownership retains the whole owner.
#[must_use = "drop/cancel rolls back; commit publishes only actual owned deferred work"]
pub struct GeneralReservation<'runtime, 'entered, const N: usize> {
    runtime: Pin<&'runtime Runtime<N>>,
    queue: Arc<Queue<N>>,
    entered: &'entered dyn EnteredProcess,
    creator: Creator,
    worker: usize,
    context: ContextId,
    slot: usize,
    nonce: u64,
    requirement: StackRequirement,
    live: bool,
    _local: PhantomData<*mut ()>,
}
#[derive(Clone, Copy)]
enum Eligibility {
    AnyIdle,
    Unstarted,
}
impl Eligibility {
    fn permits(self, task: &Task) -> bool {
        match self {
            Self::AnyIdle => true,
            Self::Unstarted => !task.ever_entered,
        }
    }
}
impl<const N: usize> Runtime<N> {
    /// Reserve one actually idle, unbound compatible General worker and one
    /// ordinary job slot. This publishes no callback, ticket, C task or current.
    /// All mutations follow real scope/current checks. Incoming IF is restored
    /// before returning for bounded nonblocking metadata setup; no permit parks.
    pub fn reserve_general<'runtime, 'entered>(
        self: Pin<&'runtime Self>,
        entered: &'entered dyn EnteredProcess,
        requirement: StackRequirement,
    ) -> Result<GeneralReservation<'runtime, 'entered, N>, WorkError> {
        self.reserve_eligible(entered, requirement, Eligibility::AnyIdle)
    }
    /// Reserve only an actual never-entered compatible worker. This is a short
    /// reservation, not stack byte access or C task publication. Eligibility is
    /// constructor/entry-owned history, never a caller-provided cold flag.
    pub fn reserve_unstarted_general<'runtime, 'entered>(
        self: Pin<&'runtime Self>,
        entered: &'entered dyn EnteredProcess,
        requirement: StackRequirement,
    ) -> Result<GeneralReservation<'runtime, 'entered, N>, WorkError> {
        self.reserve_eligible(entered, requirement, Eligibility::Unstarted)
    }
    fn reserve_eligible<'runtime, 'entered>(
        self: Pin<&'runtime Self>,
        entered: &'entered dyn EnteredProcess,
        requirement: StackRequirement,
        eligibility: Eligibility,
    ) -> Result<GeneralReservation<'runtime, 'entered, N>, WorkError> {
        entered.check()?;
        self.current_context()?;
        let flags = self.queue.cpu.save_disable()?;
        let result = (|| {
            entered.check()?;
            let creator = Creator::of(self.current_context()?);
            let mut guard = self.queue.lock()?;
            let state = guard.state();
            if state.closed || state.poisoned || self.queue.abandoned.load(Ordering::Acquire) {
                return Err(WorkError::Closed);
            }
            if state.stack_profile.is_none()
                || !state.stack_catalog.supports(Lane::General, requirement)
            {
                return Err(WorkError::Unavailable);
            }
            let slot = state
                .layout
                .admission(Lane::General, N)?
                .into_iter()
                .flatten()
                .find(|slot| state.jobs[*slot].is_none() && state.reservations[*slot] == 0)
                .ok_or(WorkError::Full)?;
            // SAFETY: actual current CPU and IF0 own this immutable retained Vec;
            // no foreign hook/callback, allocation or switch spans these reads.
            let count = unsafe { (*self.tasks.get()).len() };
            let worker = (0..count)
                .find(|index| {
                    // SAFETY: bounded actual task entry, stopped while creator runs at IF0.
                    let task = unsafe { &*self.task(*index) };
                    task.lane == Lane::General
                        && task.state == TaskState::Idle
                        && eligibility.permits(task)
                        && task.job.is_none()
                        && task.binding.is_none()
                        && !task.draining
                        && task.signal.sequence.load(Ordering::Acquire) == 0
                        && stack_requirement::compatible(
                            Some(requirement),
                            stack_requirement::Geometry::of(&task.stack),
                        )
                })
                .ok_or(WorkError::Full)?;
            let nonce = state.next_reservation;
            if nonce == 0 {
                return Err(WorkError::CorruptContext);
            }
            let next = nonce.checked_add(1).ok_or(WorkError::Exhausted)?;
            let pending = self
                .pending_reservations
                .get()
                .checked_add(1)
                .ok_or(WorkError::Exhausted)?;
            // SAFETY: exact idle unbound worker selected above, exclusively stopped at IF0.
            let task = unsafe { &mut *self.task(worker) };
            state.next_reservation = next;
            state.reservations[slot] = nonce;
            task.state = TaskState::Reserved;
            self.pending_reservations.set(pending);
            Ok(GeneralReservation {
                runtime: self,
                queue: self.queue.clone(),
                entered,
                creator,
                worker,
                context: task.id,
                slot,
                nonce,
                requirement,
                live: true,
                _local: PhantomData,
            })
        })();
        // SAFETY: exact enclosing save_disable flags; all queue/task borrows ended.
        unsafe { self.queue.cpu.restore(flags) };
        result
    }
}
impl<const N: usize> GeneralReservation<'_, '_, N> {
    fn current(&self) -> Result<(), WorkError> {
        self.entered.check()?;
        if !self.creator.matches(self.runtime.current_context()?) {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
    /// # Safety
    /// The provider already retains callback/code/context and every reachable
    /// resource through completion or quarantine, as for Queue::execute. The
    /// body fits the requested actual extent and must not unwind. Metadata
    /// setup was nonblocking; no borrowed process authority enters the job.
    /// Error admits no callback and grants no wrong-scope cleanup authority.
    pub unsafe fn commit(
        mut self,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<AssignedGeneral, WorkError> {
        self.current()?;
        let flags = self.runtime.queue.cpu.save_disable()?;
        let result = (|| {
            self.current()?;
            let mut guard = self.runtime.queue.lock()?;
            let state = guard.state();
            if state.closed
                || state.poisoned
                || self.runtime.queue.abandoned.load(Ordering::Acquire)
            {
                return Err(WorkError::Closed);
            }
            self.validate(state)?;
            let sequence = state.next;
            let next = sequence.checked_add(1).ok_or(WorkError::Exhausted)?;
            state.scheduling.insert(self.context, sequence, false)?;
            let job = Job {
                callback,
                context: context as usize,
                lane: Lane::General,
                sequence,
                running: true,
                requirement: Some(self.requirement),
            };
            // No fallible operation follows this actual ownership publication.
            state.next = next;
            state.jobs[self.slot] = Some(job);
            state.reservations[self.slot] = 0;
            // SAFETY: exact matching private reservation was checked at IF0 above;
            // no alias/hook/switch crosses the assignment of this owned child frame.
            let task = unsafe { &mut *self.runtime.task(self.worker) };
            task.job = Some((self.slot, job));
            task.flags = flags;
            task.state = TaskState::Ready;
            task.signal.pending.store(false, Ordering::Relaxed);
            task.signal.sequence.store(sequence, Ordering::Release);
            self.runtime
                .pending_reservations
                .set(self.runtime.pending_reservations.get() - 1);
            self.live = false;
            Ok(AssignedGeneral {
                ticket: Ticket {
                    queue: self.runtime.queue.id,
                    sequence,
                },
                context: self.context,
            })
        })();
        // SAFETY: all queue/task borrows ended; restore exact commit entry flags.
        unsafe { self.runtime.queue.cpu.restore(flags) };
        result
    }
    fn validate(&self, state: &State<N>) -> Result<(), WorkError> {
        if self.slot >= N
            || state.reservations[self.slot] != self.nonce
            || state.jobs[self.slot].is_some()
            || self.runtime.pending_reservations.get() == 0
        {
            return Err(WorkError::CorruptContext);
        }
        // SAFETY: caller checked real current authority at IF0 and retained the
        // unchanged actual task vector; worker is private constructor-captured.
        let task = unsafe { &*self.runtime.task(self.worker) };
        if task.id != self.context
            || task.lane != Lane::General
            || task.state != TaskState::Reserved
            || task.job.is_some()
            || task.binding.is_some()
            || task.draining
            || task.signal.sequence.load(Ordering::Acquire) != 0
            || !stack_requirement::compatible(
                Some(self.requirement),
                stack_requirement::Geometry::of(&task.stack),
            )
        {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), WorkError> {
        self.current()?;
        let flags = self.runtime.queue.cpu.save_disable()?;
        let result = (|| {
            self.current()?;
            let mut guard = self.runtime.queue.lock()?;
            let state = guard.state();
            self.validate(state)?;
            state.reservations[self.slot] = 0;
            // SAFETY: exact reserved worker ownership validated above. No callback
            // or task metadata was published, and no binding/producer owns it.
            unsafe { (*self.runtime.task(self.worker)).state = TaskState::Idle };
            self.runtime
                .pending_reservations
                .set(self.runtime.pending_reservations.get() - 1);
            self.live = false;
            Ok(())
        })();
        // SAFETY: no metadata borrow survives restoration of exact entry flags.
        unsafe { self.runtime.queue.cpu.restore(flags) };
        result
    }
    fn abandon(&mut self) {
        // No affine Runtime/Task/queue state is read or freed under a stale
        // authority. The atomic view closes admission; reserved state and every
        // real owner remain retained, including this whole pinned executor.
        self.queue.abandoned.store(true, Ordering::Release);
        quarantine();
        self.live = false;
    }
    pub fn cancel(mut self) -> Result<(), WorkError> {
        let result = self.rollback();
        if result.is_err() {
            self.abandon();
        }
        result
    }
}
impl<const N: usize> Drop for GeneralReservation<'_, '_, N> {
    fn drop(&mut self) {
        if self.live && self.rollback().is_err() {
            self.abandon();
        }
    }
}
