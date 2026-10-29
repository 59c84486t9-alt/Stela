//! Owned exclusion across creator suspension; no stack loan or child publication.
use super::*;
mod cold;
pub use cold::ColdStackPreparation;

/// Retains a genuine compatible idle worker and job slot without a process-scope
/// borrow. The lifetime pins the actual Runtime and its StackBacking owners;
/// this is not an Arc<Runtime>, stack pointer grant, ticket or Linux task.
///
/// Explicit cancel requires fresh actual authority for the same creator job.
/// Drop cannot obtain that authority and therefore closes and quarantines the
/// captured queue atomically, without accessing the affine Runtime. Forgetting
/// the value retains its markers/counts and prevents creator return/retirement.
#[must_use = "cancel with fresh entered authority; Drop retains and closes admission"]
pub struct OwnedGeneralEscrow<'runtime, const N: usize> {
    runtime: Pin<&'runtime Runtime<N>>,
    queue: Arc<Queue<N>>,
    creator: Creator,
    creator_worker: usize,
    worker: usize,
    context: ContextId,
    slot: usize,
    nonce: u64,
    requirement: StackRequirement,
    live: bool,
    _local: PhantomData<*mut ()>,
}
impl<'runtime, const N: usize> GeneralReservation<'runtime, '_, N> {
    /// Convert this checked short reservation into owned exclusion. All fallible
    /// checks precede the Pending-to-Owned transfer. No borrowed entered guard
    /// remains in the result, so the creator may park and later obtain a fresh
    /// guard. This accepts no callback and grants no C stack/current/PID access.
    pub fn into_owned(mut self) -> Result<OwnedGeneralEscrow<'runtime, N>, WorkError> {
        self.current()?;
        let flags = self.runtime.queue.cpu.save_disable()?;
        let result = (|| {
            self.current()?;
            let mut guard = self.runtime.queue.lock()?;
            let state = guard.state();
            if state.closed || state.poisoned || self.queue.abandoned.load(Ordering::Acquire) {
                return Err(WorkError::Closed);
            }
            self.validate(state)?;
            let total = self
                .runtime
                .owned_escrows
                .get()
                .checked_add(1)
                .ok_or(WorkError::Exhausted)?;
            let creator_worker = self.runtime.current.get();
            // SAFETY: current() validated this actual creator frame twice; IF0
            // stops peers and no callback/switch spans this bounded field read.
            let count = unsafe { (*self.runtime.task(creator_worker)).owned_escrows }
                .checked_add(1)
                .ok_or(WorkError::Exhausted)?;
            // No fallible operation follows the exact ownership transfer.
            // SAFETY: the private matching worker/nonce and actual creator were
            // validated under the same IF0 queue guard; no aliases survive.
            unsafe {
                (*self.runtime.task(self.worker)).state = TaskState::Escrow;
                (*self.runtime.task(creator_worker)).owned_escrows = count;
            }
            self.runtime.owned_escrows.set(total);
            self.runtime
                .pending_reservations
                .set(self.runtime.pending_reservations.get() - 1);
            self.live = false;
            Ok(OwnedGeneralEscrow {
                runtime: self.runtime,
                queue: self.queue.clone(),
                creator: self.creator,
                creator_worker,
                worker: self.worker,
                context: self.context,
                slot: self.slot,
                nonce: self.nonce,
                requirement: self.requirement,
                live: true,
                _local: PhantomData,
            })
        })();
        // SAFETY: exact enclosing save_disable flags; all task/queue borrows ended.
        unsafe { self.queue.cpu.restore(flags) };
        result
    }
}
impl<const N: usize> OwnedGeneralEscrow<'_, N> {
    fn current(&self, entered: &dyn EnteredProcess) -> Result<(), WorkError> {
        entered.check()?;
        if !self.creator.matches(self.runtime.current_context()?)
            || self.runtime.current.get() != self.creator_worker
        {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
    fn validate(&self, state: &State<N>) -> Result<(), WorkError> {
        self.validate_state(state, TaskState::Escrow)
    }
    fn validate_state(&self, state: &State<N>, expected: TaskState) -> Result<(), WorkError> {
        if self.slot >= N
            || state.reservations[self.slot] != self.nonce
            || state.jobs[self.slot].is_some()
            || self.runtime.owned_escrows.get() == 0
        {
            return Err(WorkError::CorruptContext);
        }
        // SAFETY: caller proved fresh actual authority and exact creator at IF0;
        // both constructor-captured workers stay retained and stopped here.
        let (task, creator) = unsafe {
            (
                &*self.runtime.task(self.worker),
                &*self.runtime.task(self.creator_worker),
            )
        };
        if task.id != self.context
            || task.lane != Lane::General
            || task.state != expected
            || task.job.is_some()
            || task.binding.is_some()
            || task.draining
            || task.signal.sequence.load(Ordering::Acquire) != 0
            || creator.owned_escrows == 0
            || !stack_requirement::compatible(
                Some(self.requirement),
                stack_requirement::Geometry::of(&task.stack),
            )
        {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
    fn rollback(&mut self, entered: &dyn EnteredProcess) -> Result<(), WorkError> {
        self.current(entered)?;
        let flags = self.queue.cpu.save_disable()?;
        let result = (|| {
            self.current(entered)?;
            let mut guard = self.queue.lock()?;
            let state = guard.state();
            if state.poisoned || self.queue.abandoned.load(Ordering::Acquire) {
                return Err(WorkError::Closed);
            }
            self.validate(state)?;
            state.reservations[self.slot] = 0;
            // SAFETY: exact private worker and creator ownership checked above;
            // no published callback/stack loan exists and peers remain stopped.
            unsafe {
                (*self.runtime.task(self.worker)).state = TaskState::Idle;
                (*self.runtime.task(self.creator_worker)).owned_escrows -= 1;
            }
            self.runtime
                .owned_escrows
                .set(self.runtime.owned_escrows.get() - 1);
            self.live = false;
            Ok(())
        })();
        // SAFETY: exact cancel entry flags; all affine borrows ended before restore.
        unsafe { self.queue.cpu.restore(flags) };
        result
    }
    /// Release only this unpublished exclusion under fresh actual authority for
    /// its original creator job. A closed queue still allows exact cleanup;
    /// stale, foreign or uncertain ownership instead retains the whole executor.
    pub fn cancel(mut self, entered: &dyn EnteredProcess) -> Result<(), WorkError> {
        let result = self.rollback(entered);
        if result.is_err() {
            self.abandon();
        }
        result
    }
    fn abandon(&mut self) {
        // Only the independently retained atomic queue view is touched. Never
        // inspect Runtime/stack metadata without fresh actual entered authority.
        self.queue.abandoned.store(true, Ordering::Release);
        quarantine();
        self.live = false;
    }
}
impl<const N: usize> Drop for OwnedGeneralEscrow<'_, N> {
    fn drop(&mut self) {
        if self.live {
            self.abandon();
        }
    }
}
