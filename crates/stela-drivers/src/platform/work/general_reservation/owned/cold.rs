//! Full usable-range initialization of genuinely never-entered owned backings.
use super::*;

/// Owns excluded, zeroed cold backing through the genuine pinned Runtime.
/// It exposes no bytes, address, C descriptor, stack ref or callback commit.
/// No entered guard is retained across creator suspension. Drop/forget keeps
/// the original ownership markers and cannot restore a frame under stale scope.
#[must_use = "cancel under fresh authority; otherwise the whole owner remains retained"]
pub struct ColdStackPreparation<'runtime, const N: usize> {
    escrow: OwnedGeneralEscrow<'runtime, N>,
}
impl<'runtime, const N: usize> OwnedGeneralEscrow<'runtime, N> {
    /// Initialize only actual never-entered usable backing. Any fallible
    /// precheck returns the original escrow unchanged. Bootstrap return words
    /// are invalidated only while Preparing excludes all execution/reuse.
    /// This does not expose a C stack allocation or architecture fork frame.
    #[expect(
        clippy::result_large_err,
        reason = "Failed preflight must return the exact pinned escrow without allocating or relinquishing worker/backing ownership"
    )]
    pub fn prepare_cold(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<ColdStackPreparation<'runtime, N>, (Self, WorkError)> {
        let range = match self.begin_cold(entered) {
            Ok(range) => range,
            Err(error) => return Err((self, error)),
        };
        // SAFETY: fresh authority checked the exact creator/private ownership;
        // the actual never-entered StackBacking retains immutable writable WB
        // usable bounds. Preparing excludes execution and every other mutable
        // owner. Native flags were restored; no callback/switch spans this exact
        // bounded usable-range write, and neither guard is included.
        unsafe { core::ptr::write_bytes(range.start as *mut u8, 0, range.len()) };
        Ok(ColdStackPreparation { escrow: self })
    }
    fn begin_cold(&self, entered: &dyn EnteredProcess) -> Result<Range<usize>, WorkError> {
        self.current(entered)?;
        let flags = self.queue.cpu.save_disable()?;
        let result = (|| {
            self.current(entered)?;
            let mut guard = self.queue.lock()?;
            let state = guard.state();
            if state.closed || state.poisoned || self.queue.abandoned.load(Ordering::Acquire) {
                return Err(WorkError::Closed);
            }
            self.validate(state)?;
            // SAFETY: exact reserved worker/nonce and actual creator checked at
            // IF0; immutable backing is retained by this pinned Runtime lifetime.
            let task = unsafe { &mut *self.runtime.task(self.worker) };
            if task.ever_entered {
                return Err(WorkError::Busy);
            }
            let range = task.stack.bounds.clone();
            // No fallible operation follows this exclusive frame-state transfer.
            task.state = TaskState::Preparing;
            Ok(range)
        })();
        // SAFETY: exact enclosing flags; every metadata borrow/lock ended. The
        // usable-range initialization happens only AFTER this restoration.
        unsafe { self.queue.cpu.restore(flags) };
        result
    }
}
impl<const N: usize> ColdStackPreparation<'_, N> {
    fn reseed(&self, entered: &dyn EnteredProcess) -> Result<(), WorkError> {
        let owner = &self.escrow;
        owner.current(entered)?;
        let flags = owner.queue.cpu.save_disable()?;
        let result = (|| {
            owner.current(entered)?;
            let mut guard = owner.queue.lock()?;
            let state = guard.state();
            if state.poisoned || owner.queue.abandoned.load(Ordering::Acquire) {
                return Err(WorkError::Closed);
            }
            owner.validate_state(state, TaskState::Preparing)?;
            // SAFETY: private worker/nonce/creator and IF0 qualified above;
            // Preparing retains the entire actual backing and admits no peers.
            let task = unsafe { &mut *owner.runtime.task(owner.worker) };
            if task.ever_entered {
                return Err(WorkError::CorruptContext);
            }
            let runtime = owner.runtime.get_ref() as *const Runtime<N> as usize;
            // SAFETY: this same frame owner retains original valid controls,
            // actual runtime/index and a never-entered, zeroed backing. No C
            // pointer/reference has been exposed. Only Frame::start reconstructs
            // its exact top bootstrap words and saved register metadata.
            unsafe {
                task.frame
                    .start(task.stack.bounds.end, runtime, owner.worker, entry::<N>)
            };
            task.state = TaskState::Escrow;
            Ok(())
        })();
        // SAFETY: exact enclosing flags; no task/queue borrow survives restore.
        unsafe { owner.queue.cpu.restore(flags) };
        result
    }
    /// Restore the actual cold frame and release its original unpublished
    /// reservation once, using fresh actual authority for that creator job.
    /// A stale or uncertain failure drops only captured atomic queue views;
    /// it cannot reseed/release another native owner or treat a C exit as done.
    pub fn cancel(self, entered: &dyn EnteredProcess) -> Result<(), WorkError> {
        self.reseed(entered)?;
        self.escrow.cancel(entered)
    }
}
