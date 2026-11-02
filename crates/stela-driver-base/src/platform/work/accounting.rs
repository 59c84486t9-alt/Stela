//! Measured execution intervals and bounded source-field publication.
use super::*;
mod capture;
mod publication;
mod view;
pub use capture::{ExecutionTap, InterruptedExecution};
pub use publication::{ExecutionPublication, StoppedPublication};
pub(super) use view::{ExecutionView, Fence};

/// Native assignment identity only, never current/placement/data permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionIdentity {
    queue: u64,
    context: u64,
    sequence: u64,
}
impl ExecutionIdentity {
    pub(super) fn new(queue: u64, context: u64, sequence: u64) -> Self {
        Self {
            queue,
            context,
            sequence,
        }
    }
    pub fn queue_id(self) -> u64 {
        self.queue
    }
    pub fn context_id(self) -> u64 {
        self.context
    }
    pub fn sequence(self) -> u64 {
        self.sequence
    }
}
/// Unweighted nominal CPU time for one exact native job. This contains no
/// original task/pwq pointer and cannot manufacture a clock, tick or current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionSample {
    identity: ExecutionIdentity,
    total_ns: u64,
    accounted_through_ns: u64,
    segment_started_ns: u64,
}
impl ExecutionSample {
    pub(super) fn new(
        identity: ExecutionIdentity,
        total_ns: u64,
        through: u64,
        segment: u64,
    ) -> Self {
        Self {
            identity,
            total_ns,
            accounted_through_ns: through,
            segment_started_ns: segment,
        }
    }
    pub fn identity(self) -> ExecutionIdentity {
        self.identity
    }
    pub fn total_ns(self) -> u64 {
        self.total_ns
    }
    /// Exact counter stamp used for this total. A stopped target keeps its
    /// closed account stamp; a different caller's walltime is never charged.
    pub fn accounted_through_ns(self) -> u64 {
        self.accounted_through_ns
    }
    /// Actual native Running transition, distinct from the last account stamp.
    pub fn segment_started_ns(self) -> u64 {
        self.segment_started_ns
    }
}
impl<const N: usize> Runtime<N> {
    /// Obtain the independent IRQ read view before native ingress is admitted.
    /// Retention does not grant entry, counter or data-write permission.
    pub fn execution_tap(
        self: Pin<&Self>,
        entered: &dyn EnteredProcess,
    ) -> Result<ExecutionTap, WorkError> {
        entered.check()?;
        self.dispatcher_successor()?;
        self.execution.clock()?;
        Ok(ExecutionTap {
            view: ManuallyDrop::new(self.execution.clone()),
        })
    }
    /// Live current observation/publication under the same measured native row.
    /// A disabled/missing clock reports Unavailable, never successful zero.
    pub fn execution_current(self: Pin<&Self>) -> Result<ExecutionSample, WorkError> {
        self.current_id()?;
        let index = self.current.get();
        let flags = self.queue.cpu.save_disable()?;
        let result = (|| {
            let now = self.execution.clock()?.now_ns()?;
            let sample = self.execution.sample_at(index, now)?;
            self.execution.publish_process(index, &sample);
            Ok(sample)
        })();
        // SAFETY: exact enclosing flags after no Board/Task borrow remains.
        unsafe { self.queue.cpu.restore(flags) };
        result
    }
    /// Guarded native row state for this exact kept wake generation. A Ready
    /// wake is visible before Task.state scans; this snapshot is no death or
    /// future no-wake guarantee and never creates an original current task.
    pub fn activity_for(
        self: Pin<&Self>,
        wake: &WakeHandle<N>,
    ) -> Result<scheduling::Activity, WorkError> {
        self.queue.process()?;
        if !Arc::ptr_eq(&self.queue, &wake.queue) {
            return Err(WorkError::InvalidTicket);
        }
        if wake.closed()? {
            return Err(WorkError::Closed);
        }
        self.queue
            .lock()?
            .state()
            .scheduling
            .activity(wake.id, wake.sequence)
    }
    /// Exact kept target observation for source task_sched_runtime. This does
    /// not infer an inactive task from a C flag or create current. Publication
    /// occurs at IF0, before a later IRQ can publish a newer measurement.
    pub fn execution_for(
        self: Pin<&Self>,
        wake: &WakeHandle<N>,
    ) -> Result<ExecutionSample, WorkError> {
        self.queue.process()?;
        if !Arc::ptr_eq(&self.queue, &wake.queue) {
            return Err(WorkError::InvalidTicket);
        }
        let flags = self.queue.cpu.save_disable()?;
        let result = (|| {
            // SAFETY: actual same CPU/IF0, immutable native task vector. Only
            // constructor-owned identity/signal metadata is inspected.
            let index = unsafe {
                (&*self.tasks.get())
                    .iter()
                    .position(|task| task.id == wake.id && Arc::ptr_eq(&task.signal, &wake.signal))
            }
            .ok_or(WorkError::InvalidTicket)?;
            // Validate the actual native assignment before considering its
            // shadow. A stale wake cannot observe an old metric while another
            // sequence is admitted but has not entered its stack yet.
            let assigned = {
                // SAFETY: actual same-CPU/IF0 immutable task metadata; no borrow
                // survives queue/clock/source publication below.
                let task = unsafe { &*self.task(index) };
                if let Some((_, job)) = task.job {
                    if job.sequence != wake.sequence {
                        return Err(WorkError::Closed);
                    }
                    true
                } else {
                    if task.completed_sequence != wake.sequence {
                        return Err(WorkError::Closed);
                    }
                    false
                }
            };
            let now = self.execution.clock()?.now_ns()?;
            let identity = ExecutionIdentity::new(self.queue.id, wake.id.get(), wake.sequence);
            let sample = if assigned {
                // A genuine admitted Dormant/Ready row has measured zero even
                // before its first entry. No default or missing-row zero exists.
                let (total, through, segment) =
                    self.queue
                        .lock()?
                        .state()
                        .scheduling
                        .execution(wake.id, wake.sequence, now)?;
                ExecutionSample::new(identity, total, through, segment)
            } else {
                if self.execution.identity(index)? != identity {
                    return Err(WorkError::Closed);
                }
                self.execution.sample_at(index, now)?
            };
            if self
                .execution
                .identity(index)
                .is_ok_and(|actual| actual == identity)
            {
                self.execution.publish_process(index, &sample);
            }
            Ok(sample)
        })();
        // SAFETY: exact outer flags with no target/native borrow still live.
        unsafe { self.queue.cpu.restore(flags) };
        result
    }
    pub(super) fn execution_publish_at(&self, index: usize, now: u64) -> Result<(), WorkError> {
        if self.domain().is_none() {
            return Ok(());
        }
        let sample = self.execution.sample_at(index, now)?;
        self.execution.publish_process(index, &sample);
        Ok(())
    }
    pub(super) fn execution_pause_at(&self, index: usize, now: u64) -> Result<(), WorkError> {
        if self.domain().is_none() {
            return Ok(());
        }
        let sample = self.execution.sample_at(index, now)?;
        self.execution.pause(index, &sample)
    }
    pub(super) fn execution_stop_at(&self, index: usize, now: u64) -> Result<(), WorkError> {
        if self.domain().is_none() {
            return Ok(());
        }
        let sample = self.execution.sample_at(index, now)?;
        self.execution.stop(index, &sample)
    }
    /// Take only the actual stopped field publication after the exact native
    /// physical return and every IRQ reader joined. Original data/task/RCU refs
    /// remain separately owned and must be released in a real source process.
    pub fn take_stopped_publication(
        self: Pin<&Self>,
        wake: &WakeHandle<N>,
    ) -> Result<StoppedPublication, WorkError> {
        self.queue.process()?;
        if !Arc::ptr_eq(&self.queue, &wake.queue) {
            return Err(WorkError::InvalidTicket);
        }
        let flags = self.queue.cpu.save_disable()?;
        let result = (|| {
            // SAFETY: actual affine CPU/IF0, immutable constructor vector;
            // this borrow ends before any guarded/foreign publication action.
            let index = unsafe {
                (&*self.tasks.get())
                    .iter()
                    .position(|task| task.id == wake.id)
            }
            .ok_or(WorkError::InvalidTicket)?;
            let idle_shape = {
                // SAFETY: stopped actual task, no mutable use overlaps at IF0.
                let task = unsafe { &*self.task(index) };
                if !matches!(task.state, TaskState::Idle | TaskState::Retained)
                    || task.job.is_some()
                    || task.signal.sequence.load(Ordering::Acquire) != 0
                    || task.completed_sequence != wake.sequence
                    || task.returned_sequence != wake.sequence
                    || !Arc::ptr_eq(&task.signal, &wake.signal)
                {
                    return Err(WorkError::Pending);
                }
                (task.state == TaskState::Retained
                    && task.stack_pin_nonce == 0
                    && task.binding.is_none())
                .then(|| {
                    (task.lane == Lane::General)
                        .then(|| ReleasedStackGeometry::of(&task.stack, !task.ever_entered))
                })
            };
            let stopped = self.execution.take_stopped(
                index,
                ExecutionIdentity::new(self.queue.id, wake.id.get(), wake.sequence),
            )?;
            if let Some(shape) = idle_shape {
                if let Some(shape) = shape {
                    // Publication already moved. A ledger/counter corruption after
                    // successful source-writer retirement is fatal retention, not
                    // an ordinary refusal that could discard the actual stop token.
                    self.queue
                        .lock()
                        .and_then(|mut guard| guard.state().resources.stack_released(shape))
                        .unwrap_or_else(|error| self.queue.cpu.fatal(error));
                }
                // SAFETY: exact stopped idle/unbound/pinless native worker.
                unsafe {
                    (*self.task(index)).state = TaskState::Idle;
                }
            }
            Ok(stopped)
        })();
        // SAFETY: saved flags after all native borrows ended; uncertain unwind
        // keeps StoppedPublication's actual source data owner ManuallyDrop-held.
        unsafe { self.queue.cpu.restore(flags) };
        result
    }
}
