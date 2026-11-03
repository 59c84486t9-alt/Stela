//! Continuation storage and publication independent of execution authority.
use super::*;

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TaskState {
    Idle,
    Retained,
    Reserved,
    Escrow,
    Preparing,
    Dormant,
    Terminating,
    Ready,
    Running,
    Runnable,
    Blocked,
}
#[cfg(target_arch = "x86_64")]
pub(super) struct Continuation<S, F, B> {
    pub(super) lane: Lane,
    pub(super) stack: S,
    pub(super) id: ContextId,
    pub(super) frame: context::Frame,
    pub(super) state: TaskState,
    pub(super) job: Option<(usize, Job)>,
    pub(super) flags: F,
    pub(super) draining: bool,
    pub(super) owned_escrows: usize,
    pub(super) stack_pin_nonce: u64,
    pub(super) ever_entered: bool,
    pub(super) completed_sequence: u64,
    pub(super) returned_sequence: u64,
    pub(super) stack_epoch: u64,
    pub(super) stack_retired_epoch: u64,
    pub(super) binding: Option<B>,
    pub(super) signal: Arc<WakeSignal>,
}
impl<S, F, B> Continuation<S, F, B> {
    pub(super) fn new(
        lane: Lane,
        stack: S,
        controls: context::Controls,
        flags: F,
    ) -> Result<Self, WorkError> {
        let id = NEXT_CONTEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| WorkError::Exhausted)?;
        Ok(Self {
            lane,
            stack,
            id: ContextId(id),
            frame: context::Frame::new(controls),
            state: TaskState::Idle,
            job: None,
            flags,
            draining: false,
            owned_escrows: 0,
            stack_pin_nonce: 0,
            ever_entered: false,
            completed_sequence: 0,
            returned_sequence: 0,
            stack_epoch: 0,
            stack_retired_epoch: 0,
            binding: None,
            signal: Arc::new(WakeSignal {
                #[cfg(feature = "linux-kernel")]
                physical: inactive::PhysicalRun::new(),
                service: lane == Lane::Service,
                sequence: AtomicU64::new(0),
                pending: AtomicBool::new(false),
            }),
        })
    }

    /// Publish an assignment after its scheduler row has committed.
    pub(super) fn assign(&mut self, job: (usize, Job), flags: F) {
        self.job = Some(job);
        self.state = TaskState::Ready;
        self.flags = flags;
        self.signal.pending.store(false, Ordering::Relaxed);
        self.signal
            .sequence
            .store(job.1.sequence, Ordering::Release);
    }
}
