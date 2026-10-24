//! Bounded native deferred work with real retained task continuations.
//!
//! This service is pumped by its owning physical CPU. It does not install a
//! scheduler interrupt, invent an ACPICA provider, or claim autonomous wakeup.
//! Admission never invokes a callback, allocates or releases retained owners.
//! Process/deferred context owns construction, pumping, retirement and every
//! final owner release. The pump preserves incoming IF exactly; it never enables
//! interrupt delivery to manufacture progress. A future SCI/ACPICA adapter must
//! supply a genuine dispatcher policy that permits hardware IRQ progress and
//! actual main-owned interrupt metadata, plus IRQ-safe allocation/synchronizers.
//! This module alone does not qualify that provider.
#[cfg(target_arch = "x86_64")]
use alloc::vec::Vec;
use alloc::{boxed::Box, sync::Arc};
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::AtomicUsize;
use core::{
    any::Any,
    cell::UnsafeCell,
    ffi::c_void,
    mem::ManuallyDrop,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
#[cfg(target_arch = "x86_64")]
use core::{
    cell::Cell,
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
};

#[cfg(target_arch = "x86_64")]
mod context;

pub type Callback = unsafe extern "C" fn(*mut c_void);
pub type RetainedOwner = Arc<dyn Any + Send + Sync>;
#[cfg(target_arch = "x86_64")]
const NONE: usize = usize::MAX;
#[cfg(target_arch = "x86_64")]
static NEXT_CONTEXT: AtomicU64 = AtomicU64::new(1);
static NEXT_QUEUE: AtomicU64 = AtomicU64::new(1);
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkError {
    Unavailable,
    WrongCpu,
    InterruptContext,
    Busy,
    Full,
    Closed,
    Exhausted,
    InvalidStack,
    InvalidTicket,
    WouldDeadlock,
    TimedOut,
    CorruptContext,
    Pending,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    General,
    Notify,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
enum Lane {
    Foreground,
    General,
    Notify,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextId(u64);
impl ContextId {
    pub fn get(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    queue: u64,
    sequence: u64,
}

/// Main's actual processor/context adapter. There are no no-op defaults.
///
/// # Safety
/// All methods operate at CPL0 on one qualified physical CPU, with native
/// interrupt-safe compiler code (no unprotected red zone), a stable main-owned
/// GS/FS/root context, and no task migration or root/segment changes by work.
/// `save_disable` checks
/// affinity then saves/disables local IRQs with compiler/memory ordering;
/// `restore` restores those exact flags on that CPU. `in_interrupt` uses real
/// main-owned IRQ context metadata, not IF or a made-up task ID. `ticks` is a
/// progressing monotonic clock on this CPU, including while IRQs are disabled.
/// The adapter, callback code and roots stay retained through quarantine.
/// `fatal` must not return/unwind. Operations never silently migrate contexts.
pub unsafe trait Cpu: Send + Sync {
    fn check_cpu(&self) -> Result<(), WorkError>;
    fn in_interrupt(&self) -> bool;
    fn save_disable(&self) -> Result<u64, WorkError>;
    /// # Safety
    /// Flags come from this same CPU's enclosing save_disable. Task metadata
    /// and hardware SP must already describe the resumed context; no queue
    /// lock spans this restoration or a context switch.
    unsafe fn restore(&self, flags: u64);
    fn ticks(&self) -> u64;
    fn fatal(&self, error: WorkError) -> !;
}

/// The actual exclusively owned task RAM, guard and all-root mapping lease.
///
/// # Safety
/// Bounds are immutable page-aligned writable WB native RAM, exclusively owned
/// for this task's stack, with no DMA/other mutable owner and no preexisting
/// live execution frames when admitted to a new executor. `guard` is a genuinely
/// unmapped page-aligned preceding range in every execution root, never merely
/// an address label. The entire RAM/code/root/guard lease remains valid until
/// Drop, including suspended frames and uncertain executor failure. Drop may
/// reclaim it only after the context and every producer/IRQ/work user stopped.
pub unsafe trait StackBacking: Send + Sync {
    fn bounds(&self) -> Range<usize>;
    fn guard(&self) -> Range<usize>;
}
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub struct Stack {
    backing: Box<dyn StackBacking>,
    bounds: Range<usize>,
    guard: Range<usize>,
}
impl Stack {
    pub fn new(backing: Box<dyn StackBacking>) -> Result<Self, WorkError> {
        let bounds = backing.bounds();
        let guard = backing.guard();
        if !bounds.start.is_multiple_of(4096)
            || !bounds.end.is_multiple_of(4096)
            || bounds
                .end
                .checked_sub(bounds.start)
                .is_none_or(|n| n < 16 * 1024 || n > isize::MAX as usize)
            || guard.end != bounds.start
            || !guard.start.is_multiple_of(4096)
            || guard.end.checked_sub(guard.start).is_none_or(|n| n < 4096)
        {
            return Err(WorkError::InvalidStack);
        }
        Ok(Self {
            backing,
            bounds,
            guard,
        })
    }
    pub fn bounds(&self) -> Range<usize> {
        self.bounds.clone()
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
struct Job {
    callback: Callback,
    context: usize,
    lane: Lane,
    sequence: u64,
    running: bool,
}
struct State<const N: usize> {
    jobs: [Option<Job>; N],
    next: u64,
    closed: bool,
    poisoned: bool,
}
/// No Runtime/Task pointer crosses into this IRQ-safe read view. A single
/// actual executor binds these identities to its retained stack ranges.
#[cfg(target_arch = "x86_64")]
struct ActiveContext {
    id: AtomicU64,
    start: AtomicUsize,
    end: AtomicUsize,
}
#[cfg(target_arch = "x86_64")]
impl ActiveContext {
    fn new() -> Self {
        Self {
            id: AtomicU64::new(0),
            start: AtomicUsize::new(0),
            end: AtomicUsize::new(0),
        }
    }
    // Both methods require the qualified CPU with IF clear. No queue lock or
    // borrowed Task state survives the subsequent hardware stack transition.
    fn publish(&self, id: ContextId, bounds: &Range<usize>) {
        self.start.store(bounds.start, Ordering::Relaxed);
        self.end.store(bounds.end, Ordering::Relaxed);
        self.id.store(id.get(), Ordering::Release);
    }
    fn clear(&self) {
        self.id.store(0, Ordering::Release);
        self.start.store(0, Ordering::Relaxed);
        self.end.store(0, Ordering::Relaxed);
    }
}

/// Shared preallocated admission slots. Every active/queued callback is covered
/// by the actual provider/root owner retained at construction. Callbacks and
/// their dynamic contexts must obey unsafe enqueue's lifetime contract.
pub struct Queue<const N: usize> {
    id: u64,
    abandoned: AtomicBool,
    #[cfg(target_arch = "x86_64")]
    executor_claimed: AtomicBool,
    #[cfg(target_arch = "x86_64")]
    active: ActiveContext,
    cpu: ManuallyDrop<Arc<dyn Cpu>>,
    owner: ManuallyDrop<RetainedOwner>,
    state: ManuallyDrop<UnsafeCell<State<N>>>,
    held: AtomicBool,
    retired: AtomicBool,
}
// SAFETY: same-CPU IRQ-save exclusion protects all state; foreign CPUs fail
// before touching it. A bounded try-lock refuses unexpected/NMI reentry. No
// callback, allocation, context switch or retained-owner Drop occurs locked.
unsafe impl<const N: usize> Send for Queue<N> {}
// SAFETY: as for Send above.
unsafe impl<const N: usize> Sync for Queue<N> {}
struct Guard<'a, const N: usize> {
    queue: &'a Queue<N>,
    flags: u64,
}
impl<const N: usize> Guard<'_, N> {
    fn state(&mut self) -> &mut State<N> {
        // SAFETY: a Guard exists only while `held` is set with IRQs disabled, so this
        // is the sole reference to the state.
        unsafe { &mut *self.queue.state.get() }
    }
}
impl<const N: usize> Drop for Guard<'_, N> {
    fn drop(&mut self) {
        self.queue.held.store(false, Ordering::Release);
        // SAFETY: `flags` came from this CPU's save_disable in `lock`, and the lock is
        // released above.
        unsafe { self.queue.cpu.restore(self.flags) };
    }
}
impl<const N: usize> Queue<N> {
    /// # Safety
    /// `owner` is the actual provider/context/code/root lease for all jobs,
    /// retained until real producer quiescence and retirement, never a dummy.
    /// Every IRQ/producer retains an actual Queue Arc through its full source
    /// lifetime; an unowned raw queue pointer never qualifies. Creation and
    /// final Arc/owner release occur in process/deferred context.
    pub unsafe fn new(cpu: Arc<dyn Cpu>, owner: RetainedOwner) -> Result<Arc<Self>, WorkError> {
        cpu.check_cpu()?;
        if cpu.in_interrupt() {
            return Err(WorkError::InterruptContext);
        }
        if N == 0 || N > 4096 {
            return Err(WorkError::Unavailable);
        }
        let id = NEXT_QUEUE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| WorkError::Exhausted)?;
        Ok(Arc::new(Self {
            id,
            abandoned: AtomicBool::new(false),
            #[cfg(target_arch = "x86_64")]
            executor_claimed: AtomicBool::new(false),
            #[cfg(target_arch = "x86_64")]
            active: ActiveContext::new(),
            cpu: ManuallyDrop::new(cpu),
            owner: ManuallyDrop::new(owner),
            state: ManuallyDrop::new(UnsafeCell::new(State {
                jobs: [None; N],
                next: 1,
                closed: false,
                poisoned: false,
            })),
            held: AtomicBool::new(false),
            retired: AtomicBool::new(false),
        }))
    }
    fn lock(&self) -> Result<Guard<'_, N>, WorkError> {
        let flags = self.cpu.save_disable()?;
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // SAFETY: `flags` came from the save_disable above, and no lock is held.
            unsafe { self.cpu.restore(flags) };
            return Err(WorkError::Busy);
        }
        Ok(Guard { queue: self, flags })
    }
    fn process(&self) -> Result<(), WorkError> {
        self.cpu.check_cpu()?;
        if self.cpu.in_interrupt() {
            Err(WorkError::InterruptContext)
        } else {
            Ok(())
        }
    }
    /// Read the actual executing owned work context, never a Runtime/Task
    /// pointer. Genuine CPU/IRQ metadata is checked before active metadata or
    /// hardware RSP. Arbitrary dispatcher/ISR stacks never receive an ID.
    /// The one executor is permanently bound to this unique queue lifetime;
    /// retired/abandoned views refuse even if a consumer retained the Arc.
    #[cfg(target_arch = "x86_64")]
    pub fn current_id(&self) -> Result<ContextId, WorkError> {
        self.process()?;
        if self.retired.load(Ordering::Acquire) || self.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        let id = self.active.id.load(Ordering::Acquire);
        if id == 0 {
            return Err(WorkError::Unavailable);
        }
        let bounds =
            self.active.start.load(Ordering::Relaxed)..self.active.end.load(Ordering::Relaxed);
        if !bounds.contains(&context::stack_pointer()) {
            return Err(WorkError::Unavailable);
        }
        Ok(ContextId(id))
    }

    fn enqueue_lane(
        &self,
        lane: Lane,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<Ticket, WorkError> {
        let mut guard = self.lock()?;
        let state = guard.state();
        if state.closed || state.poisoned || self.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        let slot = state
            .jobs
            .iter()
            .position(Option::is_none)
            .ok_or(WorkError::Full)?;
        let sequence = state.next;
        state.next = sequence.checked_add(1).ok_or(WorkError::Exhausted)?;
        state.jobs[slot] = Some(Job {
            callback,
            context: context as usize,
            lane,
            sequence,
            running: false,
        });
        Ok(Ticket {
            queue: self.id,
            sequence,
        })
    }
    /// Actual IRQ-safe admission. It performs no callback/allocator/ref release.
    ///
    /// # Safety
    /// Callback/context stay valid until actual completion; the retained owner
    /// covers them and any code/resources they can reach. Accepted jobs may
    /// suspend on their real task stacks. They must not unwind, overflow the
    /// owned stack, return holding locks, or free the provider/executor. An
    /// error means this job was not admitted and will never be invoked.
    pub unsafe fn execute(
        &self,
        kind: Kind,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<Ticket, WorkError> {
        self.enqueue_lane(
            match kind {
                Kind::General => Lane::General,
                Kind::Notify => Lane::Notify,
            },
            callback,
            context,
        )
    }
    pub fn close(&self) -> Result<(), WorkError> {
        let mut g = self.lock()?;
        g.state().closed = true;
        Ok(())
    }
    pub fn completed(&self, ticket: Ticket) -> Result<bool, WorkError> {
        let mut g = self.lock()?;
        let state = g.state();
        if ticket.queue != self.id || ticket.sequence == 0 || ticket.sequence >= state.next {
            return Err(WorkError::InvalidTicket);
        }
        Ok(!state
            .jobs
            .iter()
            .flatten()
            .any(|j| j.sequence == ticket.sequence))
    }
    #[cfg(target_arch = "x86_64")]
    fn next(&self, lane: Lane) -> Result<Option<(usize, Job)>, WorkError> {
        let mut g = self.lock()?;
        let state = g.state();
        if state.poisoned || self.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        let next = state
            .jobs
            .iter()
            .enumerate()
            .filter_map(|(i, j)| j.filter(|j| j.lane == lane && !j.running).map(|j| (i, j)))
            .min_by_key(|(_, j)| j.sequence);
        if let Some((i, _)) = next {
            state.jobs[i].as_mut().expect("selected slot").running = true;
        }
        Ok(next)
    }
    #[cfg(target_arch = "x86_64")]
    fn finish(&self, slot: usize, sequence: u64) -> Result<(), WorkError> {
        let mut g = self.lock()?;
        let state = g.state();
        if !state
            .jobs
            .get(slot)
            .and_then(|j| *j)
            .is_some_and(|j| j.sequence == sequence && j.running)
        {
            state.poisoned = true;
            return Err(WorkError::CorruptContext);
        }
        state.jobs[slot] = None;
        Ok(())
    }
    /// # Safety
    /// All real IRQ/driver/firmware/work producers have stopped and cannot call
    /// execute again. No executor is active or suspended; every admitted job
    /// completed. Mere close is not producer or callback synchronization.
    pub unsafe fn retire(&self) -> Result<(), WorkError> {
        self.process()?;
        let mut g = self.lock()?;
        let state = g.state();
        if !state.closed || state.poisoned || state.jobs.iter().any(Option::is_some) {
            return Err(WorkError::Pending);
        }
        #[cfg(target_arch = "x86_64")]
        {
            if self.active.id.load(Ordering::Acquire) != 0 {
                return Err(WorkError::Pending);
            }
            self.active.clear(); // Guard still holds the real CPU's IF clear.
        }
        self.retired.store(true, Ordering::Release);
        Ok(())
    }
}
impl<const N: usize> Drop for Queue<N> {
    fn drop(&mut self) {
        if self.retired.load(Ordering::Acquire) {
            // SAFETY: retirement proved no producer or executor still uses these fields.
            unsafe {
                ManuallyDrop::drop(&mut self.state);
                ManuallyDrop::drop(&mut self.owner);
                ManuallyDrop::drop(&mut self.cpu)
            };
        } else {
            quarantine();
        }
    }
}
fn quarantine() {
    let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}
pub fn quarantined_owners() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

/// A view of the real retained continuation, never authority to dereference
/// its stack. Active hooks receive actual RSP; idle detach receives saved RSP.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskContext {
    pub queue_id: u64,
    pub context_id: u64,
    pub sequence: u64,
    pub stack_start: usize,
    pub stack_end: usize,
    pub guard_start: usize,
    pub guard_end: usize,
    pub stack_pointer: usize,
}
#[cfg(target_arch = "x86_64")]
const _: () = {
    assert!(size_of::<TaskContext>() == 64);
    assert!(core::mem::offset_of!(TaskContext, sequence) == 16);
    assert!(core::mem::offset_of!(TaskContext, stack_pointer) == 56);
};
#[cfg(target_arch = "x86_64")]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaveReason {
    Yield = 0,
    Blocked = 1,
}
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParkOutcome {
    Skipped,
    Resumed,
}

/// Retained foreign execution state for one genuine continuation.
///
/// # Safety
/// This object retains every callback/code/context/root it reaches until real
/// quiescent detach and process-context final release. Hooks never unwind,
/// allocate, release owners, wait, reenter Runtime or enable hardware IRQs.
/// `attach`, `still_blocked`, `leave`, `arrive`, `complete` run on the actual
/// context stack, qualified CPU, with IF=0 and no queue lock. `detach` instead
/// runs on its taskless dispatcher for an idle task; it never invents current.
/// Returned attach/leave/detach failure is transactional. `still_blocked` only
/// reads the genuine condition and validates prepared suspension. Linux-owned
/// wrappers prepare/drain in process context BEFORE generic park/yield; hooks
/// never manufacture an owner exit or callback drain at IF=0. `leave` commits
/// only prepared state/lease suspension and clears foreign current. `arrive`
/// restores that state/current on the destination stack before IF restoration;
/// `new_job` starts a clean reused worker lease with its new existing ticket.
/// `complete` validates owner already EXITED/quiescent and clears current with
/// no drain/drop. Arrive/completion errors are fatal, never returned through an
/// inconsistent foreign context. Detach validates stopped producers and all
/// real foreign wait/task references; its final owner is released AFTER IF
/// restoration. TaskContext references are callback-scoped: copy primitive
/// metadata only, never retain the view pointer. Its ranges are observations,
/// not an independent stack/root lifetime lease.
#[cfg(target_arch = "x86_64")]
pub unsafe trait SwitchBinding: Send + Sync {
    /// # Safety
    /// Called on the actual current stack at IF0 with all binding roots retained.
    unsafe fn attach(&self, context: &TaskContext) -> Result<(), WorkError>;
    /// # Safety
    /// Called after process PREPARE on the actual current stack at IF0; pure check.
    unsafe fn still_blocked(&self, context: &TaskContext) -> Result<bool, WorkError>;
    /// # Safety
    /// Called on the outgoing actual stack at IF0 with prepared state; transactional error.
    unsafe fn leave(&self, context: &TaskContext, reason: LeaveReason) -> Result<(), WorkError>;
    /// # Safety
    /// Called on the destination actual stack at IF0 before any hardware IF restore.
    unsafe fn arrive(&self, context: &TaskContext, new_job: bool) -> Result<(), WorkError>;
    /// # Safety
    /// Called on the completing actual stack at IF0 after foreign owner already exited.
    unsafe fn complete(&self, context: &TaskContext) -> Result<(), WorkError>;
    /// # Safety
    /// Called on the idle taskless dispatcher at IF0 after genuine foreign quiescence.
    unsafe fn detach(&self, context: &TaskContext) -> Result<(), WorkError>;
}

#[cfg(target_arch = "x86_64")]
struct WakeSignal {
    sequence: AtomicU64,
    pending: AtomicBool,
}
/// IRQ-safe retained read/admission view. No Runtime, Task, foreign task or
/// stack pointer is stored here. A completed job's handle never authorizes a
/// future job on the same continuation; stale views may outlive retired stacks.
#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
pub struct WakeHandle<const N: usize> {
    queue: ManuallyDrop<Arc<Queue<N>>>,
    signal: ManuallyDrop<Arc<WakeSignal>>,
    id: ContextId,
    sequence: u64,
}
#[cfg(target_arch = "x86_64")]
impl<const N: usize> WakeHandle<N> {
    pub fn context_id(&self) -> ContextId {
        self.id
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Qualified same-CPU process/IRQ admission only; never resume inline or
    /// change the foreign condition. Close permits wakes for admitted jobs.
    /// Release/acquire pending plus final IF exclusion covers wake at park.
    pub fn wake(&self) -> Result<(), WorkError> {
        let mut guard = self.queue.lock()?;
        if guard.state().poisoned
            || self.queue.retired.load(Ordering::Acquire)
            || self.queue.abandoned.load(Ordering::Acquire)
            || self.signal.sequence.load(Ordering::Acquire) != self.sequence
        {
            return Err(WorkError::Closed);
        }
        self.signal.pending.store(true, Ordering::Release);
        Ok(())
    }
    /// Refresh only from this same genuine executing continuation. Reused-job
    /// arrive can replace an old handle without a Runtime pointer. Runtime's
    /// active binding retains Queue/signal, so such replacement decrements only
    /// nonfinal Arc references; it cannot release any owner/code/stack backing.
    pub fn renew_current(&self) -> Result<Self, WorkError> {
        if self.queue.current_id()? != self.id {
            return Err(WorkError::Unavailable);
        }
        let sequence = self.signal.sequence.load(Ordering::Acquire);
        if sequence == 0 {
            return Err(WorkError::Closed);
        }
        Ok(Self {
            queue: self.queue.clone(),
            signal: self.signal.clone(),
            id: self.id,
            sequence,
        })
    }
}

#[cfg(target_arch = "x86_64")]
impl<const N: usize> Drop for WakeHandle<N> {
    fn drop(&mut self) {
        if self.queue.process().is_ok() {
            // SAFETY: process context on the qualified CPU. Runtime retains
            // nonfinal refs during attach/arrive replacement; stale handles
            // may finally release an already-retired queue only here.
            unsafe {
                ManuallyDrop::drop(&mut self.signal);
                ManuallyDrop::drop(&mut self.queue);
            }
        } else {
            // Destruction is not IRQ/foreign-CPU reclamation authority. Keep
            // both allocations/roots rather than freeing a final owner there.
            quarantine();
        }
    }
}
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum TaskState {
    Idle,
    Ready,
    Running,
    Runnable,
    Blocked,
}
#[cfg(target_arch = "x86_64")]
struct Task {
    stack: Stack,
    id: ContextId,
    frame: context::Frame,
    state: TaskState,
    job: Option<(usize, Job)>,
    flags: u64,
    draining: bool,
    binding: Option<Arc<dyn SwitchBinding>>,
    signal: Arc<WakeSignal>,
}
/// CPU-affine pinned executor. Task zero is a real foreground continuation,
/// task one is serial Notify; remaining stacks run general work. The dispatcher
/// itself has no fabricated thread ID. All switching happens with IF=0.
#[cfg(target_arch = "x86_64")]
pub struct Runtime<const N: usize> {
    queue: Arc<Queue<N>>,
    tasks: ManuallyDrop<UnsafeCell<Vec<Task>>>,
    dispatch: UnsafeCell<context::Frame>,
    current: Cell<usize>,
    cursor: Cell<usize>,
    retired: Cell<bool>,
    _local: PhantomData<*mut ()>,
    _pinned: PhantomPinned,
}
#[cfg(target_arch = "x86_64")]
impl<const N: usize> Runtime<N> {
    fn validate_stacks(queue: &Queue<N>, stacks: &[Stack]) -> Result<(), WorkError> {
        queue.process()?;
        if stacks.len() < 4 || stacks.len() > 16 {
            return Err(WorkError::Unavailable);
        }
        for (i, a) in stacks.iter().enumerate() {
            for b in &stacks[..i] {
                if a.bounds.start < b.bounds.end && b.bounds.start < a.bounds.end {
                    return Err(WorkError::InvalidStack);
                }
                if a.backing.guard().start < b.bounds.end && b.bounds.start < a.backing.guard().end
                    || b.backing.guard().start < a.bounds.end
                        && a.bounds.start < b.backing.guard().end
                {
                    return Err(WorkError::InvalidStack);
                }
            }
        }
        let rsp = context::stack_pointer();
        if stacks.iter().any(|s| s.bounds.contains(&rsp)) {
            return Err(WorkError::InvalidStack);
        }
        Ok(())
    }
    fn new(queue: Arc<Queue<N>>, stacks: Vec<Stack>) -> Result<Pin<Box<Self>>, WorkError> {
        Self::validate_stacks(&queue, &stacks)?;
        // SAFETY: the executor runs on the qualified native CPL0 CPU.
        let controls = unsafe { context::controls()? };
        Self::with_controls(queue, stacks, controls)
    }
    fn with_controls(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
        controls: context::Controls,
    ) -> Result<Pin<Box<Self>>, WorkError> {
        let mut tasks = Vec::new();
        tasks
            .try_reserve_exact(stacks.len())
            .map_err(|_| WorkError::Full)?;
        for stack in stacks {
            let id = NEXT_CONTEXT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| WorkError::Exhausted)?;
            tasks.push(Task {
                stack,
                id: ContextId(id),
                frame: context::Frame::new(controls),
                state: TaskState::Idle,
                job: None,
                flags: 0,
                draining: false,
                binding: None,
                signal: Arc::new(WakeSignal {
                    sequence: AtomicU64::new(0),
                    pending: AtomicBool::new(false),
                }),
            });
        }
        if queue
            .executor_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(WorkError::Busy);
        }
        let executor = Box::pin(Self {
            queue,
            tasks: ManuallyDrop::new(UnsafeCell::new(tasks)),
            dispatch: UnsafeCell::new(context::Frame::new(controls)),
            current: Cell::new(NONE),
            cursor: Cell::new(0),
            retired: Cell::new(false),
            _local: PhantomData,
            _pinned: PhantomPinned,
        });
        let pointer = executor.as_ref().get_ref() as *const Self as usize;
        // SAFETY: the executor is not yet shared, and each frame starts on its own
        // retained stack.
        unsafe {
            for (i, task) in (&mut *executor.tasks.get()).iter_mut().enumerate() {
                task.frame
                    .start(task.stack.bounds.end, pointer, i, entry::<N>);
            }
        }
        Ok(executor)
    }
    unsafe fn task(&self, index: usize) -> *mut Task {
        // SAFETY: Immutable Vec allocation: take no Rust reference across a switch.
        unsafe { (&mut *self.tasks.get()).as_mut_ptr().add(index) }
    }
    pub fn queue(&self) -> &Arc<Queue<N>> {
        &self.queue
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
    fn context_view(&self, index: usize, active: bool) -> TaskContext {
        // SAFETY: callers qualify CPU/exclusion and a valid retained index.
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
    /// Attach a preallocated retained binding on this actual executing stack.
    /// No hook runs on a dispatcher/IRQ stack. Failure does not install the
    /// binding. This call consumes the supplied Arc; retain a separate clone
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
                // authority. Preserve the supplied binding's roots there.
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
            // SAFETY: current task is retained and IF0 protects its job assignment.
            let task = unsafe { &*self.task(index) };
            if view.sequence == 0 || task.signal.sequence.load(Ordering::Acquire) != view.sequence {
                return Err(WorkError::CorruptContext);
            }
            // SAFETY: the retained unsafe binding promises transactional/no-switch hooks.
            unsafe { binding.attach(&view)? };
            let handle = WakeHandle {
                queue: ManuallyDrop::new(self.queue.clone()),
                signal: ManuallyDrop::new(task.signal.clone()),
                id: task.id,
                sequence: view.sequence,
            };
            // SAFETY: exclusive qualified CPU; prior immutable borrow's last use is above.
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
    fn arrive(&self, index: usize, new_job: bool) {
        self.valid();
        let view = self.context_view(index, true);
        // SAFETY: retained current task on its real destination stack at IF0.
        if let Some(binding) = unsafe { &(*self.task(index)).binding } {
            // SAFETY: no lock/switch borrow; the retained hook restores foreign state.
            let result = unsafe { binding.arrive(&view, new_job) };
            if let Err(error) = result {
                self.queue.cpu.fatal(error);
            }
        }
    }
    /// # Safety
    /// Real foreign producers/task/wake references are quiescent. The retained
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
            // SAFETY: index comes from this retained vector.
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
    fn valid(&self) {
        if let Err(e) = self.current_id() {
            self.queue.cpu.fatal(e)
        }
    }
    /// Suspend the actual current continuation, returning only when resumed on
    /// this same retained stack and ContextId. It never calls a queued callback
    /// recursively on the lock-owning caller stack.
    pub fn yield_now(self: Pin<&Self>) -> Result<(), WorkError> {
        self.suspend(LeaveReason::Yield).map(|_| ())
    }
    /// Suspend once only if the retained foreign predicate is still blocked.
    /// Linux-owned process PREPARE must precede this call. Skipped/error leaves
    /// its original entered lease intact; its wrapper clears prepared state.
    pub fn park_if_blocked(self: Pin<&Self>) -> Result<ParkOutcome, WorkError> {
        self.suspend(LeaveReason::Blocked)
    }
    fn suspend(self: Pin<&Self>, reason: LeaveReason) -> Result<ParkOutcome, WorkError> {
        self.current_id()?;
        let index = self.current.get();
        let flags = self.queue.cpu.save_disable()?;
        let view = self.context_view(index, true);
        let admission = {
            // SAFETY: qualified current task and IF0; borrow ends before switch.
            let binding = unsafe { &(*self.task(index)).binding };
            (|| {
                if reason == LeaveReason::Blocked {
                    let binding = binding.as_ref().ok_or(WorkError::Unavailable)?;
                    // SAFETY: IF0 pure predicate; process PREPARE is provider-owned.
                    let still_blocked = unsafe { binding.still_blocked(&view)? };
                    // SAFETY: this retained field is immutable at IF0; the short
                    // borrow ends here before foreign leave or a context switch.
                    let signal = unsafe { &(*self.task(index)).signal };
                    let pending = signal.pending.swap(false, Ordering::AcqRel);
                    if !still_blocked || pending {
                        return Ok(false);
                    }
                }
                if let Some(binding) = binding {
                    // SAFETY: transactional prepared commit only, no lock/alloc/drop/switch.
                    unsafe { binding.leave(&view, reason)? };
                }
                Ok(true)
            })()
        };
        match admission {
            Ok(true) => {}
            other => {
                // SAFETY: no departure committed; original task/current/lease intact.
                unsafe { self.queue.cpu.restore(flags) };
                return other.map(|_| ParkOutcome::Skipped);
            }
        }
        // SAFETY: running task is exclusively owned, with IF disabled.
        unsafe {
            (*self.task(index)).state = if reason == LeaveReason::Blocked {
                TaskState::Blocked
            } else {
                TaskState::Runnable
            };
        }
        self.current.set(NONE);
        self.queue.active.clear();
        // SAFETY: retained initialized frames; no Task reference or queue lock spans switch.
        unsafe {
            context::switch(
                core::ptr::addr_of_mut!((*self.task(index)).frame),
                self.dispatch.get(),
            )
        };
        self.arrive(index, false);
        // SAFETY: restored foreign and native metadata match this real resumed stack.
        unsafe { self.queue.cpu.restore(flags) };
        Ok(ParkOutcome::Resumed)
    }
    /// Run at most one genuine task continuation. No callback is inline here:
    /// actual RIP/RSP switch onto its distinct owned stack precedes callback.
    /// Caller is the main dispatcher outside locks/IRQ/native guest execution.
    /// Callback contexts must be provider-owned stable objects, not escaped
    /// references into this dispatcher stack. Queue ownership covers them.
    pub fn step(self: Pin<&Self>) -> Result<bool, WorkError> {
        self.queue.process()?;
        if self.current.get() != NONE {
            return Err(WorkError::WouldDeadlock);
        }
        if self.retired.get() || self.queue.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        let flags = self.queue.cpu.save_disable()?;
        // SAFETY: the task list's length never changes after construction.
        let count = unsafe { (*self.tasks.get()).len() };
        let mut selected = None;
        for n in 0..count {
            let i = (self.cursor.get() + n) % count;
            // SAFETY: no task runs while the dispatcher steps, so this is the only
            // reference to task `i`.
            let task = unsafe { &mut (*self.task(i)) };
            if task.state == TaskState::Idle {
                let lane = match i {
                    0 => Lane::Foreground,
                    1 => Lane::Notify,
                    _ => Lane::General,
                };
                match self.queue.next(lane) {
                    Ok(Some(job)) => {
                        task.job = Some(job);
                        task.state = TaskState::Ready;
                        task.flags = flags;
                        task.signal.pending.store(false, Ordering::Relaxed);
                        task.signal
                            .sequence
                            .store(job.1.sequence, Ordering::Release);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        // SAFETY: `flags` came from the save_disable above, and no lock is held.
                        unsafe { self.queue.cpu.restore(flags) };
                        return Err(e);
                    }
                }
            }
            if task.state == TaskState::Blocked && task.signal.pending.swap(false, Ordering::AcqRel)
            {
                task.state = TaskState::Runnable;
            }
            if matches!(task.state, TaskState::Ready | TaskState::Runnable) {
                selected = Some(i);
                break;
            }
        }
        let Some(i) = selected else {
            // SAFETY: `flags` came from the save_disable above, and no lock is held.
            unsafe { self.queue.cpu.restore(flags) };
            return Ok(false);
        };
        self.cursor.set((i + 1) % count);
        // SAFETY: task `i` is idle or waiting, and IRQs are disabled.
        unsafe {
            (*self.task(i)).state = TaskState::Running;
        }
        self.current.set(i);
        // SAFETY: task `i` is valid, and IRQs are disabled.
        unsafe {
            let task = &*self.task(i);
            self.queue.active.publish(task.id, &task.stack.bounds);
        }
        // SAFETY: both frames are retained, pinned and initialized; IRQs stay disabled
        // across the switch, and no lock or borrow spans it.
        unsafe {
            context::switch(
                self.dispatch.get(),
                core::ptr::addr_of!((*self.task(i)).frame),
            )
        };
        if self.current.get() != NONE || self.queue.active.id.load(Ordering::Acquire) != 0 {
            self.queue.cpu.fatal(WorkError::CorruptContext);
        }
        // SAFETY: the dispatcher resumed with `flags` from its own save_disable.
        unsafe { self.queue.cpu.restore(flags) };
        Ok(true)
    }
    /// Foreground AML/driver calls receive a real distinct task/stack identity.
    /// Dispatcher/root/IRQ callers never receive an invented ACPICA thread ID.
    /// # Safety
    /// Callback/context ownership and bounded-stack/no-unwind rules match execute.
    /// No caller stack-local reference may escape into the job. Timeout or
    /// Pending does not cancel or release admitted work: its genuine provider-
    /// owned context remains retained until completion or permanent quarantine.
    pub unsafe fn call_foreground(
        self: Pin<&Self>,
        callback: Callback,
        ctx: *mut c_void,
        deadline: u64,
    ) -> Result<(), WorkError> {
        self.queue.process()?;
        if self.current.get() != NONE {
            return Err(WorkError::WouldDeadlock);
        }
        let ticket = self.queue.enqueue_lane(Lane::Foreground, callback, ctx)?;
        while !self.queue.completed(ticket)? {
            if self.queue.cpu.ticks() >= deadline {
                return Err(WorkError::TimedOut);
            }
            if !self.step()? {
                return Err(WorkError::Pending);
            }
        }
        Ok(())
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
                let mut queued_lanes = [false; 3];
                for job in s.jobs.iter().flatten().filter(|job| !job.running) {
                    let lane = match job.lane {
                        Lane::Foreground => 0,
                        Lane::Notify => 1,
                        Lane::General => 2,
                    };
                    queued_lanes[lane] = true;
                }
                // A queued job requires an Idle continuation in its own lane.
                // Snapshot both jobs and peer eligibility under this same IF0
                // queue guard; the current drain never counts itself.
                // SAFETY: the qualified CPU owns this task table; all peers
                // are suspended and no task reference crosses a switch.
                let peer_progress = current == NONE
                    || unsafe {
                        (&*self.tasks.get()).iter().enumerate().any(|(i, task)| {
                            i != current
                                && match task.state {
                                    TaskState::Ready | TaskState::Runnable => true,
                                    TaskState::Blocked => {
                                        task.signal.pending.load(Ordering::Acquire)
                                    }
                                    TaskState::Idle => {
                                        queued_lanes[match i {
                                            0 => 0,
                                            1 => 1,
                                            _ => 2,
                                        }]
                                    }
                                    TaskState::Running => false,
                                }
                        })
                    };
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
    /// Actual producers/IRQ/work/reset users have been stopped and cannot
    /// enqueue or resume this executor; no callback/current native frame exists.
    /// Timeout/failed drain is not retirement authority and retains every owner.
    pub unsafe fn retire(self: Pin<&Self>) -> Result<(), WorkError> {
        self.queue.process()?;
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
#[cfg(target_arch = "x86_64")]
unsafe extern "sysv64" fn entry<const N: usize>(pointer: usize, index: usize) -> ! {
    // SAFETY: covered by this function's own safety contract.
    let executor = unsafe { &*(pointer as *const Runtime<N>) };
    loop {
        executor.valid();
        // SAFETY: covered by this function's own safety contract.
        let (slot, job, flags) = unsafe {
            let t = &(*executor.task(index));
            let (slot, job) = t.job.expect("assigned task");
            (slot, job, t.flags)
        };
        executor.arrive(index, true);
        // SAFETY: covered by this function's own safety contract.
        unsafe { executor.queue.cpu.restore(flags) };
        // SAFETY: covered by this function's own safety contract.
        unsafe { (job.callback)(job.context as *mut c_void) };
        executor.valid();
        let _flags = match executor.queue.cpu.save_disable() {
            Ok(f) => f,
            Err(e) => executor.queue.cpu.fatal(e),
        };
        let view = executor.context_view(index, true);
        // SAFETY: actual retained completing task on its own stack at IF0.
        if let Some(binding) = unsafe { &(*executor.task(index)).binding } {
            // SAFETY: owner already exited; no lock/switch borrow spans this hook.
            let result = unsafe { binding.complete(&view) };
            if let Err(error) = result {
                executor.queue.cpu.fatal(error);
            }
        }
        {
            // SAFETY: retained signal field; this borrow ends before later Task
            // mutation. Close this exact job so old wake handles remain inert.
            let signal = unsafe { &(*executor.task(index)).signal };
            signal.sequence.store(0, Ordering::Release);
        }
        if let Err(e) = executor.queue.finish(slot, job.sequence) {
            executor.queue.cpu.fatal(e);
        }
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            let t = &mut (*executor.task(index));
            t.job = None;
            t.state = TaskState::Idle;
        }
        executor.current.set(NONE);
        executor.queue.active.clear();
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            context::switch(
                core::ptr::addr_of_mut!((*executor.task(index)).frame),
                executor.dispatch.get(),
            )
        };
        // Next job resumes a real continuation on this same owned task stack.
    }
}
#[cfg(target_arch = "x86_64")]
impl<const N: usize> Drop for Runtime<N> {
    fn drop(&mut self) {
        if self.retired.get() {
            // SAFETY: retirement proved no task frame or stack is still live.
            unsafe { ManuallyDrop::drop(&mut self.tasks) };
        } else {
            quarantine();
        }
    }
}

#[cfg(target_arch = "x86_64")]
struct DrainFlag {
    task: *mut bool,
}
#[cfg(target_arch = "x86_64")]
impl Drop for DrainFlag {
    fn drop(&mut self) {
        // SAFETY: the flag belongs to a task the executor retains past this drain.
        unsafe {
            self.task.write(false);
        }
    }
}

/// Sole owning constructor for a runtime; its bare pinned allocation is never
/// publicly returned. Construction and final release require process/deferred
/// context on the qualified CPU, including the last Arc release of providers.
/// Owns the complete pinned runtime allocation. An uncertain Drop retains the
/// allocation itself, not just stack pages containing pointers back to it.
#[cfg(target_arch = "x86_64")]
pub struct Executor<const N: usize> {
    runtime: ManuallyDrop<Pin<Box<Runtime<N>>>>,
}
#[cfg(target_arch = "x86_64")]
impl<const N: usize> Executor<N> {
    pub fn new(queue: Arc<Queue<N>>, stacks: Vec<Stack>) -> Result<Self, WorkError> {
        Ok(Self {
            runtime: ManuallyDrop::new(Runtime::new(queue, stacks)?),
        })
    }
    /// Genuine hosted continuation mechanism test only. StackBacking must own
    /// real mapped guarded stacks; Cpu is an explicit hosted model. This never
    /// qualifies CPL0/IRQ/native roots or registers a native producer.
    #[cfg(test)]
    pub(crate) fn new_hosted_for_test(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
    ) -> Result<Self, WorkError> {
        Runtime::<N>::validate_stacks(&queue, &stacks)?;
        // SAFETY: unprivileged read only, used solely by actual hosted stack tests.
        let controls = unsafe { context::read_controls() };
        Ok(Self {
            runtime: ManuallyDrop::new(Runtime::with_controls(queue, stacks, controls)?),
        })
    }
    /// The returned actual pinned runtime is what a retained native provider
    /// binds into its context. Do not retain a pointer to this movable wrapper.
    pub fn runtime(&self) -> Pin<&Runtime<N>> {
        self.runtime.as_ref()
    }
}
#[cfg(target_arch = "x86_64")]
impl<const N: usize> Drop for Executor<N> {
    fn drop(&mut self) {
        let process = self.runtime.queue.process().is_ok();
        if process && self.runtime.retired.get() {
            // SAFETY: the runtime retired, so no task or provider can resume it.
            unsafe {
                ManuallyDrop::drop(&mut self.runtime);
            }
        } else {
            self.runtime.queue.abandoned.store(true, Ordering::Release);
            if process && let Ok(flags) = self.runtime.queue.cpu.save_disable() {
                self.runtime.queue.active.clear();
                // SAFETY: `flags` came from the save_disable just above.
                unsafe { self.runtime.queue.cpu.restore(flags) };
            }
            // If affinity/context is unqualified, closing is atomic and the
            // complete allocation remains retained; no foreign CPU mutates
            // active metadata or releases process-affine owners.
            quarantine();
            // Keep the actual Runtime allocation, queue/provider owners, task
            // frames and real stack/root leases even after a timeout/failed drain.
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{sync::Mutex, thread};
    struct CpuModel {
        thread: thread::ThreadId,
        flags: AtomicU64,
        irq: AtomicBool,
        time: AtomicU64,
    }
    impl CpuModel {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                thread: thread::current().id(),
                flags: AtomicU64::new(0x202),
                irq: AtomicBool::new(false),
                time: AtomicU64::new(0),
            })
        }
    }
    // SAFETY: explicit hosted exclusion/flags model only. It never installs a
    // native provider or attests privileged CLI/IRQ behavior; QEMU tests bind
    // those separately. Real x86 continuations use actual OS-owned VM stacks.
    unsafe impl Cpu for CpuModel {
        fn check_cpu(&self) -> Result<(), WorkError> {
            if thread::current().id() == self.thread {
                Ok(())
            } else {
                Err(WorkError::WrongCpu)
            }
        }
        fn in_interrupt(&self) -> bool {
            self.irq.load(Ordering::Acquire)
        }
        fn save_disable(&self) -> Result<u64, WorkError> {
            self.check_cpu()?;
            Ok(self.flags.swap(2, Ordering::AcqRel))
        }
        unsafe fn restore(&self, flags: u64) {
            self.flags.store(flags, Ordering::Release);
        }
        fn ticks(&self) -> u64 {
            self.time.fetch_add(1, Ordering::Relaxed)
        }
        fn fatal(&self, e: WorkError) -> ! {
            panic!("fatal context {e:?}")
        }
    }
    struct Owner(Arc<AtomicU64>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    unsafe extern "C" fn noop(_: *mut c_void) {}
    #[test]
    fn admission_is_bounded_noninline_closed_and_restores_nested_flags() {
        let cpu = CpuModel::new();
        let drops = Arc::new(AtomicU64::new(0));
        let queue =
            unsafe { Queue::<2>::new(cpu.clone(), Arc::new(Owner(drops.clone()))) }.unwrap();
        cpu.irq.store(true, Ordering::Release);
        let a = unsafe { queue.execute(Kind::Notify, noop, core::ptr::null_mut()) }.unwrap();
        let b = unsafe { queue.execute(Kind::General, noop, core::ptr::null_mut()) }.unwrap();
        assert_eq!(
            unsafe { queue.execute(Kind::General, noop, core::ptr::null_mut()) },
            Err(WorkError::Full)
        );
        assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
        cpu.flags.store(2, Ordering::Release);
        queue.close().unwrap();
        assert_eq!(cpu.flags.load(Ordering::Acquire), 2);
        assert!(!queue.completed(a).unwrap());
        assert!(!queue.completed(b).unwrap());
        assert_eq!(
            unsafe { queue.execute(Kind::General, noop, core::ptr::null_mut()) },
            Err(WorkError::Closed)
        );
        cpu.irq.store(false, Ordering::Release);
        assert_eq!(unsafe { queue.retire() }, Err(WorkError::Pending));
        let foreign = queue.clone();
        assert_eq!(
            thread::spawn(move || foreign.close()).join().unwrap(),
            Err(WorkError::WrongCpu)
        );
        let count = quarantined_owners();
        drop(queue);
        assert!(quarantined_owners() >= count.saturating_add(1));
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn queue_ids_tickets_and_sequence_exhaustion_do_not_alias_or_wrap() {
        let cpu = CpuModel::new();
        let owner: RetainedOwner = Arc::new(());
        let a = unsafe { Queue::<2>::new(cpu.clone(), owner.clone()) }.unwrap();
        let b = unsafe { Queue::<2>::new(cpu, owner) }.unwrap();
        let ticket = unsafe { a.execute(Kind::General, noop, core::ptr::null_mut()) }.unwrap();
        assert_eq!(b.completed(ticket), Err(WorkError::InvalidTicket));
        {
            let mut g = b.lock().unwrap();
            g.state().next = u64::MAX;
        }
        assert_eq!(
            unsafe { b.execute(Kind::General, noop, core::ptr::null_mut()) },
            Err(WorkError::Exhausted)
        );
        assert!(b.lock().unwrap().state().jobs.iter().all(Option::is_none));
        b.close().unwrap();
        unsafe { b.retire() }.unwrap();
        drop((a, b));
    }

    #[cfg(target_arch = "x86_64")]
    mod switched {
        use super::*;
        use core::arch::asm;
        unsafe extern "C" {
            fn mmap(
                address: *mut c_void,
                bytes: usize,
                protection: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut c_void;
            fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
            fn munmap(address: *mut c_void, bytes: usize) -> i32;
        }
        struct MappedStack {
            base: usize,
            bytes: usize,
            dropped: Arc<AtomicU64>,
        }
        // SAFETY: actual exclusive private OS mmap, guard has PROT_NONE, and the
        // owning runtime retains this exact mapping through every continuation.
        unsafe impl StackBacking for MappedStack {
            fn bounds(&self) -> Range<usize> {
                self.base + 4096..self.base + self.bytes
            }
            fn guard(&self) -> Range<usize> {
                self.base..self.base + 4096
            }
        }
        impl Drop for MappedStack {
            fn drop(&mut self) {
                assert_eq!(unsafe { munmap(self.base as *mut c_void, self.bytes) }, 0);
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        fn stacks(dropped: Arc<AtomicU64>) -> Vec<Stack> {
            (0..4)
                .map(|_| {
                    #[cfg(target_os = "macos")]
                    let anonymous = 0x1000;
                    #[cfg(not(target_os = "macos"))]
                    let anonymous = 0x20;
                    let bytes = 128 * 1024 + 4096;
                    let base =
                        unsafe { mmap(core::ptr::null_mut(), bytes, 3, 2 | anonymous, -1, 0) };
                    assert_ne!(base as usize, usize::MAX);
                    assert_eq!(unsafe { mprotect(base, 4096, 0) }, 0);
                    Stack::new(Box::new(MappedStack {
                        base: base as usize,
                        bytes,
                        dropped: dropped.clone(),
                    }))
                    .unwrap()
                })
                .collect()
        }
        struct Fixture {
            cpu: Arc<CpuModel>,
            baseline: context::Controls,
            runtime: AtomicU64,
            events: Mutex<Vec<(u64, u64, usize)>>,
            done: AtomicBool,
        }
        impl Fixture {
            unsafe fn runtime(&self) -> Pin<&Runtime<16>> {
                unsafe {
                    Pin::new_unchecked(
                        &*(self.runtime.load(Ordering::Acquire) as *const Runtime<16>),
                    )
                }
            }
            fn event(&self, value: u64) {
                let runtime = unsafe { self.runtime() };
                let id = runtime.current_id().unwrap();
                assert_eq!(runtime.queue.current_id(), Ok(id));
                self.events
                    .lock()
                    .unwrap()
                    .push((value, id.get(), context::stack_pointer()));
            }
        }
        unsafe fn fixture<'a>(p: *mut c_void) -> &'a Fixture {
            unsafe { &*p.cast::<Fixture>() }
        }
        unsafe extern "C" fn notify_one(p: *mut c_void) {
            let f = unsafe { fixture(p) };
            f.event(20);
            unsafe { f.runtime() }.yield_now().unwrap();
            f.event(21);
        }
        unsafe extern "C" fn notify_two(p: *mut c_void) {
            unsafe { fixture(p) }.event(22);
        }
        unsafe extern "C" fn general_one(p: *mut c_void) {
            let f = unsafe { fixture(p) };
            f.event(30);
            // Model actual interrupt-entry metadata while hardware RSP still
            // belongs to a real task stack. IF/stack membership alone must
            // never authorize a thread ID or context switch from an ISR.
            f.cpu.irq.store(true, Ordering::Release);
            let r = unsafe { f.runtime() };
            assert_eq!(r.current_id(), Err(WorkError::InterruptContext));
            assert_eq!(r.queue.current_id(), Err(WorkError::InterruptContext));
            assert_eq!(r.yield_now(), Err(WorkError::InterruptContext));
            f.cpu.irq.store(false, Ordering::Release);
            let original = unsafe { context::read_controls() };
            let mxcsr = (original.mxcsr & !(3 << 13)) | 2 << 13;
            let fcw = (original.fcw & !(3 << 10)) | 2 << 10;
            unsafe {
                asm!("ldmxcsr [{}]",in(reg)&mxcsr,options(nostack));
                asm!("fldcw [{}]",in(reg)&fcw,options(nostack));
            }
            unsafe { f.runtime() }.yield_now().unwrap();
            let resumed = unsafe { context::read_controls() };
            assert_eq!(resumed.mxcsr, mxcsr);
            assert_eq!(resumed.fcw, fcw);
            unsafe {
                asm!("ldmxcsr [{}]",in(reg)&original.mxcsr,options(nostack));
                asm!("fldcw [{}]",in(reg)&original.fcw,options(nostack));
            }
            f.event(31);
        }
        unsafe extern "C" fn general_two(p: *mut c_void) {
            let f = unsafe { fixture(p) };
            let controls = unsafe { context::read_controls() };
            assert_eq!(controls.mxcsr, f.baseline.mxcsr);
            assert_eq!(controls.fcw, f.baseline.fcw);
            f.event(40);
        }
        unsafe extern "C" fn foreground(p: *mut c_void) {
            let f = unsafe { fixture(p) };
            f.event(10);
            let r = unsafe { f.runtime() };
            unsafe { r.queue.execute(Kind::Notify, notify_one, p) }.unwrap();
            unsafe { r.queue.execute(Kind::Notify, notify_two, p) }.unwrap();
            unsafe { r.queue.execute(Kind::General, general_one, p) }.unwrap();
            unsafe { r.queue.execute(Kind::General, general_two, p) }.unwrap();
            assert_eq!(
                f.events.lock().unwrap().len(),
                1,
                "execute must not run inline"
            );
            r.drain(10000).unwrap();
            f.event(11);
        }
        fn setup() -> (Executor<16>, Arc<Fixture>, Arc<CpuModel>, Arc<AtomicU64>) {
            let cpu = CpuModel::new();
            let f = Arc::new(Fixture {
                cpu: cpu.clone(),
                baseline: unsafe { context::read_controls() },
                runtime: AtomicU64::new(0),
                events: Mutex::new(Vec::new()),
                done: AtomicBool::new(false),
            });
            let q = unsafe { Queue::<16>::new(cpu.clone(), f.clone()) }.unwrap();
            let dropped = Arc::new(AtomicU64::new(0));
            // Explicit hosted actual-stack mechanism test. Native construction
            // additionally qualifies CPL0 CR0/CR4/IRQ behavior; this is not a
            // native provider or IRQ delivery attestation.
            let runtime = Runtime::with_controls(q, stacks(dropped.clone()), unsafe {
                context::read_controls()
            })
            .unwrap();
            f.runtime.store(
                runtime.as_ref().get_ref() as *const _ as u64,
                Ordering::Release,
            );
            (
                Executor {
                    runtime: ManuallyDrop::new(runtime),
                },
                f,
                cpu,
                dropped,
            )
        }
        #[test]
        fn actual_x86_continuations_have_distinct_stacks_ids_fifo_and_control_state() {
            let (executor, f, cpu, dropped) = setup();
            let r = executor.runtime();
            assert_eq!(r.current_id(), Err(WorkError::Unavailable));
            let original = unsafe { context::read_controls() };
            unsafe { r.call_foreground(foreground, Arc::as_ptr(&f) as *mut c_void, 10000) }
                .unwrap();
            let after = unsafe { context::read_controls() };
            assert_eq!(original.mxcsr, after.mxcsr);
            assert_eq!(original.fcw, after.fcw);
            let events = f.events.lock().unwrap();
            let pos = |n| events.iter().position(|e| e.0 == n).unwrap();
            assert!(pos(20) < pos(21) && pos(21) < pos(22));
            assert!(pos(30) < pos(40) && pos(40) < pos(31));
            assert_eq!(events[pos(10)].1, events[pos(11)].1);
            assert_eq!(events[pos(20)].1, events[pos(22)].1);
            let mut ids: Vec<_> = events.iter().map(|e| e.1).collect();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(ids.len(), 4);
            for (_, _, rsp) in &*events {
                assert!(
                    unsafe { &*r.tasks.get() }
                        .iter()
                        .any(|t| t.stack.bounds.contains(rsp))
                );
            }
            assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
            assert_eq!(r.queue.current_id(), Err(WorkError::Unavailable));
            drop(events);
            let view = r.queue.clone();
            unsafe { r.retire() }.unwrap();
            assert_eq!(view.current_id(), Err(WorkError::Closed));
            drop(executor);
            assert_eq!(dropped.load(Ordering::Relaxed), 4);
        }
        #[test]
        fn one_actual_executor_per_view_rejects_simultaneous_and_retired_rebinding() {
            let (executor, _, _, _) = setup();
            let view = executor.runtime().queue.clone();
            let dropped = Arc::new(AtomicU64::new(0));
            for retired in [false, true] {
                if retired {
                    unsafe { executor.runtime().retire() }.unwrap();
                }
                let result =
                    Runtime::with_controls(view.clone(), stacks(dropped.clone()), unsafe {
                        context::read_controls()
                    });
                assert!(matches!(result, Err(WorkError::Busy)));
                assert_eq!(
                    view.current_id(),
                    Err(if retired {
                        WorkError::Closed
                    } else {
                        WorkError::Unavailable
                    })
                );
            }
            assert_eq!(dropped.load(Ordering::Relaxed), 8);
        }

        unsafe extern "C" fn serial_drain(p: *mut c_void) {
            let f = unsafe { fixture(p) };
            let r = unsafe { f.runtime() };
            unsafe { r.queue.execute(Kind::Notify, notify_two, p) }.unwrap();
            assert_eq!(r.drain(10000), Err(WorkError::WouldDeadlock));
            f.event(50);
        }
        unsafe extern "C" fn cyclic_drain(p: *mut c_void) {
            let f = unsafe { fixture(p) };
            let r = unsafe { f.runtime() };
            let result = r.drain(10000);
            assert!(matches!(result, Ok(()) | Err(WorkError::WouldDeadlock)));
            f.event(if result.is_err() { 61 } else { 60 });
        }
        #[test]
        fn serial_and_actual_two_task_drain_cycles_refuse_without_hanging() {
            let (executor, f, _, _) = setup();
            let r = executor.runtime();
            let context = Arc::as_ptr(&f) as *mut c_void;
            unsafe { r.queue.execute(Kind::Notify, serial_drain, context) }.unwrap();
            unsafe { r.queue.execute(Kind::General, cyclic_drain, context) }.unwrap();
            unsafe { r.queue.execute(Kind::General, cyclic_drain, context) }.unwrap();
            r.drain(20000).unwrap();
            let events = f.events.lock().unwrap();
            assert!(events.iter().any(|e| e.0 == 50));
            assert!(events.iter().any(|e| e.0 == 61));
            assert!(events.iter().any(|e| e.0 == 60));
            drop(events);
            unsafe { r.retire() }.unwrap();
        }
        unsafe extern "C" fn suspended(p: *mut c_void) {
            let f = unsafe { fixture(p) };
            while !f.done.load(Ordering::Acquire) {
                unsafe { f.runtime() }.yield_now().unwrap();
            }
        }
        #[test]
        fn timeout_retains_the_actual_runtime_all_stacks_and_callback_provider() {
            let (executor, f, _, dropped) = setup();
            let raw = executor.runtime().get_ref() as *const Runtime<16>;
            let view = executor.runtime().queue.clone();
            assert_eq!(
                unsafe {
                    executor.runtime().call_foreground(
                        suspended,
                        Arc::as_ptr(&f) as *mut c_void,
                        20,
                    )
                },
                Err(WorkError::TimedOut)
            );
            assert_eq!(
                unsafe { executor.runtime().retire() },
                Err(WorkError::Pending)
            );
            let weak = Arc::downgrade(&f);
            drop(executor);
            drop(f);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            assert!(weak.upgrade().is_some());
            assert_eq!(view.current_id(), Err(WorkError::Closed));
            assert_eq!(view.active.id.load(Ordering::Acquire), 0);
            let retained = unsafe { Pin::new_unchecked(&*raw) };
            assert_eq!(retained.step(), Err(WorkError::Closed));
        }
        // Genuine switched-stack fixtures for the generic binding contract.
        // This is a hosted state/IRQ model, not a native Linux/C task producer.
        mod bound {
            use super::*;

            struct Globals {
                current: AtomicU64,
                preempt: AtomicU64,
                virtual_irq: AtomicU64,
                entered: AtomicBool,
            }
            struct Binding {
                cpu: Arc<CpuModel>,
                globals: Arc<Globals>,
                id: AtomicU64,
                sequence: AtomicU64,
                saved_preempt: AtomicU64,
                saved_irq: AtomicU64,
                saved_entered: AtomicBool,
                blocked: AtomicBool,
                prepared: AtomicBool,
                refuse_attach: AtomicBool,
                refuse_leave: AtomicBool,
                wake_at_commit: AtomicBool,
                refs: AtomicU64,
                arrives: AtomicU64,
                completed: AtomicU64,
                detached: AtomicBool,
                handle: Mutex<Option<WakeHandle<16>>>,
            }
            impl Binding {
                fn new(cpu: Arc<CpuModel>, globals: Arc<Globals>) -> Arc<Self> {
                    Arc::new(Self {
                        cpu,
                        globals,
                        id: AtomicU64::new(0),
                        sequence: AtomicU64::new(0),
                        saved_preempt: AtomicU64::new(0),
                        saved_irq: AtomicU64::new(0x200),
                        saved_entered: AtomicBool::new(false),
                        blocked: AtomicBool::new(false),
                        prepared: AtomicBool::new(false),
                        refuse_attach: AtomicBool::new(false),
                        refuse_leave: AtomicBool::new(false),
                        wake_at_commit: AtomicBool::new(false),
                        refs: AtomicU64::new(1),
                        arrives: AtomicU64::new(0),
                        completed: AtomicU64::new(0),
                        detached: AtomicBool::new(false),
                        handle: Mutex::new(None),
                    })
                }
                fn stack(&self, context: &TaskContext, active: bool) {
                    assert_eq!(self.cpu.flags.load(Ordering::Acquire), 2);
                    assert!(
                        (context.stack_start..context.stack_end).contains(&context.stack_pointer)
                    );
                    assert_eq!(context.guard_end, context.stack_start);
                    assert!(context.guard_end - context.guard_start >= 4096);
                    assert_eq!(
                        (context.stack_start..context.stack_end)
                            .contains(&context::stack_pointer()),
                        active
                    );
                    if active {
                        assert!(context.sequence > 0);
                    }
                }
                fn current(&self, context: &TaskContext) {
                    self.stack(context, true);
                    assert_eq!(self.id.load(Ordering::Acquire), context.context_id);
                    assert_eq!(self.sequence.load(Ordering::Acquire), context.sequence);
                    assert_eq!(
                        self.globals.current.load(Ordering::Acquire),
                        context.context_id
                    );
                }
                fn enter(&self, preempt: u64, virtual_irq: u64) {
                    assert_eq!(
                        self.globals.current.load(Ordering::Acquire),
                        self.id.load(Ordering::Acquire)
                    );
                    assert!(!self.globals.entered.swap(true, Ordering::AcqRel));
                    self.globals.preempt.store(preempt, Ordering::Release);
                    self.globals
                        .virtual_irq
                        .store(virtual_irq, Ordering::Release);
                }
                fn exit(&self) {
                    self.blocked.store(false, Ordering::Release);
                    self.prepared.store(false, Ordering::Release);
                    self.globals.preempt.store(0, Ordering::Release);
                    self.globals.virtual_irq.store(0x200, Ordering::Release);
                    assert!(self.globals.entered.swap(false, Ordering::AcqRel));
                }
                fn wake(&self) {
                    self.handle
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .wake()
                        .unwrap();
                }
            }
            // SAFETY: hosted single-thread hooks use atomics and bounded try_lock,
            // retain all model roots, never switch/allocate/drop final owners.
            // They validate genuine Runtime stack/ticket metadata on every hook.
            unsafe impl SwitchBinding for Binding {
                unsafe fn attach(&self, context: &TaskContext) -> Result<(), WorkError> {
                    self.stack(context, true);
                    if self.refuse_attach.load(Ordering::Acquire) {
                        return Err(WorkError::Busy);
                    }
                    assert_eq!(self.globals.current.load(Ordering::Acquire), 0);
                    assert_eq!(self.id.swap(context.context_id, Ordering::AcqRel), 0);
                    self.sequence.store(context.sequence, Ordering::Release);
                    self.globals
                        .current
                        .store(context.context_id, Ordering::Release);
                    Ok(())
                }
                unsafe fn still_blocked(&self, context: &TaskContext) -> Result<bool, WorkError> {
                    self.current(context);
                    if !self.prepared.load(Ordering::Acquire)
                        || self.globals.preempt.load(Ordering::Acquire) != 1
                    {
                        return Err(WorkError::Busy);
                    }
                    Ok(self.blocked.load(Ordering::Acquire))
                }
                unsafe fn leave(
                    &self,
                    context: &TaskContext,
                    reason: LeaveReason,
                ) -> Result<(), WorkError> {
                    self.current(context);
                    if self.refuse_leave.load(Ordering::Acquire)
                        || (self.globals.entered.load(Ordering::Acquire)
                            && !self.prepared.load(Ordering::Acquire))
                    {
                        return Err(WorkError::Busy);
                    }
                    if reason == LeaveReason::Blocked {
                        assert_eq!(self.globals.preempt.load(Ordering::Acquire), 1);
                    }
                    self.saved_preempt.store(
                        self.globals.preempt.swap(0, Ordering::AcqRel),
                        Ordering::Release,
                    );
                    self.saved_irq.store(
                        self.globals.virtual_irq.swap(0x200, Ordering::AcqRel),
                        Ordering::Release,
                    );
                    self.saved_entered.store(
                        self.globals.entered.swap(false, Ordering::AcqRel),
                        Ordering::Release,
                    );
                    self.prepared.store(false, Ordering::Release);
                    self.globals.current.store(0, Ordering::Release);
                    if self.wake_at_commit.swap(false, Ordering::AcqRel) {
                        // Deterministic injection after final condition/pending
                        // check, before Blocked publication/switch. This is a
                        // spurious admitted wake, not a lock-acquire result.
                        if let Err(error) = self.handle.try_lock().unwrap().as_ref().unwrap().wake()
                        {
                            self.cpu.fatal(error);
                        }
                    }
                    Ok(())
                }
                unsafe fn arrive(
                    &self,
                    context: &TaskContext,
                    new_job: bool,
                ) -> Result<(), WorkError> {
                    self.stack(context, true);
                    assert_eq!(self.globals.current.load(Ordering::Acquire), 0);
                    assert_eq!(self.globals.preempt.load(Ordering::Acquire), 0);
                    assert!(!self.globals.entered.load(Ordering::Acquire));
                    assert_eq!(self.id.load(Ordering::Acquire), context.context_id);
                    if new_job {
                        assert_eq!(self.sequence.load(Ordering::Acquire), 0);
                        let mut handle = self.handle.try_lock().unwrap();
                        let renewed = handle.as_ref().unwrap().renew_current()?;
                        assert_eq!(renewed.sequence(), context.sequence);
                        *handle = Some(renewed); // nonfinal Arc decrements only
                        self.sequence.store(context.sequence, Ordering::Release);
                        self.saved_preempt.store(0, Ordering::Release);
                        self.saved_irq.store(0x200, Ordering::Release);
                        self.saved_entered.store(false, Ordering::Release);
                    } else {
                        assert_eq!(self.sequence.load(Ordering::Acquire), context.sequence);
                    }
                    self.globals
                        .current
                        .store(context.context_id, Ordering::Release);
                    self.globals.preempt.store(
                        self.saved_preempt.load(Ordering::Acquire),
                        Ordering::Release,
                    );
                    self.globals
                        .virtual_irq
                        .store(self.saved_irq.load(Ordering::Acquire), Ordering::Release);
                    self.globals.entered.store(
                        self.saved_entered.load(Ordering::Acquire),
                        Ordering::Release,
                    );
                    self.arrives.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
                unsafe fn complete(&self, context: &TaskContext) -> Result<(), WorkError> {
                    self.current(context);
                    assert!(!self.globals.entered.load(Ordering::Acquire));
                    assert_eq!(self.globals.preempt.load(Ordering::Acquire), 0);
                    assert_eq!(self.globals.virtual_irq.load(Ordering::Acquire), 0x200);
                    assert!(!self.blocked.load(Ordering::Acquire));
                    assert_eq!(self.refs.load(Ordering::Acquire), 1);
                    self.globals.current.store(0, Ordering::Release);
                    self.sequence.store(0, Ordering::Release);
                    self.completed.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
                unsafe fn detach(&self, context: &TaskContext) -> Result<(), WorkError> {
                    self.stack(context, false);
                    assert_eq!(context.context_id, self.id.load(Ordering::Acquire));
                    assert_eq!(context.sequence, 0);
                    assert_eq!(self.globals.current.load(Ordering::Acquire), 0);
                    if self.refs.load(Ordering::Acquire) != 1
                        || self.sequence.load(Ordering::Acquire) != 0
                    {
                        return Err(WorkError::Pending);
                    }
                    self.detached.store(true, Ordering::Release);
                    Ok(())
                }
            }
            struct BoundFixture {
                cpu: Arc<CpuModel>,
                runtime: AtomicU64,
                globals: Arc<Globals>,
                bindings: [Arc<Binding>; 2],
                cancelled: AtomicBool,
                data: AtomicU64,
                events: Mutex<Vec<(u64, u64, usize)>>,
            }
            impl BoundFixture {
                unsafe fn runtime(&self) -> Pin<&Runtime<16>> {
                    // SAFETY: test Queue retains this fixture; actual executor
                    // allocation stays pinned/owned through completion/quarantine.
                    unsafe {
                        Pin::new_unchecked(
                            &*(self.runtime.load(Ordering::Acquire) as *const Runtime<16>),
                        )
                    }
                }
                fn event(&self, n: u64) {
                    let runtime = unsafe { self.runtime() };
                    let context = runtime.current_context().unwrap();
                    assert_eq!(
                        context.context_id,
                        self.globals.current.load(Ordering::Acquire)
                    );
                    self.events.lock().unwrap().push((
                        n,
                        context.context_id,
                        context::stack_pointer(),
                    ));
                }
                fn bind(&self, index: usize) {
                    let binding = self.bindings[index].clone();
                    let handle = unsafe { self.runtime() }
                        .bind_current(binding.clone())
                        .unwrap();
                    *binding.handle.lock().unwrap() = Some(handle);
                }
                fn detach_all(&self) {
                    for binding in &self.bindings {
                        let id = binding.id.load(Ordering::Acquire);
                        if id == 0 {
                            continue;
                        }
                        let retained =
                            unsafe { self.runtime().detach_binding(ContextId(id)) }.unwrap();
                        assert_eq!(self.cpu.flags.load(Ordering::Acquire), 0x202);
                        assert!(binding.detached.load(Ordering::Acquire));
                        // Final model/waker release occurs only after IF restore.
                        binding.handle.lock().unwrap().take();
                        drop(retained);
                    }
                }
            }
            fn bound_setup() -> (Executor<16>, Arc<BoundFixture>, Arc<AtomicU64>) {
                let cpu = CpuModel::new();
                let globals = Arc::new(Globals {
                    current: AtomicU64::new(0),
                    preempt: AtomicU64::new(0),
                    virtual_irq: AtomicU64::new(0x200),
                    entered: AtomicBool::new(false),
                });
                let f = Arc::new(BoundFixture {
                    cpu: cpu.clone(),
                    runtime: AtomicU64::new(0),
                    globals: globals.clone(),
                    bindings: [
                        Binding::new(cpu.clone(), globals.clone()),
                        Binding::new(cpu.clone(), globals),
                    ],
                    cancelled: AtomicBool::new(false),
                    data: AtomicU64::new(0),
                    events: Mutex::new(Vec::new()),
                });
                let queue = unsafe { Queue::<16>::new(cpu, f.clone()) }.unwrap();
                let dropped = Arc::new(AtomicU64::new(0));
                let executor =
                    Executor::new_hosted_for_test(queue, stacks(dropped.clone())).unwrap();
                f.runtime.store(
                    executor.runtime().get_ref() as *const Runtime<16> as u64,
                    Ordering::Release,
                );
                (executor, f, dropped)
            }
            unsafe fn bound<'a>(p: *mut c_void) -> &'a BoundFixture {
                unsafe { &*p.cast::<BoundFixture>() }
            }
            unsafe extern "C" fn park_until_cancelled(p: *mut c_void) {
                let f = unsafe { bound(p) };
                f.bind(0);
                let binding = &f.bindings[0];
                binding.enter(1, 0x200);
                binding.blocked.store(true, Ordering::Release);
                binding.prepared.store(true, Ordering::Release);
                f.event(1);
                assert_eq!(
                    unsafe { f.runtime() }.park_if_blocked(),
                    Ok(ParkOutcome::Resumed)
                );
                assert!(f.cancelled.load(Ordering::Acquire));
                assert_eq!(f.data.load(Ordering::Acquire), 0x1234);
                assert_eq!(f.globals.preempt.load(Ordering::Acquire), 1);
                f.event(2);
                binding.exit();
            }
            #[test]
            fn blocked_pending_cancel_irq_wake_late_handle_and_quiescent_retirement() {
                let (executor, f, dropped) = bound_setup();
                let r = executor.runtime();
                let p = Arc::as_ptr(&f) as *mut c_void;
                assert_eq!(r.current_context(), Err(WorkError::Unavailable));
                assert_eq!(r.park_if_blocked(), Err(WorkError::Unavailable));
                assert_eq!(
                    unsafe { r.call_foreground(park_until_cancelled, p, 10000) },
                    Err(WorkError::Pending)
                );
                assert!(!r.step().unwrap());
                assert_eq!(r.drain(10000), Err(WorkError::Pending));
                assert_eq!(unsafe { r.retire() }, Err(WorkError::Pending));
                let handle = f.bindings[0]
                    .handle
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .clone();
                assert_eq!(
                    unsafe { r.detach_binding(handle.context_id()) }.err(),
                    Some(WorkError::Pending)
                );
                let foreign = handle.clone();
                // Return the handle to its CPU before Drop: no foreign reclamation.
                let (error, foreign) = thread::spawn(move || (foreign.wake(), foreign))
                    .join()
                    .unwrap();
                assert_eq!(error, Err(WorkError::WrongCpu));
                drop(foreign);
                r.queue.close().unwrap(); // existing blocked job must still wake
                f.data.store(0x1234, Ordering::Release);
                f.cancelled.store(true, Ordering::Release);
                f.bindings[0].blocked.store(false, Ordering::Release);
                f.cpu.flags.store(2, Ordering::Release);
                f.cpu.irq.store(true, Ordering::Release);
                assert_eq!(r.current_context(), Err(WorkError::InterruptContext));
                assert_eq!(r.park_if_blocked(), Err(WorkError::InterruptContext));
                assert_eq!(
                    handle.renew_current().err(),
                    Some(WorkError::InterruptContext)
                );
                handle.wake().unwrap();
                handle.wake().unwrap();
                assert_eq!(f.cpu.flags.load(Ordering::Acquire), 2);
                f.cpu.irq.store(false, Ordering::Release);
                f.cpu.flags.store(0x202, Ordering::Release);
                assert!(r.step().unwrap());
                assert!(!r.step().unwrap());
                assert_eq!(handle.wake(), Err(WorkError::Closed));
                f.bindings[0].refs.store(2, Ordering::Release);
                assert_eq!(
                    unsafe { r.detach_binding(handle.context_id()) }.err(),
                    Some(WorkError::Pending)
                );
                assert_eq!(unsafe { r.retire() }, Err(WorkError::Pending));
                f.bindings[0].refs.store(1, Ordering::Release);
                f.detach_all();
                unsafe { r.retire() }.unwrap();
                drop(executor);
                assert_eq!(dropped.load(Ordering::Acquire), 4);
                assert_eq!(handle.wake(), Err(WorkError::Closed));
                drop(handle);
            }
            unsafe extern "C" fn peer_waiter(p: *mut c_void) {
                let f = unsafe { bound(p) };
                f.bind(1);
                let binding = &f.bindings[1];
                binding.enter(1, 0x200);
                binding.blocked.store(true, Ordering::Release);
                binding.prepared.store(true, Ordering::Release);
                f.event(20);
                unsafe { f.runtime() }.park_if_blocked().unwrap();
                assert!(f.cancelled.load(Ordering::Acquire));
                assert_eq!(f.data.load(Ordering::Acquire), 99);
                assert_eq!(f.globals.preempt.load(Ordering::Acquire), 1);
                f.event(21);
                binding.exit();
            }
            unsafe extern "C" fn peer_waker(p: *mut c_void) {
                let f = unsafe { bound(p) };
                f.bind(0);
                let binding = &f.bindings[0];
                binding.enter(3, 0);
                f.event(10);
                unsafe { f.runtime() }
                    .queue
                    .execute(Kind::General, peer_waiter, p)
                    .unwrap();
                binding.prepared.store(true, Ordering::Release);
                unsafe { f.runtime() }.yield_now().unwrap();
                assert_eq!(f.globals.preempt.load(Ordering::Acquire), 3);
                assert_eq!(f.globals.virtual_irq.load(Ordering::Acquire), 0);
                f.event(11);
                // Pending peers are blocked; drain returns, it cannot poll them.
                assert_eq!(unsafe { f.runtime() }.drain(10000), Err(WorkError::Pending));
                f.data.store(99, Ordering::Release);
                f.cancelled.store(true, Ordering::Release);
                f.bindings[1].blocked.store(false, Ordering::Release);
                f.bindings[1].wake();
                binding.prepared.store(true, Ordering::Release);
                unsafe { f.runtime() }.yield_now().unwrap();
                assert_eq!(f.globals.preempt.load(Ordering::Acquire), 3);
                binding.exit();
                f.event(12);
            }
            #[test]
            fn multiple_real_continuations_preserve_stack_identity_preempt_irq_and_lease() {
                let (executor, f, dropped) = bound_setup();
                let r = executor.runtime();
                unsafe { r.call_foreground(peer_waker, Arc::as_ptr(&f) as *mut c_void, 10000) }
                    .unwrap();
                let events = f.events.lock().unwrap();
                let pos = |n| events.iter().position(|e| e.0 == n).unwrap();
                assert!(
                    pos(10) < pos(20)
                        && pos(20) < pos(11)
                        && pos(11) < pos(21)
                        && pos(21) < pos(12)
                );
                assert_eq!(events[pos(10)].1, events[pos(11)].1);
                assert_ne!(events[pos(10)].1, events[pos(20)].1);
                assert_ne!(events[pos(10)].2, events[pos(20)].2);
                drop(events);
                assert_eq!(f.globals.current.load(Ordering::Acquire), 0);
                f.detach_all();
                unsafe { r.retire() }.unwrap();
                drop(executor);
                assert_eq!(dropped.load(Ordering::Acquire), 4);
            }
            unsafe extern "C" fn races_and_refusals(p: *mut c_void) {
                let f = unsafe { bound(p) };
                let r = unsafe { f.runtime() };
                let binding = &f.bindings[0];
                binding.refuse_attach.store(true, Ordering::Release);
                assert_eq!(r.bind_current(binding.clone()).err(), Some(WorkError::Busy));
                assert_eq!(f.globals.current.load(Ordering::Acquire), 0);
                binding.refuse_attach.store(false, Ordering::Release);
                f.bind(0);
                binding.enter(1, 0x200);
                binding.blocked.store(true, Ordering::Release);
                binding.prepared.store(true, Ordering::Release);
                binding.wake();
                binding.wake();
                assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Skipped));
                assert!(f.globals.entered.load(Ordering::Acquire));
                assert_eq!(binding.arrives.load(Ordering::Acquire), 0);
                // The Linux process wrapper clears a skipped prepared marker.
                binding.prepared.store(false, Ordering::Release);
                assert_eq!(r.park_if_blocked(), Err(WorkError::Busy));
                assert_eq!(f.globals.preempt.load(Ordering::Acquire), 1);
                binding.prepared.store(true, Ordering::Release);
                binding.refuse_leave.store(true, Ordering::Release);
                assert_eq!(r.park_if_blocked(), Err(WorkError::Busy));
                assert!(f.globals.entered.load(Ordering::Acquire));
                binding.refuse_leave.store(false, Ordering::Release);
                binding.wake_at_commit.store(true, Ordering::Release);
                assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
                assert_eq!(binding.arrives.load(Ordering::Acquire), 1);
                // Spurious wake resumes only the continuation; it did not
                // satisfy the model condition or fabricate lock ownership.
                assert!(binding.blocked.load(Ordering::Acquire));
                binding.exit();
                f.event(30);
            }
            unsafe extern "C" fn reused_worker(p: *mut c_void) {
                let f = unsafe { bound(p) };
                let binding = &f.bindings[0];
                let handle = unsafe { f.runtime() }.wake_handle().unwrap();
                assert_eq!(
                    handle.sequence(),
                    binding.handle.lock().unwrap().as_ref().unwrap().sequence()
                );
                assert_eq!(
                    unsafe { f.runtime() }.current_id().unwrap(),
                    handle.context_id()
                );
                binding.enter(0, 0x200);
                f.event(31);
                binding.exit();
            }
            #[test]
            fn final_check_commit_spurious_wakes_transactional_errors_and_reused_job_generation() {
                let (executor, f, dropped) = bound_setup();
                let r = executor.runtime();
                let p = Arc::as_ptr(&f) as *mut c_void;
                unsafe { r.call_foreground(races_and_refusals, p, 10000) }.unwrap();
                let old = f.bindings[0]
                    .handle
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .clone();
                assert_eq!(old.wake(), Err(WorkError::Closed));
                assert_eq!(old.renew_current().err(), Some(WorkError::Unavailable));
                unsafe { r.call_foreground(reused_worker, p, 10000) }.unwrap();
                assert_eq!(old.wake(), Err(WorkError::Closed));
                assert_ne!(
                    old.sequence(),
                    f.bindings[0]
                        .handle
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .sequence()
                );
                assert_eq!(f.bindings[0].completed.load(Ordering::Acquire), 2);
                assert_eq!(f.bindings[0].arrives.load(Ordering::Acquire), 2);
                f.detach_all();
                unsafe { r.retire() }.unwrap();
                drop(executor);
                assert_eq!(dropped.load(Ordering::Acquire), 4);
                drop(old);
            }
            #[test]
            fn abandoned_blocked_executor_retains_actual_stacks_and_rejects_late_wake() {
                let (executor, f, dropped) = bound_setup();
                let r = executor.runtime();
                assert_eq!(
                    unsafe {
                        r.call_foreground(
                            park_until_cancelled,
                            Arc::as_ptr(&f) as *mut c_void,
                            10000,
                        )
                    },
                    Err(WorkError::Pending)
                );
                let handle = f.bindings[0]
                    .handle
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .clone();
                let weak = Arc::downgrade(&f);
                drop(executor);
                drop(f);
                assert_eq!(dropped.load(Ordering::Acquire), 0);
                assert!(weak.upgrade().is_some());
                assert_eq!(handle.wake(), Err(WorkError::Closed));
                drop(handle);
            }
            // Saturated-lane drain regressions use genuine retained stacks,
            // the existing binding model and admitted immutable wake handles.
            mod saturated_drain {
                use super::*;

                unsafe fn sleeper(p: *mut c_void, index: usize) {
                    let f = unsafe { bound(p) };
                    f.bind(index);
                    let binding = &f.bindings[index];
                    binding.enter(1, 0x200);
                    binding.blocked.store(true, Ordering::Release);
                    binding.prepared.store(true, Ordering::Release);
                    f.event(80 + index as u64);
                    assert_eq!(
                        unsafe { f.runtime() }.park_if_blocked(),
                        Ok(ParkOutcome::Resumed)
                    );
                    f.event(82 + index as u64);
                    binding.exit();
                }
                unsafe extern "C" fn first(p: *mut c_void) {
                    unsafe { sleeper(p, 0) };
                }
                unsafe extern "C" fn second(p: *mut c_void) {
                    unsafe { sleeper(p, 1) };
                }
                unsafe extern "C" fn queued(p: *mut c_void) {
                    let f = unsafe { bound(p) };
                    // The same-lane callback starts only after a real wake
                    // releases a retained continuation for its next job.
                    f.event(84);
                    f.data.fetch_add(1, Ordering::Release);
                }
                unsafe extern "C" fn general_origin(p: *mut c_void) {
                    let f = unsafe { bound(p) };
                    let runtime = unsafe { f.runtime() };
                    let origin = runtime.current_context().unwrap();
                    unsafe { runtime.queue().execute(Kind::General, first, p) }.unwrap();
                    unsafe { runtime.queue().execute(Kind::General, second, p) }.unwrap();
                    unsafe { runtime.queue().execute(Kind::General, queued, p) }.unwrap();
                    // Both actual General stacks park. The third General job
                    // remains queued, while the Idle Notify stack is ineligible.
                    assert_eq!(runtime.drain(10000), Err(WorkError::Pending));
                    assert_eq!(f.data.load(Ordering::Acquire), 0);
                    assert_eq!(
                        f.events
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|e| e.0)
                            .collect::<Vec<_>>(),
                        [80, 81]
                    );
                    assert_eq!(
                        runtime.current_context().unwrap().context_id,
                        origin.context_id
                    );
                    f.bindings[0].wake();
                    // One actual wake releases one General stack. The queued
                    // callback completes; the second sleeper still needs wake.
                    assert_eq!(runtime.drain(10000), Err(WorkError::Pending));
                    assert_eq!(f.data.load(Ordering::Acquire), 1);
                    assert_eq!(
                        f.events
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|e| e.0)
                            .collect::<Vec<_>>(),
                        [80, 81, 82, 84]
                    );
                    f.bindings[1].wake();
                    runtime.drain(10000).unwrap();
                    assert_eq!(
                        runtime.current_context().unwrap().context_id,
                        origin.context_id
                    );
                }
                unsafe extern "C" fn notify_origin(p: *mut c_void) {
                    let f = unsafe { bound(p) };
                    let runtime = unsafe { f.runtime() };
                    let origin = runtime.current_context().unwrap();
                    unsafe { runtime.queue().execute(Kind::Notify, first, p) }.unwrap();
                    unsafe { runtime.queue().execute(Kind::Notify, queued, p) }.unwrap();
                    // The serial Notify continuation parks. Both Idle General
                    // stacks are real, but cannot execute the queued Notify job.
                    assert_eq!(runtime.drain(10000), Err(WorkError::Pending));
                    assert_eq!(f.data.load(Ordering::Acquire), 0);
                    assert_eq!(
                        f.events
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|e| e.0)
                            .collect::<Vec<_>>(),
                        [80]
                    );
                    f.bindings[0].wake();
                    runtime.drain(10000).unwrap();
                    assert_eq!(f.data.load(Ordering::Acquire), 1);
                    assert_eq!(
                        f.events
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|e| e.0)
                            .collect::<Vec<_>>(),
                        [80, 82, 84]
                    );
                    assert_eq!(
                        runtime.current_context().unwrap().context_id,
                        origin.context_id
                    );
                }
                fn run(origin: Callback, expected: &[u64]) {
                    let (executor, f, dropped) = bound_setup();
                    let runtime = executor.runtime();
                    unsafe {
                        runtime.call_foreground(origin, Arc::as_ptr(&f) as *mut c_void, 10000)
                    }
                    .unwrap();
                    assert_eq!(
                        f.events
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|e| e.0)
                            .collect::<Vec<_>>(),
                        expected
                    );
                    assert_eq!(f.cpu.flags.load(Ordering::Acquire), 0x202);
                    f.detach_all();
                    unsafe { runtime.retire() }.unwrap();
                    drop(executor);
                    assert_eq!(dropped.load(Ordering::Acquire), 4);
                }
                #[test]
                fn queued_general_behind_all_blocked_general_stacks_returns_pending_until_wake() {
                    run(general_origin, &[80, 81, 82, 84, 83]);
                }
                #[test]
                fn queued_notify_behind_blocked_notify_stack_returns_pending_until_wake() {
                    run(notify_origin, &[80, 82, 84]);
                }
            }
        }
    }
}
