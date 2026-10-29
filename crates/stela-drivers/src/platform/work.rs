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
use crate::bus::dma::memory::{MemoryError, PinnedPages};
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
#[cfg(target_arch = "x86_64")]
pub mod scheduling;
#[cfg(target_arch = "x86_64")]
pub mod service;

#[cfg(target_arch = "x86_64")]
mod general_reservation;
mod reservation;
mod stack_requirement;
#[cfg(target_arch = "x86_64")]
pub use general_reservation::{
    AssignedGeneral, ColdStackPreparation, EnteredProcess, GeneralReservation, OwnedGeneralEscrow,
    PinnedColdStackPreparation, StackPinError,
};
pub use stack_requirement::{StackProfile, StackRequirement};
#[cfg(all(test, unix, target_arch = "x86_64"))]
pub(crate) mod test_support;
use reservation::Layout;
pub use reservation::{FirmwareQueue, FirmwareRole, GpeQueueBudget, ReservationPolicy};

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
    Service,
    Firmware,
    Portal,
    Gpe,
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

    /// Export a real allocation/mapping pin from this backing's resource owner.
    /// The caller independently checks exact usable coverage/cache/granules;
    /// an incompatible actual view is refused, never treated as stack access.
    /// Metadata setup is fallible and nonblocking, without queue reentry, root
    /// changes, migration or parking. No replacement RAM or PA/VA labels may
    /// stand in for the real retained allocation and mapping owner.
    ///
    /// # Safety
    /// The caller exclusively owns genuinely never-entered, fully zeroed usable
    /// backing, with no live frame/DMA/other byte user. Every successful pin
    /// satisfies PageBacking's real ownership contract, including initial zero
    /// and mapping retention. No C stack/address/current permission follows.
    unsafe fn pin_cold_pages(&self) -> Result<PinnedPages, MemoryError> {
        Err(MemoryError::Unavailable)
    }
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
    requirement: Option<StackRequirement>,
}
struct State<const N: usize> {
    jobs: [Option<Job>; N],
    reservations: [u64; N],
    #[cfg(target_arch = "x86_64")]
    next_reservation: u64,
    layout: Layout,
    stack_profile: Option<StackProfile>,
    stack_catalog: stack_requirement::Catalog,
    next: u64,
    closed: bool,
    poisoned: bool,
    #[cfg(target_arch = "x86_64")]
    scheduling: scheduling::Board,
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
    inspection: AtomicBool,
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
                reservations: [0; N],
                #[cfg(target_arch = "x86_64")]
                next_reservation: 1,
                layout: Layout::Ordinary,
                stack_profile: None,
                stack_catalog: stack_requirement::Catalog::empty(),
                next: 1,
                closed: false,
                poisoned: false,
                #[cfg(target_arch = "x86_64")]
                scheduling: scheduling::Board::new(),
            })),
            held: AtomicBool::new(false),
            inspection: AtomicBool::new(false),
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
        self.enqueue_requirement(lane, callback, context, None)
    }
    fn enqueue_requirement(
        &self,
        lane: Lane,
        callback: Callback,
        context: *mut c_void,
        requested: Option<StackRequirement>,
    ) -> Result<Ticket, WorkError> {
        let mut guard = self.lock()?;
        let state = guard.state();
        if state.closed || state.poisoned || self.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        let requirement = match (state.stack_profile, requested) {
            (None, Some(_)) => return Err(WorkError::Unavailable),
            (None, None) => None,
            (Some(profile), requested) => {
                let requirement = requested.unwrap_or_else(|| profile.default_for(lane));
                if !state.stack_catalog.supports(lane, requirement) {
                    return Err(WorkError::Unavailable);
                }
                Some(requirement)
            }
        };
        let ranges = state.layout.admission(lane, N)?;
        let slot = ranges
            .into_iter()
            .flatten()
            .find(|index| state.jobs[*index].is_none() && state.reservations[*index] == 0)
            .ok_or(WorkError::Full)?;
        let sequence = state.next;
        state.next = sequence.checked_add(1).ok_or(WorkError::Exhausted)?;
        state.jobs[slot] = Some(Job {
            callback,
            context: context as usize,
            lane,
            sequence,
            running: false,
            requirement,
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
    /// Queue General work with explicit geometry in an actual mixed-stack profile.
    /// This does not reserve an idle worker or implement thread creation.
    ///
    /// # Safety
    /// As for execute: callback/code/context remain retained through genuine
    /// completion or quarantine, and the body fits its requested usable extent.
    /// Rejection transfers nothing; a descriptor is no native/current authority.
    pub unsafe fn execute_general_with_requirement(
        &self,
        requirement: StackRequirement,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<Ticket, WorkError> {
        self.enqueue_requirement(Lane::General, callback, context, Some(requirement))
    }
    /// Claim one of the named policy's two actual portal continuations before
    /// accepting the callback/context. Full means neither idle worker is free;
    /// no request is hidden behind two blocked ordinary AML evaluations.
    ///
    /// # Safety
    /// The actual provider/request retains callback, context and every reachable
    /// owner until genuine completion or quarantine, as for [`Self::execute`].
    /// Rejection transfers nothing. This supplies no ACPICA or native entry grant.
    pub unsafe fn execute_portal(
        &self,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<Ticket, WorkError> {
        self.enqueue_lane(Lane::Portal, callback, context)
    }
    /// Admit serial GPE work into its independent reserved lane. Spare ordinary
    /// admission slots may hold pending GPE jobs; ordinary stacks never run them.
    ///
    /// # Safety
    /// The actual provider retains the callback/context through completion or
    /// quarantine. On error it still owns them and no callback was admitted.
    pub unsafe fn execute_gpe(
        &self,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<Ticket, WorkError> {
        self.enqueue_lane(Lane::Gpe, callback, context)
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
    fn next(
        &self,
        lane: Lane,
        geometry: stack_requirement::Geometry,
    ) -> Result<Option<(usize, Job)>, WorkError> {
        let mut g = self.lock()?;
        let state = g.state();
        if state.poisoned || self.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        let next = state
            .jobs
            .iter()
            .enumerate()
            .filter_map(|(i, j)| {
                j.filter(|j| {
                    state.reservations[i] == 0
                        && j.lane == lane
                        && !j.running
                        && stack_requirement::compatible(j.requirement, geometry)
                })
                .map(|j| (i, j))
            })
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
        if state.reservations.get(slot).is_none_or(|nonce| *nonce != 0) {
            return Err(WorkError::CorruptContext);
        }
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
    /// External IRQ/driver/firmware/work producers have stopped and cannot
    /// concurrently enqueue or resume an executor. Retain the actual owner,
    /// CPU/process authority and backing through genuine Runtime retirement.
    /// Retained jobs, active/suspended callbacks and reservation markers are
    /// checked refusal conditions: Pending/Closed does not retire or release
    /// them. Mere close is not producer synchronization, and queue retirement
    /// alone is not a task-stack or terminal C lifecycle proof.
    pub unsafe fn retire(&self) -> Result<(), WorkError> {
        self.process()?;
        let mut g = self.lock()?;
        let state = g.state();
        #[cfg(target_arch = "x86_64")]
        if !state.scheduling.quiet() {
            return Err(WorkError::Pending);
        }
        if !state.closed
            || state.poisoned
            || self.abandoned.load(Ordering::Acquire)
            || state.jobs.iter().any(Option::is_some)
            || state.reservations.iter().any(|nonce| *nonce != 0)
        {
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
    Reschedule = 2,
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
    service: bool,
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
    pub(crate) fn closed(&self) -> Result<bool, WorkError> {
        self.queue.process()?;
        Ok(self.queue.retired.load(Ordering::Acquire)
            || self.queue.abandoned.load(Ordering::Acquire)
            || self.signal.sequence.load(Ordering::Acquire) != self.sequence)
    }
    /// Immutable actual constructor role, not a live task or entry grant.
    #[cfg(feature = "linux-kernel")]
    pub(crate) fn service_reserved(&self) -> Result<bool, WorkError> {
        self.queue.process()?;
        Ok(self.signal.service)
    }
    /// Qualified same-CPU process/IRQ admission only; never resume inline or
    /// change the foreign condition. Close permits wakes for admitted jobs.
    /// Release/acquire pending plus final IF exclusion covers wake at park.
    /// Qualify process-context owner release on this retained queue's actual
    /// CPU, including after job close. This grants no current task/RSP, live
    /// sequence, Linux entry or native producer authority and signals nothing.
    #[cfg(feature = "linux-kernel")]
    pub(crate) fn check_process(&self) -> Result<(), WorkError> {
        self.queue.process()
    }
    pub fn wake(&self) -> Result<(), WorkError> {
        let mut guard = self.queue.lock()?;
        if guard.state().poisoned
            || self.queue.retired.load(Ordering::Acquire)
            || self.queue.abandoned.load(Ordering::Acquire)
            || self.signal.sequence.load(Ordering::Acquire) != self.sequence
        {
            return Err(WorkError::Closed);
        }
        // Real blocked->ready ordering is committed before wake publication;
        // duplicate/running wakes preserve equal-FIFO order. No C/task pointer.
        guard.state().scheduling.wake(self.id, self.sequence)?;
        self.queue.inspection.store(true, Ordering::Release);
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
    Reserved,
    Escrow,
    Preparing,
    Ready,
    Running,
    Runnable,
    Blocked,
}
#[cfg(target_arch = "x86_64")]
struct Task {
    lane: Lane,
    stack: Stack,
    id: ContextId,
    frame: context::Frame,
    state: TaskState,
    job: Option<(usize, Job)>,
    flags: u64,
    draining: bool,
    owned_escrows: usize,
    ever_entered: bool,
    binding: Option<Arc<dyn SwitchBinding>>,
    signal: Arc<WakeSignal>,
}
pub(crate) const MAX_CONTINUATIONS: usize = 32;

/// CPU-affine pinned executor. Task zero is a real foreground continuation,
/// task one is serial Notify; an optional Linux service reserves task two and
/// firmware reserves task three. Remaining stacks run general work. The dispatcher
/// itself has no fabricated thread ID. All switching happens with IF=0.
#[cfg(target_arch = "x86_64")]
pub struct Runtime<const N: usize> {
    queue: Arc<Queue<N>>,
    layout: Layout,
    tasks: ManuallyDrop<UnsafeCell<Vec<Task>>>,
    dispatch: UnsafeCell<context::Frame>,
    current: Cell<usize>,
    cursor: Cell<usize>,
    retired: Cell<bool>,
    pending_reservations: Cell<usize>,
    owned_escrows: Cell<usize>,
    service_started: Cell<bool>,
    firmware_started: Cell<bool>,
    firmware_turn: Cell<bool>,
    firmware_cursor: Cell<usize>,
    service_domain: ManuallyDrop<UnsafeCell<Option<Arc<service::Domain<N>>>>>,
    _local: PhantomData<*mut ()>,
    _pinned: PhantomPinned,
}
#[cfg(target_arch = "x86_64")]
impl<const N: usize> Runtime<N> {
    fn validate_stacks(queue: &Queue<N>, stacks: &[Stack]) -> Result<(), WorkError> {
        Self::validate_stack_limit(queue, stacks, 16)
    }
    fn validate_stack_limit(
        queue: &Queue<N>,
        stacks: &[Stack],
        limit: usize,
    ) -> Result<(), WorkError> {
        queue.process()?;
        if stacks.len() < 4 || stacks.len() > limit {
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
        Self::with_service_controls(queue, stacks, controls, false)
    }
    fn with_service_controls(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
        controls: context::Controls,
        reserve_service: bool,
    ) -> Result<Pin<Box<Self>>, WorkError> {
        Self::with_reserved_controls(queue, stacks, controls, reserve_service, false)
    }
    fn with_reserved_controls(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
        controls: context::Controls,
        reserve_service: bool,
        reserve_firmware: bool,
    ) -> Result<Pin<Box<Self>>, WorkError> {
        let layout = match (reserve_service, reserve_firmware) {
            (false, false) => Layout::Ordinary,
            (true, false) => Layout::LinuxService,
            (true, true) => Layout::FirmwareControl,
            (false, true) => return Err(WorkError::Unavailable),
        };
        Self::with_layout_controls(queue, stacks, controls, layout)
    }
    fn with_layout_controls(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
        controls: context::Controls,
        layout: Layout,
    ) -> Result<Pin<Box<Self>>, WorkError> {
        Self::with_profile_controls(queue, stacks, controls, layout, None)
    }
    fn with_profile_controls(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
        controls: context::Controls,
        layout: Layout,
        profile: Option<StackProfile>,
    ) -> Result<Pin<Box<Self>>, WorkError> {
        layout.validate(stacks.len(), N)?;
        let catalog = match profile {
            Some(profile) => stack_requirement::Catalog::from_actual(&stacks, profile, layout)?,
            None => stack_requirement::Catalog::empty(),
        };
        let mut tasks = Vec::new();
        tasks
            .try_reserve_exact(stacks.len())
            .map_err(|_| WorkError::Full)?;
        for (index, stack) in stacks.into_iter().enumerate() {
            let id = NEXT_CONTEXT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| WorkError::Exhausted)?;
            tasks.push(Task {
                lane: layout.lane(index),
                stack,
                id: ContextId(id),
                frame: context::Frame::new(controls),
                state: TaskState::Idle,
                job: None,
                flags: 0,
                draining: false,
                owned_escrows: 0,
                ever_entered: false,
                binding: None,
                signal: Arc::new(WakeSignal {
                    service: layout.lane(index) == Lane::Service,
                    sequence: AtomicU64::new(0),
                    pending: AtomicBool::new(false),
                }),
            });
        }
        {
            let mut admission = queue.lock()?;
            let state = admission.state();
            // Native worker permits require an empty pre-admission queue: a
            // legacy Notify job in an ordinary slot otherwise bypasses the two
            // real-worker limit. Legacy constructors keep their prior contract.
            if state.reservations.iter().any(|nonce| *nonce != 0)
                || (layout.firmware_roles() && state.jobs.iter().any(Option::is_some))
                || state.jobs[N - layout.slots()..].iter().any(Option::is_some)
            {
                return Err(WorkError::Busy);
            }
            if queue
                .executor_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(WorkError::Busy);
            }
            // The real constructor atomically reserves its actual admission slots.
            // Existing queued jobs are never moved, discarded or reinterpreted.
            state.layout = layout;
            state.stack_profile = profile;
            state.stack_catalog = catalog;
        }
        let executor = Box::pin(Self {
            queue,
            layout,
            tasks: ManuallyDrop::new(UnsafeCell::new(tasks)),
            dispatch: UnsafeCell::new(context::Frame::new(controls)),
            current: Cell::new(NONE),
            cursor: Cell::new(0),
            retired: Cell::new(false),
            pending_reservations: Cell::new(0),
            owned_escrows: Cell::new(0),
            service_started: Cell::new(false),
            firmware_started: Cell::new(false),
            firmware_turn: Cell::new(true),
            firmware_cursor: Cell::new(0),
            service_domain: ManuallyDrop::new(UnsafeCell::new(None)),
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
    fn domain(&self) -> Option<&Arc<service::Domain<N>>> {
        // SAFETY: same-CPU access; one setup publication precedes all jobs.
        unsafe { (&*self.service_domain.get()).as_ref() }
    }
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
        // SAFETY: immutable actual constructor role, on qualified dispatcher.
        if unsafe { (*self.task(2)).lane } != Lane::Service {
            return Err(WorkError::Unavailable);
        }
        // Enabling a sidecar cannot reinterpret already suspended task frames.
        // Queued, unassigned jobs are fine: they enter NORMAL on actual assign.
        // SAFETY: qualified taskless dispatcher owns the retained task vector;
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
        scheduling.state().scheduling.enabled = true;
        drop(scheduling);
        // SAFETY: first publication before jobs; no callback/drop/borrow crosses it.
        unsafe { *self.service_domain.get() = Some(domain) };
        Ok(())
    }
    /// Start the optional reserved service once, on its actual distinct stack.
    /// The ordinary General/Notify queue cannot submit into this private lane.
    ///
    /// # Safety
    /// The queue's retained owner covers callback/code/context through genuine
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
        // belongs to this qualified dispatcher and is never caller role bits.
        if unsafe { (*self.task(2)).lane } != Lane::Service {
            return Err(WorkError::Unavailable);
        }
        let ticket = self.queue.enqueue_lane(Lane::Service, callback, context)?;
        self.service_started.set(true);
        Ok(ticket)
    }
    /// Start the independently reserved firmware continuation once. Its lane
    /// cannot be consumed by General/Notify work or the Linux service domain.
    /// Reservation supplies no AML, SCI, hardware or Linux entry authority.
    ///
    /// # Safety
    /// The retained owner covers callback/code/context until genuine stop,
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
        // SAFETY: all runtimes retain at least four tasks. The qualified taskless
        // dispatcher reads immutable constructor metadata without invoking work.
        if unsafe { (*self.task(3)).lane } != Lane::Firmware {
            return Err(WorkError::Unavailable);
        }
        let ticket = self.queue.enqueue_lane(Lane::Firmware, callback, context)?;
        self.firmware_started.set(true);
        Ok(ticket)
    }
    /// Check actual CPU/current/RSP before identifying the firmware continuation.
    pub fn firmware_current(&self) -> Result<bool, WorkError> {
        self.current_id()?;
        // SAFETY: current_id validated the current index, state and retained stack.
        Ok(unsafe { (*self.task(self.current.get())).lane } == Lane::Firmware)
    }
    /// Actual constructor role after validating CPU, current job and real RSP.
    /// The tag is observation, never an execution or native service capability.
    pub fn firmware_role_current(&self) -> Result<Option<FirmwareRole>, WorkError> {
        self.current_id()?;
        // SAFETY: current_id validated the current index/state/retained stack.
        Ok(self
            .layout
            .role(unsafe { (*self.task(self.current.get())).lane }))
    }
    /// Check actual CPU/current/RSP before identifying the reserved service.
    pub fn service_current(&self) -> Result<bool, WorkError> {
        self.current_id()?;
        // SAFETY: current_id validated the actual retained continuation.
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
    /// Capture scheduling authority for this actual job in the optional domain.
    /// The handle retains only immutable queue/signal/generation metadata.
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
    /// Involuntary cooperative boundary, distinct from explicit yield-to-tail.
    /// Default round-robin stays unchanged; future FIFO ordering consumes this
    /// distinct reason instead of treating it as an explicit yield.
    pub fn reschedule(self: Pin<&Self>) -> Result<(), WorkError> {
        self.suspend(LeaveReason::Reschedule).map(|_| ())
    }
    /// Actual process/current check precedes retained clock/provider entry.
    pub fn reschedule_requested(self: Pin<&Self>) -> Result<bool, WorkError> {
        self.current_id()?;
        let Some(domain) = self.domain() else {
            return Ok(false);
        };
        if self.service_current()? {
            return Ok(false);
        }
        // Capture before inspection. A later wake must survive this query.
        let requested = self.queue.inspection.swap(false, Ordering::AcqRel);
        Ok(domain.inspect_and_wake()? || requested)
    }
    /// Suspend once only if the retained foreign predicate is still blocked.
    /// Linux-owned process PREPARE must precede this call. Skipped/error leaves
    /// its original entered lease intact; its wrapper clears prepared state.
    pub fn park_if_blocked(self: Pin<&Self>) -> Result<ParkOutcome, WorkError> {
        self.suspend(LeaveReason::Blocked)
    }
    fn suspend(self: Pin<&Self>, reason: LeaveReason) -> Result<ParkOutcome, WorkError> {
        self.current_id()?;
        if self.pending_reservations.get() != 0 {
            return Err(WorkError::Busy);
        }
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
                // Pure bounded preflight before foreign leave commits. Native
                // IRQ delivery is excluded; exhaustion after a hook's explicit
                // generic peer wake remains a terminal transition failure.
                self.queue.lock()?.state().scheduling.can_suspend(
                    ContextId(view.context_id),
                    view.sequence,
                    reason,
                )?;
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
        // Foreign departure committed. A failed sidecar commit is terminal;
        // it cannot return through a now-suspended foreign owner/lease.
        let transition = (|| {
            self.queue.lock()?.state().scheduling.suspend(
                ContextId(view.context_id),
                view.sequence,
                reason,
            )
        })();
        if let Err(error) = transition {
            self.queue.cpu.fatal(error);
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
    /// # Safety
    /// Qualified taskless dispatcher at IF0; all retained task frames are stopped.
    unsafe fn next_firmware(&self, count: usize) -> Option<usize> {
        for offset in 0..count {
            let index = (self.firmware_cursor.get() + offset) % count;
            // SAFETY: bounded immutable task vector, stopped under dispatcher IF0.
            let task = unsafe { &*self.task(index) };
            if self.layout.role(task.lane).is_none()
                || !matches!(task.state, TaskState::Ready | TaskState::Runnable)
            {
                continue;
            }
            if task.state == TaskState::Ready && matches!(task.lane, Lane::Notify | Lane::Portal) {
                let sequence = match task.job {
                    Some((_, job)) => job.sequence,
                    None => self.queue.cpu.fatal(WorkError::CorruptContext),
                };
                let earlier = (0..count).any(|peer| {
                    // SAFETY: same stopped task vector; this read cannot switch or invoke work.
                    let other = unsafe { &*self.task(peer) };
                    other.lane == task.lane
                        && other.state == TaskState::Ready
                        && other.job.is_some_and(|(_, job)| job.sequence < sequence)
                });
                if earlier {
                    continue;
                }
            }
            return Some(index);
        }
        None
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
        let due_service = if let Some(domain) = self.domain() {
            if !self.service_started.get() {
                return Err(WorkError::Unavailable);
            }
            match domain.inspect_and_wake() {
                Ok(due) => due,
                Err(error) => self.queue.cpu.fatal(error),
            }
        } else {
            false
        };
        let flags = self.queue.cpu.save_disable()?;
        // SAFETY: the task list's length never changes after construction.
        let count = unsafe { (*self.tasks.get()).len() };
        let mut selected = None;
        let has_firmware = self.layout.role(Lane::Firmware).is_some();
        for n in 0..count {
            let i = (if due_service { 2 } else { self.cursor.get() } + n) % count;
            // SAFETY: no task runs while the dispatcher steps, so this is the only
            // reference to task `i`.
            let task = unsafe { &mut (*self.task(i)) };
            if task.state == TaskState::Idle {
                match self
                    .queue
                    .next(task.lane, stack_requirement::Geometry::of(&task.stack))
                {
                    Ok(Some(job)) => {
                        let inserted = (|| {
                            self.queue.lock()?.state().scheduling.insert(
                                task.id,
                                job.1.sequence,
                                task.lane == Lane::Service,
                            )
                        })();
                        if let Err(error) = inserted {
                            self.queue.cpu.fatal(error);
                        }
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
                // A valid generic wake can be posted by a leave hook after
                // the final pending check but before actual block commit.
                // Earlier IRQ publication already moved the row; duplicate
                // wake preserves its original ready order.
                let ready = (|| {
                    self.queue.lock()?.state().scheduling.wake(
                        task.id,
                        task.job.ok_or(WorkError::CorruptContext)?.1.sequence,
                    )
                })();
                if let Err(error) = ready {
                    self.queue.cpu.fatal(error);
                }
                task.state = TaskState::Runnable;
            }
            if matches!(task.state, TaskState::Ready | TaskState::Runnable) {
                if self.layout.role(task.lane).is_some() {
                    continue;
                }
                if self.domain().is_none() {
                    if selected.is_none() {
                        selected = Some(i);
                    }
                    if !has_firmware {
                        break; // Preserve the legacy Runtime's exact RR behavior.
                    }
                    continue;
                }
                let precedes = if due_service && i == 2 {
                    true
                } else if due_service && selected == Some(2) {
                    false
                } else if let Some(prior) = selected {
                    // SAFETY: dispatcher IF0, no task or callback is running.
                    let prior = unsafe { &*self.task(prior) };
                    let result = (|| {
                        self.queue.lock()?.state().scheduling.precedes(
                            (
                                task.id,
                                task.job.ok_or(WorkError::CorruptContext)?.1.sequence,
                            ),
                            (
                                prior.id,
                                prior.job.ok_or(WorkError::CorruptContext)?.1.sequence,
                            ),
                        )
                    })();
                    match result {
                        Ok(value) => value,
                        Err(error) => self.queue.cpu.fatal(error),
                    }
                } else {
                    true
                };
                if precedes {
                    selected = Some(i);
                }
            }
        }
        // SAFETY: the qualified dispatcher still holds actual IF0; all task
        // frames are stopped and no mutable task borrow survives the scan.
        let firmware = unsafe { self.next_firmware(count) };
        // Firmware is outside Linux FIFO ranks. At most one firmware turn
        // separates eligible non-firmware turns; an idle peer set permits it to
        // continue. Due Linux deadline/IRQ work retains its existing precedence.
        if let Some(index) = firmware
            && !(due_service && selected == Some(2))
            && (self.firmware_turn.get() || selected.is_none())
        {
            selected = Some(index);
        }
        let Some(i) = selected else {
            // SAFETY: `flags` came from the save_disable above, and no lock is held.
            unsafe { self.queue.cpu.restore(flags) };
            return Ok(false);
        };
        if !(due_service && i == 2) {
            self.firmware_turn.set(Some(i) != firmware);
            if Some(i) == firmware {
                self.firmware_cursor.set((i + 1) % count);
            }
            self.cursor.set((i + 1) % count);
        }
        // SAFETY: immutable selected actual job at IF0; no borrow spans switch.
        let task = unsafe { &*self.task(i) };
        let running = (|| {
            self.queue.lock()?.state().scheduling.running(
                task.id,
                task.job.ok_or(WorkError::CorruptContext)?.1.sequence,
            )
        })();
        if let Err(error) = running {
            self.queue.cpu.fatal(error);
        }
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
    /// One real dispatch, or one owned idle/event wait followed by dispatch.
    /// Due inspection only wakes; all service callbacks run on its real stack.
    pub fn step_or_idle(self: Pin<&Self>) -> Result<bool, WorkError> {
        if self.step()? {
            return Ok(true);
        }
        let Some(domain) = self.domain() else {
            return Ok(false);
        };
        if let Err(error) = domain.idle() {
            self.queue.cpu.fatal(error);
        }
        self.step()
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
    /// # Safety
    /// The qualified dispatcher/current task owns this Runtime, the queue lock
    /// holds IF0, all peers are suspended, and no task borrow spans this call.
    unsafe fn peer_progress(&self, current: usize, state: &State<N>) -> bool {
        if current == NONE {
            return true;
        }
        let lane_index = |lane| match lane {
            Lane::Foreground => 0,
            Lane::Notify => 1,
            Lane::General => 2,
            Lane::Service => 3,
            Lane::Firmware => 4,
            Lane::Portal => 5,
            Lane::Gpe => 6,
        };
        let mut queued_lanes = [false; 7];
        for job in state.jobs.iter().flatten().filter(|job| !job.running) {
            queued_lanes[lane_index(job.lane)] = true;
        }
        // SAFETY: caller holds the actual same-CPU IF0 queue guard and all peer
        // frames are stopped. This read neither switches nor retains references.
        unsafe {
            (&*self.tasks.get()).iter().enumerate().any(|(i, task)| {
                i != current
                    && match task.state {
                        TaskState::Ready | TaskState::Runnable => true,
                        TaskState::Blocked => task.signal.pending.load(Ordering::Acquire),
                        TaskState::Idle => queued_lanes[lane_index(task.lane)],
                        TaskState::Running
                        | TaskState::Reserved
                        | TaskState::Escrow
                        | TaskState::Preparing => false,
                    }
            })
        }
    }
    /// Observe the actual constructor's protected GPE admission budget.
    /// None means the legacy layout has no protected pending guarantee. This
    /// copy neither synchronizes IRQs nor grants provider/progress authority.
    pub fn protected_gpe_budget(&self) -> Result<Option<GpeQueueBudget>, WorkError> {
        self.queue.process()?;
        if self.retired.get() || self.queue.abandoned.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        Ok(self.layout.protected_gpe())
    }
    /// Check actual CPU/policy/lifetime/current-role eligibility for a firmware
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
            // SAFETY: actual current frame was checked; its immutable lane is
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
    /// retain every admitted callback/context. Only NativeFirmware16 has these
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
                // SAFETY: qualified same-CPU queue guard holds IF0; no task
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
    /// concurrently enqueue, resume or mutate this executor. Actual owner,
    /// CPU/process authority and stack backing remain valid throughout the call.
    /// Current/suspended callbacks, reservations, escrows and bindings are checked
    /// before retirement; Pending/Closed retains them. Timeout/failed drain is
    /// not retirement authority. Idle dispatcher continuation frames do not
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
#[cfg(target_arch = "x86_64")]
unsafe extern "sysv64" fn entry<const N: usize>(pointer: usize, index: usize) -> ! {
    // SAFETY: covered by this function's own safety contract.
    let executor = unsafe { &*(pointer as *const Runtime<N>) };
    executor.valid();
    // SAFETY: the actual constructed trampoline just entered this retained
    // worker at IF0. The monotonic history changes only here, before hooks or
    // callbacks; an idle suspended entry frame can never masquerade as cold.
    unsafe { (*executor.task(index)).ever_entered = true };
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
        // SAFETY: this actual completing frame owns its immutable task index;
        // only its entered creator can alter the per-job escrow count. Peer
        // callbacks may complete while another creator retains an owned escrow.
        let owned_escrows = unsafe { (*executor.task(index)).owned_escrows };
        if executor.pending_reservations.get() != 0 || owned_escrows != 0 {
            executor.queue.abandoned.store(true, Ordering::Release);
            quarantine();
            executor.queue.cpu.fatal(WorkError::Pending);
        }
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
        let removed = (|| {
            executor
                .queue
                .lock()?
                .state()
                .scheduling
                .remove(ContextId(view.context_id), view.sequence)
        })();
        if let Err(error) = removed {
            executor.queue.cpu.fatal(error);
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
        if self.retired.get() && self.owned_escrows.get() == 0 {
            // SAFETY: retirement proved no task frame or stack is still live.
            unsafe { ManuallyDrop::drop(&mut self.tasks) };
            // SAFETY: successful retirement also required actual domain release.
            unsafe { ManuallyDrop::drop(&mut self.service_domain) };
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
    /// Reserve one actual service continuation in addition to Foreground,
    /// Notify and at least two General continuations. Start/bind the service
    /// explicitly before admitting dependent Linux operations.
    pub fn new_with_service(queue: Arc<Queue<N>>, stacks: Vec<Stack>) -> Result<Self, WorkError> {
        Runtime::<N>::validate_stacks(&queue, &stacks)?;
        if stacks.len() < 5 {
            return Err(WorkError::Unavailable);
        }
        // SAFETY: same qualified native construction boundary as new().
        let controls = unsafe { context::controls()? };
        Ok(Self {
            runtime: ManuallyDrop::new(Runtime::with_service_controls(
                queue, stacks, controls, true,
            )?),
        })
    }
    /// Reserve independent Linux and firmware continuations at indices two
    /// and three, alongside Foreground, Notify and at least two General tasks.
    /// Reserve two queue admission slots as well (N must be at least three).
    /// Preexisting jobs in either final slot reject construction with Busy;
    /// no queued work moves or disappears. Guarded stacks and CPU ownership
    /// are validated as in new(). Starting grants no foreign service capability.
    pub fn new_with_services(queue: Arc<Queue<N>>, stacks: Vec<Stack>) -> Result<Self, WorkError> {
        Runtime::<N>::validate_stacks(&queue, &stacks)?;
        if stacks.len() < 6 {
            return Err(WorkError::Unavailable);
        }
        // SAFETY: same qualified native construction boundary as new().
        let controls = unsafe { context::controls()? };
        Ok(Self {
            runtime: ManuallyDrop::new(Runtime::with_reserved_controls(
                queue, stacks, controls, true, true,
            )?),
        })
    }
    /// Apply a named bounded qualification/prototype reservation policy. The layout reserves
    /// real workers and admission slots; it supplies no native IRQ/AML/provider
    /// capability. The queue must be empty (Busy otherwise), so every admitted
    /// Portal/Notify job first claims an actual idle-worker permit. Existing
    /// constructors keep their original layouts/contracts.
    pub fn new_with_policy(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
        policy: ReservationPolicy,
    ) -> Result<Self, WorkError> {
        let layout = policy.layout();
        Runtime::<N>::validate_stack_limit(&queue, &stacks, layout.stack_limit())?;
        layout.validate(stacks.len(), N)?;
        // SAFETY: same qualified native construction boundary as new().
        let controls = unsafe { context::controls()? };
        Ok(Self {
            runtime: ManuallyDrop::new(Runtime::with_layout_controls(
                queue, stacks, controls, layout,
            )?),
        })
    }
    /// Opt into actual mixed stack geometry for the explicit32-stack prototype.
    /// Empty-queue validation is transactional. Descriptors supply no native
    /// mapping/current/kernel-thread/IRQ authority.
    pub fn new_with_profile(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
        policy: ReservationPolicy,
        profile: StackProfile,
    ) -> Result<Self, WorkError> {
        let layout = policy.layout();
        Runtime::<N>::validate_stack_limit(&queue, &stacks, layout.stack_limit())?;
        layout.validate(stacks.len(), N)?;
        // SAFETY: same qualified native construction boundary as new_with_policy.
        let controls = unsafe { context::controls()? };
        Ok(Self {
            runtime: ManuallyDrop::new(Runtime::with_profile_controls(
                queue,
                stacks,
                controls,
                layout,
                Some(profile),
            )?),
        })
    }
    #[cfg(all(test, unix))]
    pub(crate) fn new_hosted_profile_for_test(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
        policy: ReservationPolicy,
        profile: StackProfile,
    ) -> Result<Self, WorkError> {
        let layout = policy.layout();
        Runtime::<N>::validate_stack_limit(&queue, &stacks, layout.stack_limit())?;
        layout.validate(stacks.len(), N)?;
        // SAFETY: unprivileged control snapshot and genuine owned guarded mmap stacks only.
        let controls = unsafe { context::read_controls() };
        Ok(Self {
            runtime: ManuallyDrop::new(Runtime::with_profile_controls(
                queue,
                stacks,
                controls,
                layout,
                Some(profile),
            )?),
        })
    }
    /// Genuine hosted continuation mechanism test only. StackBacking must own
    /// real mapped guarded stacks; Cpu is an explicit hosted model. This never
    /// qualifies CPL0/IRQ/native roots or registers a native producer.
    #[cfg(all(test, unix))]
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
    #[cfg(all(test, feature = "linux-kernel"))]
    pub(crate) fn new_hosted_service_for_test(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
    ) -> Result<Self, WorkError> {
        Runtime::<N>::validate_stacks(&queue, &stacks)?;
        // SAFETY: actual hosted stack mechanism only, as new_hosted_for_test.
        let controls = unsafe { context::read_controls() };
        Ok(Self {
            runtime: ManuallyDrop::new(Runtime::with_service_controls(
                queue, stacks, controls, true,
            )?),
        })
    }
    #[cfg(all(test, unix))]
    pub(crate) fn new_hosted_policy_for_test(
        queue: Arc<Queue<N>>,
        stacks: Vec<Stack>,
        policy: ReservationPolicy,
    ) -> Result<Self, WorkError> {
        let layout = policy.layout();
        Runtime::<N>::validate_stack_limit(&queue, &stacks, layout.stack_limit())?;
        layout.validate(stacks.len(), N)?;
        // SAFETY: unprivileged real control snapshot for owned guarded hosted stacks only.
        let controls = unsafe { context::read_controls() };
        Ok(Self {
            runtime: ManuallyDrop::new(Runtime::with_layout_controls(
                queue, stacks, controls, layout,
            )?),
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
        if process && self.runtime.retired.get() && self.runtime.owned_escrows.get() == 0 {
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
mod tests;
