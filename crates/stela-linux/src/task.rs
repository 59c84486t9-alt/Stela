//! Linux task metadata on kept cooperative continuations.
//!
//! This binds original C task_struct/current and the entered service lease.
//! The normal/WW and original RT mutex adapters supply wake/signal/I/O effects.
//! NORMAL nice, FIFO and inherited ranks commit against retained job identities
//! on the same checked queue; native IRQ delivery remains the service's owner.
use alloc::sync::Arc;
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    mem::{ManuallyDrop, MaybeUninit},
    pin::Pin,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_driver_base::platform::work::scheduling::{BasePolicy, Snapshot};
use stela_driver_base::platform::work::{
    ContextId, LeaveReason, ParkOutcome, Runtime, SwitchBinding, TaskContext, WakeHandle, WorkError,
};

#[repr(C)]
struct Rank {
    policy: u32,
    realtime: u32,
    effective: i32,
    nice: i32,
}

impl Rank {
    fn snapshot(&self) -> Result<Snapshot, WorkError> {
        let base = match (self.policy, self.realtime) {
            (0, 0) if self.nice == 0 => BasePolicy::Normal,
            (0, 0) if (-20..=19).contains(&self.nice) => BasePolicy::NormalNice(self.nice as i8),
            (1, priority @ 1..=99) => BasePolicy::Fifo(priority as u8),
            _ => return Err(WorkError::Unavailable),
        };
        if !(-20..=19).contains(&self.nice) {
            return Err(WorkError::Unavailable);
        }
        Ok(Snapshot {
            base,
            effective: self
                .effective
                .try_into()
                .map_err(|_| WorkError::Unavailable)?,
        })
    }
}

#[repr(C)]
struct TaskOps {
    is_current: unsafe extern "C" fn(*mut c_void, *const TaskContext) -> bool,
    wake_target: unsafe extern "C" fn(*mut c_void, u64) -> i32,
    service_reserved: unsafe extern "C" fn(*mut c_void) -> bool,
    rank: unsafe extern "C" fn(*mut c_void, u64, *const Rank, *const Rank, bool) -> i32,
}
#[repr(C)]
struct ScopeOps {
    park: unsafe extern "C" fn(*mut c_void) -> i32,
    yield_now: unsafe extern "C" fn(*mut c_void) -> i32,
    reschedule: unsafe extern "C" fn(*mut c_void) -> i32,
    reschedule_requested: unsafe extern "C" fn(*mut c_void) -> bool,
}
#[repr(C)]
struct CTask {
    _opaque: [u8; 0],
}
unsafe extern "C" {
    fn stela_linux_task_catalog_capacity() -> u32;
    fn stela_linux_task_stack_bytes() -> usize;
    fn stela_linux_task_stack_alignment() -> usize;
    fn stela_linux_task_stack_guard() -> usize;
    fn stela_linux_task_allocate() -> *mut CTask;
    fn stela_linux_task_attach(
        task: *mut CTask,
        context: *const TaskContext,
        ops: *const TaskOps,
        binding: *mut c_void,
    ) -> i32;
    fn stela_linux_task_still_blocked(task: *mut CTask, context: *const TaskContext) -> i32;
    fn stela_linux_task_leave(task: *mut CTask, context: *const TaskContext, reason: u32) -> i32;
    fn stela_linux_task_arrive(task: *mut CTask, context: *const TaskContext, new_job: bool)
    -> i32;
    fn stela_linux_task_complete(task: *mut CTask, context: *const TaskContext) -> i32;
    fn stela_linux_task_detach(task: *mut CTask, context: *const TaskContext) -> i32;
    fn stela_linux_task_release(task: *mut CTask);
    fn stela_linux_task_scope_begin(
        task: *mut CTask,
        ops: *const ScopeOps,
        scope: *mut c_void,
    ) -> i32;
    fn stela_linux_task_scope_end(task: *mut CTask) -> i32;
    fn stela_linux_task_signal(task: *mut CTask, expected_sequence: u64, kind: u32) -> i32;
}

/// Geometry from the compiled Linux configuration, for resource planning.
/// It does not attest mappings, CPU/current permission or a native provider.
pub fn stack_requirement() -> Result<stela_driver_base::platform::work::StackRequirement, WorkError>
{
    // SAFETY: these three C functions return immutable compiled constants only;
    // they inspect no task, entered owner, mutable catalog or native pointer.
    let (bytes, alignment, guard) = unsafe {
        (
            stela_linux_task_stack_bytes(),
            stela_linux_task_stack_alignment(),
            stela_linux_task_stack_guard(),
        )
    };
    stela_driver_base::platform::work::StackRequirement::exact(bytes, alignment, guard)
}

static QUARANTINED: AtomicU64 = AtomicU64::new(0);

/// Metadata kept because its final release was not explicitly checked.
/// This counts no native/GPU validation and never reclaims uncertain tasks.
pub fn quarantined() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

/// Keeps the C task independently of a per-enter borrowed service owner.
/// The first immutable waker validates CPU/IRQ/RSP before C state access;
/// renew_current obtains the existing job ticket on stack reuse.
pub struct TaskBinding<const N: usize> {
    task: NonNull<CTask>,
    first: UnsafeCell<MaybeUninit<WakeHandle<N>>>,
    target: UnsafeCell<MaybeUninit<WakeHandle<N>>>,
    published: AtomicBool,
    detached: AtomicBool,
    released: bool,
}
// SAFETY: no foreign CPU mutates the C task or first waker. Runtime
// identity is checked before C entry; publication is single-writer release/
// acquire and the immutable waker is held until safe detach/release.
unsafe impl<const N: usize> Send for TaskBinding<N> {}
// SAFETY: same single checked CPU contract; IRQ wake views contain no C task.
unsafe impl<const N: usize> Sync for TaskBinding<N> {}

fn status(value: i32) -> Result<(), WorkError> {
    match value {
        0 => Ok(()),
        -16 => Err(WorkError::Busy),
        -28 => Err(WorkError::Full),
        _ => Err(WorkError::CorruptContext),
    }
}
impl<const N: usize> TaskBinding<N> {
    const OPS: TaskOps = TaskOps {
        is_current: Self::current,
        wake_target: Self::wake_target,
        service_reserved: Self::service_reserved,
        rank: Self::rank,
    };
    const SCOPE_OPS: ScopeOps = ScopeOps {
        park: Self::park,
        yield_now: Self::yield_now,
        reschedule: Self::reschedule,
        reschedule_requested: Self::reschedule_requested,
    };

    /// Allocate original task metadata before entering a Linux owner.
    ///
    /// # Safety
    /// Call in checked process context on the Runtime CPU, with the canonical
    /// heap initialized. Every binding using the common !SMP C archive must stay
    /// on that SAME checked physical CPU for its lifetime; keep all
    /// CPU/code/root permission separately. No native producer is established
    /// by this allocation. C metadata failure is fallible; Arc allocation uses
    /// the image's existing global allocation-error policy.
    pub unsafe fn new() -> Result<Arc<Self>, WorkError> {
        // SAFETY: immutable compiled C storage-ceiling observation, with no task/owner access.
        if unsafe { stela_linux_task_catalog_capacity() } as usize
            != stela_driver_base::platform::work::MAX_CONTINUATIONS
        {
            return Err(WorkError::Unavailable);
        }
        // SAFETY: caller supplies canonical heap/process permission.
        let task = NonNull::new(unsafe { stela_linux_task_allocate() }).ok_or(WorkError::Full)?;
        Ok(Arc::new(Self {
            task,
            first: UnsafeCell::new(MaybeUninit::uninit()),
            target: UnsafeCell::new(MaybeUninit::uninit()),
            published: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            released: false,
        }))
    }

    /// Attach only to this current continuation, before Linux entry.
    /// Initial waker publication completes before any original C task service.
    pub fn bind_current(self: &Arc<Self>, runtime: Pin<&Runtime<N>>) -> Result<(), WorkError> {
        if self.published.load(Ordering::Acquire) {
            return Err(WorkError::Busy);
        }
        let handle = runtime.bind_current(self.clone())?;
        // SAFETY: one successful Runtime attachment owns this same-CPU initial
        // publication. Runtime keeps this binding before returning the handle.
        unsafe {
            (*self.first.get()).write(handle.clone());
            (*self.target.get()).write(handle);
        };
        self.published.store(true, Ordering::Release);
        Ok(())
    }

    fn first(&self) -> Result<&WakeHandle<N>, WorkError> {
        if !self.published.load(Ordering::Acquire) || self.detached.load(Ordering::Acquire) {
            return Err(WorkError::Unavailable);
        }
        // SAFETY: acquired once-only initialization, immutable through detach.
        Ok(unsafe { (*self.first.get()).assume_init_ref() })
    }
    pub fn context_id(&self) -> Result<ContextId, WorkError> {
        Ok(self.first()?.context_id())
    }
    /// Real current job's immutable wake view. An older IRQ copy remains closed
    /// after completion and cannot authorize a later job on the reused stack.
    pub fn current_wake(&self) -> Result<WakeHandle<N>, WorkError> {
        self.first()?.renew_current()
    }
    /// Capture this current job, keeping metadata independently of
    /// original C usage refs. An old target may outlive clean job completion;
    /// its expected sequence can never signal or inspect a future job.
    pub fn target_current(self: &Arc<Self>) -> Result<TargetTask<N>, WorkError> {
        let wake = self.current_wake()?;
        Ok(TargetTask {
            binding: ManuallyDrop::new(self.clone()),
            wake: ManuallyDrop::new(wake),
        })
    }

    unsafe extern "C" fn wake_target(binding: *mut c_void, expected: u64) -> i32 {
        // SAFETY: C validated an entered same-CPU caller and kept
        // target reference. It cannot run a callback/switch or free this Arc.
        let this = unsafe { &*binding.cast::<Self>() };
        if !this.published.load(Ordering::Acquire) || this.detached.load(Ordering::Acquire) {
            return -116; // ESTALE
        }
        // SAFETY: same-CPU exclusion and acquired initial publication; only an
        // new-job arrive updates this field, before C can target it.
        let handle = unsafe { (*this.target.get()).assume_init_ref() };
        if expected == 0 || handle.sequence() != expected {
            return -116;
        }
        match handle.wake() {
            Ok(()) => 0,
            Err(WorkError::Busy) => -16,
            Err(WorkError::Closed) => -116,
            Err(_) => -1,
        }
    }
    unsafe extern "C" fn service_reserved(binding: *mut c_void) -> bool {
        // SAFETY: C kept this binding and validated the target generation.
        // The first immutable signal owns the constructor's stack role,
        // even after an ordinary task reused its stack for a later job.
        let this = unsafe { &*binding.cast::<Self>() };
        if let Ok(first) = this.first()
            && let Ok(reserved) = first.service_reserved()
        {
            return reserved;
        }
        // An invalid role provider cannot silently authorize signal mutation.
        // SAFETY: fail closed before the C caller's first signal/ref effect.
        unsafe { core::arch::asm!("ud2", options(noreturn)) };
    }

    unsafe extern "C" fn rank(
        binding: *mut c_void,
        expected: u64,
        before: *const Rank,
        after: *const Rank,
        head: bool,
    ) -> i32 {
        // SAFETY: C retains this binding through its validated task generation;
        // no switch or final drop can occur while its PI lock is held.
        let this = unsafe { &*binding.cast::<Self>() };
        if !this.published.load(Ordering::Acquire)
            || this.detached.load(Ordering::Acquire)
            || expected == 0
        {
            return -116;
        }
        // SAFETY: initial publication and every new-job arrive initialize the
        // target before C can use its same-CPU, serialized task metadata.
        let target = unsafe { (*this.target.get()).assume_init_ref() };
        if target.sequence() != expected || before.is_null() || after.is_null() {
            return -116;
        }
        let result = (|| {
            let handle = target.scheduling_handle()?;
            // SAFETY: the live C call provides two initialized, immutable
            // primitive records; their borrows end before returning to C.
            let (before, after) = unsafe { ((&*before).snapshot()?, (&*after).snapshot()?) };
            // SAFETY: C owns the original task's serialized priority/PI-lock
            // mutation and commits matching C fields before releasing it.
            unsafe { handle.update(before, after, head) }
        })();
        match result {
            Ok(()) => 0,
            Err(WorkError::Closed) => -116,
            Err(WorkError::Unavailable) => -95,
            Err(_) => -1,
        }
    }

    fn validate(&self, context: &TaskContext) -> Result<(), WorkError> {
        let handle = self.current_wake()?;
        if handle.context_id().get() != context.context_id || handle.sequence() != context.sequence
        {
            return Err(WorkError::CorruptContext);
        }
        // Runtime keeps Queue/signal while attached: this temporary handle's
        // drop is necessarily nonfinal, including IF=0 arrive callbacks.
        Ok(())
    }
    unsafe extern "C" fn current(binding: *mut c_void, context: *const TaskContext) -> bool {
        // SAFETY: Arc receiver and callback-scoped readable view.
        let this = unsafe { &*binding.cast::<Self>() };
        // Validate CPU/IRQ/RSP independently BEFORE dereferencing any
        // mutable C task/context field. ops/binding stay immutable and kept
        // throughout attached lifetime, including taskless/IRQ rejection.
        let Ok(handle) = this.current_wake() else {
            return false;
        };
        // SAFETY: same-CPU current has now been established. C supplies
        // copied primitive metadata, not a temporary Runtime view.
        let view = unsafe { &*context };
        handle.context_id().get() == view.context_id && handle.sequence() == view.sequence
    }

    /// Run C with a shared Runtime capability on this stack.
    ///
    /// # Safety
    /// `body`/`context` remain valid through every real suspension; C may not
    /// unwind, escape the capability, leave a Linux owner/critical state live,
    /// or retire the Runtime/stack/binding. Keep shared owner roots and use
    /// the checked C lease for mutations. An exclusive Rust owner/context
    /// borrow may not span park if another continuation can access that owner.
    pub unsafe fn run_scoped(
        self: &Arc<Self>,
        runtime: Pin<&Runtime<N>>,
        body: unsafe extern "C" fn(*mut c_void),
        context: *mut c_void,
    ) -> Result<(), WorkError> {
        let view = runtime.current_context()?;
        self.validate(&view)?;
        let scope = Scope { runtime };
        // Pin the stack-local capability; it may not move/escape while
        // suspended C frames borrow it. Pin<&Runtime> is shared, never &mut.
        let scope = core::pin::pin!(scope);
        let pointer = scope.as_ref().get_ref() as *const Scope<'_, N> as *mut c_void;
        // SAFETY: task/current and immovable scoped capability above.
        status(unsafe {
            stela_linux_task_scope_begin(self.task.as_ptr(), &Self::SCOPE_OPS, pointer)
        })?;
        // SAFETY: caller's no-unwind/no-escape body contract keeps this scope live.
        unsafe { body(context) };
        // SAFETY: body returned only after Linux exit and restored task state.
        let ended = unsafe { stela_linux_task_scope_end(self.task.as_ptr()) };
        // A returning error would destroy a scope C might still keep. This is
        // a fail-closed contract violation, not a recoverable lifetime release.
        if ended != 0 {
            // SAFETY: an escaped C borrow cannot be released or unwound. Stop
            // before destroying its scoped stack capability or borrowed owners.
            unsafe { core::arch::asm!("ud2", options(noreturn)) };
        }
        Ok(())
    }
    unsafe extern "C" fn park(scope: *mut c_void) -> i32 {
        // SAFETY: run_scoped keeps this pinned shared Runtime borrow until C
        // returns, including the suspended stack and borrowed owners.
        match unsafe { &*scope.cast::<Scope<'_, N>>() }
            .runtime
            .park_if_blocked()
        {
            Ok(ParkOutcome::Skipped) => 0,
            Ok(ParkOutcome::Resumed) => 1,
            Err(WorkError::Busy) => -16,
            Err(_) => -22,
        }
    }
    unsafe extern "C" fn yield_now(scope: *mut c_void) -> i32 {
        // SAFETY: same shared scoped capability as park.
        match unsafe { &*scope.cast::<Scope<'_, N>>() }
            .runtime
            .yield_now()
        {
            Ok(()) => 0,
            Err(WorkError::Busy) => -16,
            Err(_) => -22,
        }
    }

    unsafe extern "C" fn reschedule(scope: *mut c_void) -> i32 {
        // SAFETY: same pinned shared Runtime scope; C proved a process
        // preparation or its private outside-owner scope-end preparation.
        match unsafe { &*scope.cast::<Scope<'_, N>>() }
            .runtime
            .reschedule()
        {
            Ok(()) => 0,
            Err(WorkError::Busy) => -16,
            Err(_) => -22,
        }
    }
    unsafe extern "C" fn reschedule_requested(scope: *mut c_void) -> bool {
        // SAFETY: C checks current, critical state and scope before this
        // bounded clock/query callback. It invokes no C delivery or switch.
        match unsafe { &*scope.cast::<Scope<'_, N>>() }
            .runtime
            .reschedule_requested()
        {
            Ok(requested) => requested,
            Err(_) => {
                // SAFETY: invalid/closed providers cannot become a false query.
                unsafe { core::arch::asm!("ud2", options(noreturn)) };
            }
        }
    }

    /// Release a pristine unattached task, or after Runtime detach restored flags.
    ///
    /// # Safety
    /// Producer/waiter/task/code users have stopped, on the checked
    /// process CPU outside IRQ and Linux entry, after native flags restoration.
    /// Detach's unsafe quiescence promise is real, not inferred from Arc counts.
    pub unsafe fn release_quiescent(self: Arc<Self>) -> Result<(), Arc<Self>> {
        if self.published.load(Ordering::Acquire) && !self.detached.load(Ordering::Acquire) {
            return Err(self);
        }
        let mut this = Arc::try_unwrap(self)?;
        // SAFETY: explicit caller proof plus successful unique detached ownership.
        unsafe { stela_linux_task_release(this.task.as_ptr()) };
        this.released = true;
        Ok(())
    }
}
struct Scope<'a, const N: usize> {
    runtime: Pin<&'a Runtime<N>>,
}

// SAFETY: Runtime owns real current/stack/IF exclusion and keeps this Arc.
// Each C hook is transactional before leave or bounded after committed arrival;
// no drain/allocator/final release occurs in any hook. C copies view metadata.
unsafe impl<const N: usize> SwitchBinding for TaskBinding<N> {
    unsafe fn attach(&self, context: &TaskContext) -> Result<(), WorkError> {
        if self.published.load(Ordering::Acquire) || self.detached.load(Ordering::Acquire) {
            return Err(WorkError::Busy);
        }
        // SAFETY: initial stack hook precedes initial WakeHandle publication.
        status(unsafe {
            stela_linux_task_attach(
                self.task.as_ptr(),
                context,
                &Self::OPS,
                self as *const Self as *mut c_void,
            )
        })
    }
    unsafe fn still_blocked(&self, context: &TaskContext) -> Result<bool, WorkError> {
        self.validate(context)?;
        // SAFETY: current CPU/RSP/ticket checked before C state inspection.
        match unsafe { stela_linux_task_still_blocked(self.task.as_ptr(), context) } {
            0 => Ok(false),
            1 => Ok(true),
            -16 => Err(WorkError::Busy),
            _ => Err(WorkError::CorruptContext),
        }
    }
    unsafe fn leave(&self, context: &TaskContext, reason: LeaveReason) -> Result<(), WorkError> {
        self.validate(context)?;
        // SAFETY: outgoing stack/IF0, C requires prepared process snapshot.
        status(unsafe { stela_linux_task_leave(self.task.as_ptr(), context, reason as u32) })
    }
    unsafe fn arrive(&self, context: &TaskContext, new_job: bool) -> Result<(), WorkError> {
        self.validate(context)?;
        if new_job {
            let next = self.current_wake()?;
            // SAFETY: same-CPU destination stack/IF0, no foreign C or
            // IRQ task-pointer reader. The mutable field borrow ends before
            // any hook. Runtime keeps Queue/signal so old Drop is nonfinal.
            let previous =
                unsafe { core::ptr::replace((*self.target.get()).assume_init_mut(), next) };
            drop(previous);
        }
        // SAFETY: resumed/new job stack and existing ticket before IF restore.
        status(unsafe { stela_linux_task_arrive(self.task.as_ptr(), context, new_job) })
    }
    unsafe fn complete(&self, context: &TaskContext) -> Result<(), WorkError> {
        self.validate(context)?;
        // SAFETY: outgoing real stack; C refuses unless process exit/scope ended.
        status(unsafe { stela_linux_task_complete(self.task.as_ptr(), context) })
    }
    unsafe fn detach(&self, context: &TaskContext) -> Result<(), WorkError> {
        // No current validation is invented on the idle dispatcher. Runtime
        // already checks CPU/IF0/quiescence and supplies saved RSP.
        if self.first()?.context_id().get() != context.context_id {
            return Err(WorkError::CorruptContext);
        }
        // SAFETY: unsafe caller's producer quiescence and idle hook.
        status(unsafe { stela_linux_task_detach(self.task.as_ptr(), context) })?;
        self.detached.store(true, Ordering::Release);
        Ok(())
    }
}
impl<const N: usize> Drop for TaskBinding<N> {
    fn drop(&mut self) {
        if !self.released {
            // No uncertain Drop can become C metadata release permission. A live
            // Runtime still keeps an Arc; safely detached but unconsumed task
            // metadata is held and observable here.
            QUARANTINED.fetch_add(1, Ordering::Relaxed);
        }
        if self.published.load(Ordering::Acquire) {
            // SAFETY: exclusive Self destruction and acquired single publication.
            // WakeHandle itself quarantines final roots on IRQ/foreign CPU Drop.
            unsafe {
                (*self.target.get()).assume_init_drop();
                (*self.first.get()).assume_init_drop();
            };
        }
    }
}

/// The two observable kernel-wait cancellation classes. These post real
/// original SIGUSR1/SIGKILL pending bits; no POSIX process termination, siginfo
/// delivery, realtime queue or guest signal ABI is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum WaitSignal {
    Interrupt = 1,
    Fatal = 2,
}

/// Owns metadata and an immutable expected job, not a permanent C usage ref.
/// Completion can close the job while this handle is held. Only the plain
/// WakeHandle is an IRQ signal view; TargetTask's C operations are process-only.
pub struct TargetTask<const N: usize> {
    binding: ManuallyDrop<Arc<TaskBinding<N>>>,
    wake: ManuallyDrop<WakeHandle<N>>,
}
impl<const N: usize> Clone for TargetTask<N> {
    fn clone(&self) -> Self {
        Self {
            binding: self.binding.clone(),
            wake: self.wake.clone(),
        }
    }
}
impl<const N: usize> TargetTask<N> {
    pub fn context_id(&self) -> ContextId {
        self.wake.context_id()
    }
    pub fn sequence(&self) -> u64 {
        self.wake.sequence()
    }
    /// Post to the captured job only. Closed/reused jobs return Closed before
    /// future C state is accessed; keeping this target is not a Linux task ref.
    ///
    /// # Safety
    /// Call on the real same-CPU entered Linux process continuation described
    /// by `caller`, with shared service roots kept. Do not call from IRQ,
    /// IF0 switch hooks, a dispatcher, or outside run_scoped/Linux entry.
    /// Target wait cancellation returns Busy once its body has returned (or
    /// no C body is active); generic immutable wakes remain valid.
    pub unsafe fn signal(
        &self,
        caller: Pin<&Runtime<N>>,
        kind: WaitSignal,
    ) -> Result<(), WorkError> {
        self.wake.check_process()?;
        caller.current_context()?;
        // SAFETY: immutable expected generation plus separately kept C
        // metadata; caller proves entered Linux process permission.
        match unsafe {
            stela_linux_task_signal(self.binding.task.as_ptr(), self.sequence(), kind as u32)
        } {
            0 => Ok(()),
            -116 => Err(WorkError::Closed),
            -16 => Err(WorkError::Busy),
            -95 => Err(WorkError::Unavailable),
            _ => Err(WorkError::CorruptContext),
        }
    }
}
impl<const N: usize> Drop for TargetTask<N> {
    fn drop(&mut self) {
        if self.wake.check_process().is_ok() {
            // SAFETY: checked process CPU. Native callers keep the normal
            // flags-restored release boundary; no switch hook owns a TargetTask.
            // Keep the immutable wake owner until after binding destruction.
            unsafe {
                ManuallyDrop::drop(&mut self.binding);
                ManuallyDrop::drop(&mut self.wake);
            }
        } else {
            // Never let an old producer's final owner release run in native
            // IRQ/foreign-CPU context. Keep BOTH metadata and provider roots.
            QUARANTINED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) mod tests;
