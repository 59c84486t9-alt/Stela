//! Actual Linux task metadata on retained cooperative continuations.
//!
//! This binds original C task_struct/current and the entered service lease.
//! The shared normal/WW mutex adapter supplies genuine wake/signal/I/O effects.
//! Native producers and the distinct RT-mutex/I2C extension remain unadmitted.
use crate::platform::work::{
    ContextId, LeaveReason, ParkOutcome, Runtime, SwitchBinding, TaskContext, WakeHandle, WorkError,
};
use alloc::sync::Arc;
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    mem::{ManuallyDrop, MaybeUninit},
    pin::Pin,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

#[repr(C)]
struct TaskOps {
    is_current: unsafe extern "C" fn(*mut c_void, *const TaskContext) -> bool,
    wake_target: unsafe extern "C" fn(*mut c_void, u64) -> i32,
}
#[repr(C)]
struct ScopeOps {
    park: unsafe extern "C" fn(*mut c_void) -> i32,
    yield_now: unsafe extern "C" fn(*mut c_void) -> i32,
}
#[repr(C)]
struct CTask {
    _opaque: [u8; 0],
}
unsafe extern "C" {
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

static QUARANTINED: AtomicU64 = AtomicU64::new(0);

/// Metadata kept because its final release was not explicitly qualified.
/// This counts no native/GPU qualification and never reclaims uncertain tasks.
pub fn quarantined() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

/// Retains the C task independently of a per-enter borrowed service owner.
/// The first immutable waker validates actual CPU/IRQ/RSP before C state access;
/// renew_current obtains the actual existing job ticket on stack reuse.
pub struct TaskBinding<const N: usize> {
    task: NonNull<CTask>,
    first: UnsafeCell<MaybeUninit<WakeHandle<N>>>,
    target: UnsafeCell<MaybeUninit<WakeHandle<N>>>,
    published: AtomicBool,
    detached: AtomicBool,
    released: bool,
}
// SAFETY: no foreign CPU mutates the C task or first waker. Actual Runtime
// identity is checked before C entry; publication is single-writer release/
// acquire and the immutable waker is retained until safe detach/release.
unsafe impl<const N: usize> Send for TaskBinding<N> {}
// SAFETY: same single qualified CPU contract; IRQ wake views contain no C task.
unsafe impl<const N: usize> Sync for TaskBinding<N> {}

fn status(value: i32) -> Result<(), WorkError> {
    match value {
        0 => Ok(()),
        -16 => Err(WorkError::Busy),
        _ => Err(WorkError::CorruptContext),
    }
}
impl<const N: usize> TaskBinding<N> {
    const OPS: TaskOps = TaskOps {
        is_current: Self::current,
        wake_target: Self::wake_target,
    };
    const SCOPE_OPS: ScopeOps = ScopeOps {
        park: Self::park,
        yield_now: Self::yield_now,
    };

    /// Allocate original task metadata before entering a Linux owner.
    ///
    /// # Safety
    /// Call in qualified process context on the Runtime CPU, with the canonical
    /// heap initialized. Every binding using the common !SMP C archive must stay
    /// on that SAME qualified physical CPU for its lifetime; retain all actual
    /// CPU/code/root authority separately. No native producer is established
    /// by this allocation. C metadata failure is fallible; Arc allocation uses
    /// the image's existing global allocation-error policy.
    pub unsafe fn new() -> Result<Arc<Self>, WorkError> {
        // SAFETY: caller supplies actual canonical heap/process authority.
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

    /// Attach only to this actual current continuation, before Linux entry.
    /// Initial waker publication completes before any original C task service.
    pub fn bind_current(self: &Arc<Self>, runtime: Pin<&Runtime<N>>) -> Result<(), WorkError> {
        if self.published.load(Ordering::Acquire) {
            return Err(WorkError::Busy);
        }
        let handle = runtime.bind_current(self.clone())?;
        // SAFETY: one successful Runtime attachment owns this same-CPU initial
        // publication. Runtime retains this binding before returning the handle.
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
    /// Capture this actual current job, retaining metadata independently of
    /// original C usage refs. An old target may outlive clean job completion;
    /// its expected sequence can never signal or inspect a future job.
    pub fn target_current(self: &Arc<Self>) -> Result<TargetTask<N>, WorkError> {
        let wake = self.current_wake()?;
        Ok(TargetTask { binding: ManuallyDrop::new(self.clone()), wake: ManuallyDrop::new(wake) })
    }

    unsafe extern "C" fn wake_target(binding: *mut c_void, expected: u64) -> i32 {
        // SAFETY: C validated an actual entered same-CPU caller and retained
        // target reference. It cannot run a callback/switch or free this Arc.
        let this = unsafe { &*binding.cast::<Self>() };
        if !this.published.load(Ordering::Acquire) || this.detached.load(Ordering::Acquire) {
            return -116; // ESTALE
        }
        // SAFETY: same-CPU exclusion and acquired initial publication; only an
        // actual new-job arrive updates this field, before C can target it.
        let handle = unsafe { (*this.target.get()).assume_init_ref() };
        if expected == 0 || handle.sequence() != expected { return -116; }
        match handle.wake() {
            Ok(()) => 0, Err(WorkError::Busy) => -16,
            Err(WorkError::Closed) => -116, Err(_) => -1,
        }
    }

    fn validate(&self, context: &TaskContext) -> Result<(), WorkError> {
        let handle = self.current_wake()?;
        if handle.context_id().get() != context.context_id || handle.sequence() != context.sequence
        {
            return Err(WorkError::CorruptContext);
        }
        // Runtime retains Queue/signal while attached: this temporary handle's
        // drop is necessarily nonfinal, including IF=0 arrive callbacks.
        Ok(())
    }
    unsafe extern "C" fn current(binding: *mut c_void, context: *const TaskContext) -> bool {
        // SAFETY: retained Arc receiver and callback-scoped readable view.
        let this = unsafe { &*binding.cast::<Self>() };
        // Validate actual CPU/IRQ/RSP independently BEFORE dereferencing any
        // mutable C task/context field. ops/binding stay immutable and retained
        // throughout attached lifetime, including taskless/IRQ rejection.
        let Ok(handle) = this.current_wake() else {
            return false;
        };
        // SAFETY: actual same-CPU current has now been established. C supplies
        // copied primitive metadata, not a retained temporary Runtime view.
        let view = unsafe { &*context };
        handle.context_id().get() == view.context_id && handle.sequence() == view.sequence
    }

    /// Run C with a shared retained Runtime capability on this actual stack.
    ///
    /// # Safety
    /// `body`/`context` remain valid through every real suspension; C may not
    /// unwind, escape the capability, leave a Linux owner/critical state live,
    /// or retire the Runtime/stack/binding. Retain shared owner roots and use
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
        // Pin the actual stack-local capability; it may not move/escape while
        // suspended C frames borrow it. Pin<&Runtime> is shared, never &mut.
        let scope = core::pin::pin!(scope);
        let pointer = scope.as_ref().get_ref() as *const Scope<'_, N> as *mut c_void;
        // SAFETY: retained task/current and immovable scoped capability above.
        status(unsafe {
            stela_linux_task_scope_begin(self.task.as_ptr(), &Self::SCOPE_OPS, pointer)
        })?;
        // SAFETY: caller's no-unwind/no-escape body contract keeps this scope live.
        unsafe { body(context) };
        // SAFETY: body returned only after Linux exit and restored task state.
        let ended = unsafe { stela_linux_task_scope_end(self.task.as_ptr()) };
        // A returning error would destroy a scope C might still retain. This is
        // a fail-closed contract violation, not a recoverable lifetime release.
        if ended != 0 {
            // SAFETY: an escaped C borrow cannot be released or unwound. Stop
            // before destroying its scoped stack capability or borrowed owners.
            unsafe { core::arch::asm!("ud2", options(noreturn)) };
        }
        Ok(())
    }
    unsafe extern "C" fn park(scope: *mut c_void) -> i32 {
        // SAFETY: run_scoped retains this pinned shared Runtime borrow until C
        // returns, including the actual suspended stack and borrowed owners.
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
        // SAFETY: same retained shared scoped capability as park.
        match unsafe { &*scope.cast::<Scope<'_, N>>() }
            .runtime
            .yield_now()
        {
            Ok(()) => 0,
            Err(WorkError::Busy) => -16,
            Err(_) => -22,
        }
    }

    /// Release a pristine unattached task, or after Runtime detach restored flags.
    ///
    /// # Safety
    /// Actual producer/waiter/task/code users have stopped, on the qualified
    /// process CPU outside IRQ and Linux entry, after native flags restoration.
    /// Detach's unsafe quiescence promise is real, not inferred from Arc counts.
    pub unsafe fn release_quiescent(self: Arc<Self>) -> Result<(), Arc<Self>> {
        if self.published.load(Ordering::Acquire) && !self.detached.load(Ordering::Acquire) {
            return Err(self);
        }
        let mut this = match Arc::try_unwrap(self) {
            Ok(value) => value,
            Err(value) => return Err(value),
        };
        // SAFETY: explicit caller proof plus successful unique detached ownership.
        unsafe { stela_linux_task_release(this.task.as_ptr()) };
        this.released = true;
        Ok(())
    }
}
struct Scope<'a, const N: usize> {
    runtime: Pin<&'a Runtime<N>>,
}

// SAFETY: Runtime owns real current/stack/IF exclusion and retains this Arc.
// Each C hook is transactional before leave or bounded after committed arrival;
// no drain/allocator/final release occurs in any hook. C copies view metadata.
unsafe impl<const N: usize> SwitchBinding for TaskBinding<N> {
    unsafe fn attach(&self, context: &TaskContext) -> Result<(), WorkError> {
        if self.published.load(Ordering::Acquire) || self.detached.load(Ordering::Acquire) {
            return Err(WorkError::Busy);
        }
        // SAFETY: initial actual-stack hook precedes initial WakeHandle publication.
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
        // SAFETY: actual outgoing stack/IF0, C requires prepared process snapshot.
        status(unsafe { stela_linux_task_leave(self.task.as_ptr(), context, reason as u32) })
    }
    unsafe fn arrive(&self, context: &TaskContext, new_job: bool) -> Result<(), WorkError> {
        self.validate(context)?;
        if new_job {
            let next = self.current_wake()?;
            // SAFETY: actual same-CPU destination stack/IF0, no foreign C or
            // IRQ task-pointer reader. The mutable field borrow ends before
            // any hook. Runtime retains Queue/signal so old Drop is nonfinal.
            let previous = unsafe {
                core::ptr::replace((*self.target.get()).assume_init_mut(), next)
            };
            drop(previous);
        }
        // SAFETY: actual resumed/new job stack and existing ticket before IF restore.
        status(unsafe { stela_linux_task_arrive(self.task.as_ptr(), context, new_job) })
    }
    unsafe fn complete(&self, context: &TaskContext) -> Result<(), WorkError> {
        self.validate(context)?;
        // SAFETY: outgoing real stack; C refuses unless process exit/scope ended.
        status(unsafe { stela_linux_task_complete(self.task.as_ptr(), context) })
    }
    unsafe fn detach(&self, context: &TaskContext) -> Result<(), WorkError> {
        // No current validation is fabricated on the idle dispatcher. Runtime
        // already qualifies CPU/IF0/quiescence and supplies saved actual RSP.
        if self.first()?.context_id().get() != context.context_id {
            return Err(WorkError::CorruptContext);
        }
        // SAFETY: unsafe caller's producer quiescence and genuine idle hook.
        status(unsafe { stela_linux_task_detach(self.task.as_ptr(), context) })?;
        self.detached.store(true, Ordering::Release);
        Ok(())
    }
}
impl<const N: usize> Drop for TaskBinding<N> {
    fn drop(&mut self) {
        if !self.released {
            // No uncertain Drop can become C metadata release authority. A live
            // Runtime still retains an Arc; safely detached but unconsumed task
            // metadata is deliberately retained and observable here.
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
pub enum WaitSignal { Interrupt = 1, Fatal = 2 }

/// Owns metadata and an immutable expected job, not a permanent C usage ref.
/// Completion can close the job while this handle is retained. Only the plain
/// WakeHandle is an IRQ signal view; TargetTask's C operations are process-only.
pub struct TargetTask<const N: usize> {
    binding: ManuallyDrop<Arc<TaskBinding<N>>>,
    wake: ManuallyDrop<WakeHandle<N>>,
}
impl<const N: usize> Clone for TargetTask<N> {
    fn clone(&self) -> Self {
        Self { binding: self.binding.clone(), wake: self.wake.clone() }
    }
}
impl<const N: usize> TargetTask<N> {
    pub fn context_id(&self) -> ContextId { self.wake.context_id() }
    pub fn sequence(&self) -> u64 { self.wake.sequence() }
    /// Post to the captured job only. Closed/reused jobs return Closed before
    /// future C state is accessed; retaining this target is not a Linux task ref.
    ///
    /// # Safety
    /// Call on the real same-CPU entered Linux process continuation described
    /// by `caller`, with shared service roots retained. Do not call from IRQ,
    /// IF0 switch hooks, a dispatcher, or outside run_scoped/Linux entry.
    pub unsafe fn signal(&self, caller: Pin<&Runtime<N>>, kind: WaitSignal) -> Result<(), WorkError> {
        self.wake.check_process()?;
        caller.current_context()?;
        // SAFETY: immutable expected generation plus separately retained C
        // metadata; caller proves actual entered Linux process authority.
        match unsafe { stela_linux_task_signal(self.binding.task.as_ptr(), self.sequence(), kind as u32) } {
            0 => Ok(()), -116 => Err(WorkError::Closed), -16 => Err(WorkError::Busy),
            _ => Err(WorkError::CorruptContext),
        }
    }
}
impl<const N: usize> Drop for TargetTask<N> {
    fn drop(&mut self) {
        if self.wake.check_process().is_ok() {
            // SAFETY: qualified process CPU. Native callers retain the normal
            // flags-restored release boundary; no switch hook owns a TargetTask.
            // Keep the immutable wake owner until after binding destruction.
            unsafe { ManuallyDrop::drop(&mut self.binding); ManuallyDrop::drop(&mut self.wake); }
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
pub(crate) mod tests {
    //! Hosted source fixtures only. Real mmap stacks/guards and actual Runtime
    //! continuations; the CPU/IRQ model grants no native admission. All C tree
    //! assertions are retained. This plain Rust child is not whole-C ASan/UBSan.
    extern crate std;
    use super::*;
    use crate::platform::work::{Cpu, Executor, Kind, Queue, Stack, StackBacking};
    use alloc::{boxed::Box, vec::Vec};
    use core::{
        alloc::{GlobalAlloc, Layout},
        cell::UnsafeCell,
        ops::Range,
        ptr,
        sync::atomic::{AtomicPtr, AtomicUsize},
    };
    use std::{alloc::System, sync::Mutex, thread};

    #[repr(align(4096))]
    struct Span([u8; 64 * 1024]);
    struct Raw {
        storage: UnsafeCell<Span>,
        enabled: AtomicBool,
        occupied: AtomicBool,
        size: AtomicUsize,
        align: AtomicUsize,
    }
    // SAFETY: allocation wins one CAS; its unique live owner excludes concurrent
    // read/free/reuse of the raw bytes. No libc allocation/growth/lock fallback.
    unsafe impl Sync for Raw {}
    static RAW: Raw = Raw {
        storage: UnsafeCell::new(Span([0; 64 * 1024])),
        enabled: AtomicBool::new(false),
        occupied: AtomicBool::new(false),
        size: AtomicUsize::new(0),
        align: AtomicUsize::new(0),
    };
    impl Raw {
        fn base(&self) -> *mut u8 {
            self.storage.get().cast::<u8>()
        }
        unsafe fn allocate(&self, layout: Layout) -> *mut u8 {
            if !self.enabled.load(Ordering::Acquire)
                || layout.size() == 0
                || layout.size() > 64 * 1024
                || layout.align() > 4096
            {
                return ptr::null_mut();
            }
            if self
                .occupied
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                return ptr::null_mut();
            }
            self.size.store(layout.size(), Ordering::Relaxed);
            self.align.store(layout.align(), Ordering::Relaxed);
            // SAFETY: sole successful CAS owner holds the entire aligned span.
            unsafe { ptr::write_bytes(self.base(), 0, layout.size()) };
            self.base()
        }
        unsafe fn free(&self, pointer: *mut u8, layout: Layout) {
            if pointer != self.base()
                || !self.occupied.load(Ordering::Relaxed)
                || layout.size() != self.size.load(Ordering::Relaxed)
                || layout.align() != self.align.load(Ordering::Relaxed)
            {
                std::process::abort();
            }
            // SAFETY: unique exact-layout owner frees once, before release/reuse.
            unsafe { ptr::write_bytes(pointer, 0xd3, layout.size()) };
            self.occupied.store(false, Ordering::Release);
        }
        fn address_in_storage(&self, pointer: *const u8) -> bool {
            (pointer as usize).wrapping_sub(self.base() as usize) < 64 * 1024
        }
    }
    struct CanonicalHeap;
    #[global_allocator]
    static CANONICAL: CanonicalHeap = CanonicalHeap;
    // SAFETY: all ordinary layouts belong to System; the canonical raw try span
    // has exact base/layout/live identity and this SAME GlobalAlloc's free branch.
    // Raw free does not allocate/drop/spin. Other unit tests keep System behavior.
    unsafe impl GlobalAlloc for CanonicalHeap {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: ordinary valid GlobalAlloc layout, delegated unchanged.
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: same ordinary System owner and exact layout.
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            if RAW.address_in_storage(pointer) {
                // SAFETY: canonical raw span branch checks exact identity/layout.
                unsafe { RAW.free(pointer, layout) };
            } else {
                // SAFETY: ordinary canonical allocation has this same System owner.
                unsafe { System.dealloc(pointer, layout) };
            }
        }
    }
    unsafe fn try_allocate(layout: Layout) -> *mut u8 {
        // SAFETY: immutable registry uses this canonical allocator's raw branch;
        // matching free goes through the actual production Rust heap bridge.
        unsafe { RAW.allocate(layout) }
    }
    #[unsafe(no_mangle)]
    extern "C" fn stela_test_heap_try_enable(enable: bool) {
        if RAW.occupied.load(Ordering::Acquire) {
            std::process::abort();
        }
        // Fixture policy only: false forces ordinary exhaustion; permanent registry
        // capability stays installed. Caller excludes concurrent allocator users.
        RAW.enabled.store(enable, Ordering::Release);
    }
    #[unsafe(no_mangle)]
    extern "C" fn stela_test_heap_try_contains(pointer: *const c_void) -> bool {
        // Diagnostic contract: caller owns a live returned allocation and excludes
        // concurrent free/reuse. occupied does not publish later size/align stores.
        RAW.occupied.load(Ordering::Acquire)
            && (pointer as usize).wrapping_sub(RAW.base() as usize)
                < RAW.size.load(Ordering::Relaxed)
    }

    unsafe extern "C" {
        fn stela_linux_trees_fixture() -> i32;
        fn stela_linux_task_test_taskless();
        fn stela_linux_task_test_unprepared_begin();
        fn stela_linux_task_test_unprepared_end();
        fn stela_linux_task_test_foreground(context: *mut c_void);
        fn stela_linux_task_test_worker(context: *mut c_void);
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
    // SAFETY: real exclusive OS mapping, PROT_NONE guard, retained through every
    // switched frame. Hosted test only; this is no native root/IRQ/provider grant.
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
            // SAFETY: Runtime retired all frames/producers and detached C task users.
            assert_eq!(unsafe { munmap(self.base as *mut c_void, self.bytes) }, 0);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn stacks(dropped: &Arc<AtomicU64>, usable: usize) -> Vec<Stack> {
        (0..4)
            .map(|_| {
                #[cfg(target_os = "macos")]
                let anonymous = 0x1000;
                #[cfg(not(target_os = "macos"))]
                let anonymous = 0x20;
                let bytes = usable + 4096;
                // SAFETY: actual OS-owned anonymous RW memory; no preexisting frames.
                let base = unsafe { mmap(ptr::null_mut(), bytes, 3, 2 | anonymous, -1, 0) };
                assert_ne!(base as usize, usize::MAX);
                // SAFETY: first page of this owned mapping becomes genuinely unmapped.
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
    // SAFETY: explicit hosted same-thread exclusion/IRQ model. No CPL0 CLI/STI or
    // real native producer is claimed. Runtime still uses actual switched stacks.
    unsafe impl Cpu for CpuModel {
        fn check_cpu(&self) -> Result<(), WorkError> {
            if self.thread == thread::current().id() {
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
        fn fatal(&self, _: WorkError) -> ! {
            std::process::abort()
        }
    }
    struct Fixture {
        cpu: Arc<CpuModel>,
        runtime: AtomicPtr<Runtime<16>>,
        bindings: [Mutex<Option<Arc<TaskBinding<16>>>>; 2],
        wake: Mutex<Option<WakeHandle<16>>>,
        late: Mutex<Option<WakeHandle<16>>>,
        trees: AtomicU64,
        refused: AtomicBool,
    }
    impl Fixture {
        fn new(cpu: Arc<CpuModel>) -> Arc<Self> {
            Arc::new(Self {
                cpu,
                runtime: AtomicPtr::new(ptr::null_mut()),
                bindings: [Mutex::new(None), Mutex::new(None)],
                wake: Mutex::new(None),
                late: Mutex::new(None),
                trees: AtomicU64::new(0),
                refused: AtomicBool::new(false),
            })
        }
        unsafe fn runtime(&self) -> Pin<&Runtime<16>> {
            self.cpu.check_cpu().unwrap();
            // SAFETY: harness owns pinned executor through all callbacks/retirement;
            // Queue retains this fixture. This private process-only helper cannot
            // escape into an IRQ waker; production run_scoped retains a real borrow.
            unsafe { Pin::new_unchecked(&*self.runtime.load(Ordering::Acquire)) }
        }
        fn binding(&self, index: usize) -> Arc<TaskBinding<16>> {
            if let Some(binding) = self.bindings[index].lock().unwrap().clone() {
                return binding;
            }
            // SAFETY: actual hosted qualified process thread before Linux entry.
            let binding = unsafe { TaskBinding::new() }.unwrap();
            binding.bind_current(unsafe { self.runtime() }).unwrap();
            *self.bindings[index].lock().unwrap() = Some(binding.clone());
            binding
        }
    }
    unsafe fn fixture<'a>(context: *mut c_void) -> &'a Fixture {
        // SAFETY: actual Queue owner retains this private fixture through callback.
        unsafe { &*context.cast::<Fixture>() }
    }
    unsafe extern "C" fn worker(context: *mut c_void) {
        let f = unsafe { fixture(context) };
        let binding = f.binding(1);
        // SAFETY: shared Runtime/fixture live through complete scoped C body.
        unsafe { binding.run_scoped(f.runtime(), stela_linux_task_test_worker, context) }.unwrap();
        let wake = f.wake.lock().unwrap().take().unwrap();
        wake.wake().unwrap();
    }
    unsafe extern "C" fn unprepared(context: *mut c_void) {
        let f = unsafe { fixture(context) };
        let runtime = unsafe { f.runtime() };
        unsafe { stela_linux_task_test_unprepared_begin() };
        let before = runtime.current_context().unwrap();
        // Direct generic yield cannot silently suspend an entered C lease. A
        // refusal keeps the SAME actual task, native flags and service owner.
        assert_eq!(runtime.yield_now(), Err(WorkError::Busy));
        assert_eq!(
            runtime.current_context().unwrap().context_id,
            before.context_id
        );
        assert_eq!(cpu_flags(f), 0x202);
        unsafe { stela_linux_task_test_unprepared_end() };
    }
    fn cpu_flags(f: &Fixture) -> u64 {
        f.cpu.flags.load(Ordering::Acquire)
    }
    unsafe extern "C" fn foreground(context: *mut c_void) {
        let f = unsafe { fixture(context) };
        let runtime = unsafe { f.runtime() };
        let binding = f.binding(0);
        let wake = binding.current_wake().unwrap();
        *f.late.lock().unwrap() = Some(wake.clone());
        *f.wake.lock().unwrap() = Some(wake);
        // Genuine worker executes only after the blocked foreground released its
        // prepared owner lease. It wakes this exact old job's retained signal.
        unsafe { runtime.queue().execute(Kind::General, worker, context) }.unwrap();
        // Refuse an unprepared entered lease without leaving or changing identity.
        unsafe { binding.run_scoped(runtime, unprepared, context) }.unwrap();
        let view = runtime.current_context().unwrap();
        // Additional C fixture checks all entered IRQ/BH/RCU/preempt refusals.
        unsafe { binding.run_scoped(runtime, stela_linux_task_test_foreground, context) }.unwrap();
        assert_eq!(
            runtime.current_context().unwrap().context_id,
            view.context_id
        );
    }
    unsafe extern "C" fn trees_body(_: *mut c_void) {
        // SAFETY: retained actual C task, entered by the unchanged fixture body.
        assert_eq!(unsafe { stela_linux_trees_fixture() }, 0);
    }
    unsafe extern "C" fn trees(context: *mut c_void) {
        let f = unsafe { fixture(context) };
        let binding = f.binding(0);
        // SAFETY: scope retains actual shared Runtime and all owner/model backing.
        unsafe { binding.run_scoped(f.runtime(), trees_body, context) }.unwrap();
        f.trees.fetch_add(1, Ordering::Relaxed);
    }
    unsafe extern "C" fn reject_large_stack(context: *mut c_void) {
        let f = unsafe { fixture(context) };
        let binding = unsafe { TaskBinding::<16>::new() }.unwrap();
        assert_eq!(
            binding.bind_current(unsafe { f.runtime() }),
            Err(WorkError::CorruptContext)
        );
        // Rejected initial attach installed no C task or binding; unique metadata
        // rollback occurs here in actual process context, never IF=0 hooks.
        assert!(unsafe { binding.release_quiescent() }.is_ok());
        f.refused.store(true, Ordering::Release);
    }

    /// Invoked in its own current unit-test executable, so actual C globals and
    /// permanent canonical registry cannot race parallel parent unit fixtures.
    pub(crate) fn run_trees_child() {
        let executable = std::env::current_exe().unwrap();
        let output = std::process::Command::new(executable)
            .args([
                "--exact",
                "gpu::linux::task::tests::trees_child",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
                "--format=pretty",
                "--color=never",
            ])
            .output()
            .unwrap();
        let stdout = std::string::String::from_utf8_lossy(&output.stdout);
        let stderr = std::string::String::from_utf8_lossy(&output.stderr);
        // A missing/cfg-excluded exact selector exits successfully with zero
        // tests. Require actual named execution AND exactly one passing test.
        let named = stdout
            .lines()
            .any(|line| line == "test gpu::linux::task::tests::trees_child ... ok");
        let one_passed = stdout
            .lines()
            .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"));
        assert!(
            output.status.success() && named && one_passed,
            "task-aware tree child did not pass exactly once ({}):\n{}{}",
            output.status,
            stdout,
            stderr
        );
    }
    #[test]
    #[ignore = "isolated exact child of gpu::c_tests::linux_trees; no global registry sharing"]
    fn trees_child() {
        // SAFETY: isolated single test child; same canonical GlobalAlloc owns this
        // real raw span and ordinary System storage until exact-layout free.
        assert!(unsafe { crate::gpu::linux::heap::register(try_allocate) }.is_ok());
        unsafe { stela_linux_task_test_taskless() };
        let dropped = Arc::new(AtomicU64::new(0));
        // A larger generic Runtime stack is real, but not this Linux THREAD_SIZE.
        {
            let cpu = CpuModel::new();
            let f = Fixture::new(cpu.clone());
            let queue = unsafe { Queue::<16>::new(cpu, f.clone()) }.unwrap();
            let executor =
                Executor::new_hosted_for_test(queue, stacks(&dropped, 32 * 1024)).unwrap();
            let runtime = executor.runtime();
            f.runtime.store(
                runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>,
                Ordering::Release,
            );
            unsafe {
                runtime.call_foreground(reject_large_stack, Arc::as_ptr(&f) as *mut c_void, 10000)
            }
            .unwrap();
            assert!(f.refused.load(Ordering::Acquire));
            runtime.queue().close().unwrap();
            unsafe { runtime.retire() }.unwrap();
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
        let cpu = CpuModel::new();
        let f = Fixture::new(cpu.clone());
        let queue = unsafe { Queue::<16>::new(cpu.clone(), f.clone()) }.unwrap();
        let executor = Executor::new_hosted_for_test(queue, stacks(&dropped, 16 * 1024)).unwrap();
        let runtime = executor.runtime();
        f.runtime.store(
            runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>,
            Ordering::Release,
        );
        let context = Arc::as_ptr(&f) as *mut c_void;
        assert_eq!(runtime.current_context(), Err(WorkError::Unavailable));
        unsafe { runtime.call_foreground(foreground, context, 10000) }.unwrap();
        assert_eq!(
            f.late.lock().unwrap().as_ref().unwrap().wake(),
            Err(WorkError::Closed)
        );
        let first = f.bindings[0]
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .context_id()
            .unwrap();
        // Reuse the SAME actual continuation/C task with a new existing job ticket.
        unsafe { runtime.call_foreground(trees, context, 10000) }.unwrap();
        assert_eq!(f.trees.load(Ordering::Relaxed), 1);
        assert_eq!(
            f.bindings[0]
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .context_id()
                .unwrap(),
            first
        );
        assert_eq!(
            f.late.lock().unwrap().as_ref().unwrap().wake(),
            Err(WorkError::Closed)
        );
        assert!(!RAW.occupied.load(Ordering::Acquire));
        assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
        runtime.queue().close().unwrap();
        assert_eq!(unsafe { runtime.retire() }, Err(WorkError::Pending));
        for slot in &f.bindings {
            let binding = slot.lock().unwrap().take().unwrap();
            // SAFETY: both actual callbacks completed, no C waiter/foreign producer;
            // no registered IRQ producer or C task reference escapes this child.
            let retained =
                unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
            assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
            drop(retained); // after flags restoration; break the binding/Queue cycle
            assert!(unsafe { binding.release_quiescent() }.is_ok());
        }
        f.late.lock().unwrap().take();
        unsafe { runtime.retire() }.unwrap();
        drop(executor);
        assert_eq!(dropped.load(Ordering::Relaxed), 8);
        assert_eq!(quarantined(), 0);
        unsafe { stela_linux_task_test_taskless() };
    }


    #[repr(C)]
    struct MutexCall {
        scenario: u32,
        role: u32,
        context: *mut c_void,
        checkpoint: unsafe extern "C" fn(*mut c_void, u32),
    }
    unsafe extern "C" {
        fn stela_linux_mutex_test_run(context: *mut c_void);
    }
    struct MutexRole {
        fixture: alloc::sync::Weak<MutexFixture>,
        scenario: u32,
        role: usize,
    }
    struct MutexFixture {
        cpu: Arc<CpuModel>,
        runtime: AtomicPtr<Runtime<16>>,
        bindings: [Mutex<Option<Arc<TaskBinding<16>>>>; 4],
        targets: [Mutex<Option<TargetTask<16>>>; 5],
        jobs: [Box<MutexRole>; 5],
        completed: AtomicU64,
        signals: AtomicU64,
        stale: AtomicU64,
        prepare_signals: AtomicU64,
        self_signals: AtomicU64,
    }
    impl MutexFixture {
        fn new(cpu: Arc<CpuModel>, scenario: u32) -> Arc<Self> {
            Arc::new_cyclic(|weak| Self {
                cpu,
                runtime: AtomicPtr::new(ptr::null_mut()),
                bindings: core::array::from_fn(|_| Mutex::new(None)),
                targets: core::array::from_fn(|_| Mutex::new(None)),
                // All stable callback storage is allocated before publication;
                // neither original wake_q nor PREPARE callbacks allocate it.
                jobs: core::array::from_fn(|role| Box::new(MutexRole {
                    fixture: weak.clone(),
                    scenario,
                    role,
                })),
                completed: AtomicU64::new(0),
                signals: AtomicU64::new(0),
                stale: AtomicU64::new(0),
                prepare_signals: AtomicU64::new(0),
                self_signals: AtomicU64::new(0),
            })
        }
        unsafe fn runtime(&self) -> Pin<&Runtime<16>> {
            self.cpu.check_cpu().unwrap();
            // SAFETY: this private hosted fixture's retained executor owns the
            // exact pinned Runtime until all callbacks end and bindings detach.
            unsafe { Pin::new_unchecked(&*self.runtime.load(Ordering::Acquire)) }
        }
        fn binding(&self, index: usize) -> Arc<TaskBinding<16>> {
            if let Some(binding) = self.bindings[index].lock().unwrap().clone() {
                return binding;
            }
            // SAFETY: real process stack/CPU, outside entered C/IF0 hooks.
            let binding = unsafe { TaskBinding::new() }.unwrap();
            binding.bind_current(unsafe { self.runtime() }).unwrap();
            *self.bindings[index].lock().unwrap() = Some(binding.clone());
            binding
        }
        fn context(&self, role: usize) -> *mut c_void {
            &*self.jobs[role] as *const MutexRole as *mut c_void
        }
        fn target(&self, role: usize) -> TargetTask<16> {
            // This is also used in an original RCU process-retirement callback.
            // Refuse contention instead of blocking at SOFTIRQ_OFFSET; cloning
            // only increments retained owners, with nonfinal drops afterward.
            self.targets[role].try_lock().unwrap().as_ref().unwrap().clone()
        }
        fn enqueue(&self, role: usize) {
            let lane = if role == 1 || role == 4 { Kind::Notify } else { Kind::General };
            // SAFETY: fixture owns stable job storage until every real callback
            // completes. Enqueue is bounded, with no callback or heap allocation.
            unsafe { self.runtime().queue().execute(lane, mutex_role, self.context(role)) }.unwrap();
        }
    }
    unsafe fn mutex_job<'a>(context: *mut c_void) -> &'a MutexRole {
        // SAFETY: stable boxed role retained by the actual Queue fixture owner.
        unsafe { &*context.cast::<MutexRole>() }
    }
    unsafe extern "C" fn mutex_checkpoint(context: *mut c_void, event: u32) {
        let job = unsafe { mutex_job(context) };
        let f = job.fixture.upgrade().unwrap();
        let runtime = unsafe { f.runtime() };
        match event {
            1 => {
                f.enqueue(1);
                if job.scenario == 0 {
                    f.enqueue(2);
                    f.enqueue(3);
                }
            }
            2 | 3 | 4 => {
                let target = f.target(1);
                let kind = if event == 3 { WaitSignal::Fatal } else { WaitSignal::Interrupt };
                // SAFETY: called by the real same-CPU entered C owner. Event4
                // is process PREPARE's bounded softirq-accounted callback, not
                // a native interrupt producer or an IF0 switch hook.
                unsafe { target.signal(runtime, kind) }.unwrap();
                if event == 4 {
                    f.prepare_signals.fetch_add(1, Ordering::Relaxed);
                } else {
                    f.signals.fetch_add(1, Ordering::Relaxed);
                }
            }
            5 => {
                let old = f.target(1);
                assert_eq!(unsafe { old.signal(runtime, WaitSignal::Fatal) }, Err(WorkError::Closed));
                f.stale.fetch_add(1, Ordering::Relaxed);
            }
            6 => f.enqueue(4),
            7 | 8 => {
                let target = f.target(0);
                let kind = if event == 7 { WaitSignal::Interrupt } else { WaitSignal::Fatal };
                // SAFETY: actual entered current posts to its own expected job.
                unsafe { target.signal(runtime, kind) }.unwrap();
                f.self_signals.fetch_add(1, Ordering::Relaxed);
            }
            10 => {
                let target = f.target(1);
                let wake = (*target.wake).clone();
                drop(target);
                // Explicit hosted IRQ model: only the retained generic atomic
                // signal view is reachable here, never a C task/Runtime pointer.
                f.cpu.irq.store(true, Ordering::Release);
                wake.wake().unwrap();
                wake.wake().unwrap(); // coalesced repeated wake before resume
                f.cpu.irq.store(false, Ordering::Release);
                drop(wake);
            }
            _ => panic!("unexpected mutex checkpoint"),
        }
    }
    unsafe extern "C" fn mutex_role(context: *mut c_void) {
        let job = unsafe { mutex_job(context) };
        let f = job.fixture.upgrade().unwrap();
        let runtime = unsafe { f.runtime() };
        let index = if job.role == 4 { 1 } else { job.role };
        let binding = f.binding(index);
        let target = binding.target_current().unwrap();
        if job.role == 4 {
            let old = f.target(1);
            assert_eq!(old.context_id(), target.context_id());
            assert_ne!(old.sequence(), target.sequence());
        }
        *f.targets[job.role].try_lock().unwrap() = Some(target);
        let mut call = MutexCall {
            scenario: job.scenario,
            role: job.role as u32,
            context,
            checkpoint: mutex_checkpoint,
        };
        // SAFETY: only shared retained Runtime/owner roots span suspension;
        // call is an actual immovable stack local until this C body returns.
        unsafe {
            binding.run_scoped(runtime, stela_linux_mutex_test_run, ptr::from_mut(&mut call).cast())
        }.unwrap();
        f.completed.fetch_add(1, Ordering::Relaxed);
    }

    fn exact_mutex_child(selector: &str) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", selector, "--ignored", "--test-threads=1", "--nocapture", "--format=pretty", "--color=never"])
            .output().unwrap();
        let stdout = std::string::String::from_utf8_lossy(&output.stdout);
        let stderr = std::string::String::from_utf8_lossy(&output.stderr);
        let expected = std::format!("test {selector} ... ok");
        let named = stdout.lines().any(|line| line == expected);
        let one = stdout.lines().any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"));
        assert!(output.status.success() && named && one,
            "mutex child did not execute/pass exactly once ({}):\n{}{}", output.status, stdout, stderr);
    }
    pub(crate) fn run_mutex_child() {
        exact_mutex_child("gpu::linux::task::tests::mutex_child");
        exact_mutex_child("gpu::linux::task::tests::mutex_quarantine_child");
    }

    #[test]
    #[ignore = "isolated exact child of gpu::c_tests::linux_mutex_wait"]
    fn mutex_child() {
        // SAFETY: isolated canonical allocator registry, same real GlobalAlloc
        // owns ordinary and raw-span allocations and their exact-layout frees.
        assert!(unsafe { crate::gpu::linux::heap::register(try_allocate) }.is_ok());
        assert_eq!(core::mem::size_of::<MutexCall>(), 24);
        let dropped = Arc::new(AtomicU64::new(0));
        for scenario in 0..11 {
            let cpu = CpuModel::new();
            let f = MutexFixture::new(cpu.clone(), scenario);
            let queue = unsafe { Queue::<16>::new(cpu.clone(), f.clone()) }.unwrap();
            let executor = Executor::new_hosted_for_test(queue, stacks(&dropped, 16 * 1024)).unwrap();
            let runtime = executor.runtime();
            f.runtime.store(runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>, Ordering::Release);
            // SAFETY: actual guarded stacks and retained fixture/job roots, no
            // C owner/ref survives completion, no native admission is asserted.
            unsafe { runtime.call_foreground(mutex_role, f.context(0), 100000) }.unwrap();
            assert_eq!(f.completed.load(Ordering::Relaxed), if scenario == 0 { 5 } else { 2 });
            assert_eq!(f.prepare_signals.load(Ordering::Relaxed), u64::from(scenario == 5));
            assert_eq!(f.stale.load(Ordering::Relaxed), if scenario == 0 { 2 } else { 0 });
            let expected_signals = match scenario { 1 | 3 | 4 | 6 | 9 => 1, 2 => 2, _ => 0 };
            assert_eq!(f.signals.load(Ordering::Relaxed), expected_signals);
            assert_eq!(f.self_signals.load(Ordering::Relaxed), if scenario < 7 || scenario == 10 { 2 } else { 0 });
            // All expected-job snapshots are now inert even though metadata is
            // still retained. Taking them in process context breaks Arc cycles.
            for slot in &f.targets {
                if let Some(target) = slot.lock().unwrap().take() {
                    assert_eq!(target.wake.wake(), Err(WorkError::Closed));
                    drop(target);
                }
            }
            assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
            runtime.queue().close().unwrap();
            assert_eq!(unsafe { runtime.retire() }, Err(WorkError::Pending));
            for slot in &f.bindings {
                if let Some(binding) = slot.lock().unwrap().take() {
                    let retained = unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
                    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
                    drop(retained);
                    // SAFETY: actual jobs completed; C refs, waiters, signal
                    // snapshots and all producer borrows ended independently.
                    assert!(unsafe { binding.release_quiescent() }.is_ok());
                }
            }
            unsafe { runtime.retire() }.unwrap();
            drop(executor);
            assert_eq!(dropped.load(Ordering::Relaxed), (u64::from(scenario) + 1) * 4);
            assert_eq!(quarantined(), 0);
            assert!(!RAW.occupied.load(Ordering::Acquire));
            unsafe { stela_linux_task_test_taskless() };
        }
    }

    unsafe extern "C" fn quarantine_targets(context: *mut c_void) {
        // No Linux entry is needed for capture/drop mechanics. Runtime still
        // provides actual current/C task identity on its real guarded stack.
        let job = unsafe { mutex_job(context) };
        let f = job.fixture.upgrade().unwrap();
        let binding = f.binding(0);
        let baseline = Arc::strong_count(&binding);
        let target = binding.target_current().unwrap();
        let foreign = target.clone();
        thread::spawn(move || drop(foreign)).join().unwrap();
        assert_eq!(quarantined(), 1);
        assert_eq!(Arc::strong_count(&binding), baseline + 2);
        let irq = target.clone();
        f.cpu.irq.store(true, Ordering::Release);
        drop(irq);
        f.cpu.irq.store(false, Ordering::Release);
        assert_eq!(quarantined(), 2);
        assert_eq!(Arc::strong_count(&binding), baseline + 3);
        drop(target);
        assert_eq!(Arc::strong_count(&binding), baseline + 2);
    }
    #[test]
    #[ignore = "isolated exact child; intentional quarantine cannot share normal teardown proof"]
    fn mutex_quarantine_child() {
        let dropped = Arc::new(AtomicU64::new(0));
        let cpu = CpuModel::new();
        let f = MutexFixture::new(cpu.clone(), 0);
        let queue = unsafe { Queue::<16>::new(cpu, f.clone()) }.unwrap();
        let executor = Executor::new_hosted_for_test(queue, stacks(&dropped, 16 * 1024)).unwrap();
        let runtime = executor.runtime();
        f.runtime.store(runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>, Ordering::Release);
        unsafe { runtime.call_foreground(quarantine_targets, f.context(0), 100000) }.unwrap();
        runtime.queue().close().unwrap();
        let binding = f.bindings[0].lock().unwrap().take().unwrap();
        let retained = unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
        drop(retained);
        // The two improper drops intentionally kept real metadata owners. A
        // claimed unique release must refuse; no final C free is smuggled into
        // the foreign thread/IRQ model or inferred from task usage alone.
        let unreleased = unsafe { binding.release_quiescent() }.err().unwrap();
        assert_eq!(Arc::strong_count(&unreleased), 3);
        drop(unreleased); // nonfinal process-context drop; two retained owners remain
        unsafe { runtime.retire() }.unwrap();
        drop(executor);
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
        assert_eq!(quarantined(), 2);
    }
}
