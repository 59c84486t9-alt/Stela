//! Hosted source fixtures only. Real mmap stacks/guards and Runtime
//! continuations; the CPU/IRQ model grants no native admission. All C tree
//! assertions are held. This plain Rust child is not whole-C ASan/UBSan.
extern crate std;
use super::*;
use alloc::{boxed::Box, vec::Vec};
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ops::Range,
    ptr,
    sync::atomic::{AtomicPtr, AtomicUsize},
};
use std::{alloc::System, sync::Mutex, thread};
use stela_driver_base::platform::work::service;
use stela_driver_base::platform::work::{Cpu, Executor, Kind, Queue, Stack, StackBacking};

/// Page-aligned backing, reached only through the raw storage pointer.
#[repr(align(4096))]
struct Span(
    #[expect(dead_code, reason = "reached only through the raw storage pointer")] [u8; 64 * 1024],
);
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
        // SAFETY: sole test-only C counter owner; fixed atomics and a
        // refusal flag, with no allocator/lock/drop/spin or replacement.
        if !unsafe { stela_test_allocation_attempt(1) } {
            return ptr::null_mut();
        }
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
        // SAFETY: observe this ordinary backend attempt once;
        // refusal returns NULL before the SAME canonical System call.
        if !unsafe { stela_test_allocation_attempt(0) } {
            return ptr::null_mut();
        }
        // SAFETY: ordinary valid GlobalAlloc layout, delegated unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: observe this ordinary backend attempt once;
        // refusal returns NULL before the SAME canonical System call.
        if !unsafe { stela_test_allocation_attempt(0) } {
            return ptr::null_mut();
        }
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
    // matching free goes through the production Rust heap bridge.
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
        && (pointer as usize).wrapping_sub(RAW.base() as usize) < RAW.size.load(Ordering::Relaxed)
}

unsafe extern "C" {
    fn stela_test_allocation_attempt(route: u32) -> bool;
    fn stela_linux_trees_fixture() -> i32;
    fn stela_linux_task_test_taskless();
    fn stela_linux_percpu_fixture(context: *mut c_void);
    fn stela_linux_percpu_taskless_fixture();
    fn stela_linux_task_test_unprepared_begin();
    fn stela_linux_task_test_unprepared_end();
    fn stela_linux_task_test_foreground(context: *mut c_void);
    fn stela_linux_task_test_worker(context: *mut c_void);
    fn stela_linux_task_test_schedule_worker(context: *mut c_void);
    fn stela_linux_task_test_pending_schedule(context: *mut c_void);
    fn stela_linux_task_test_service_wait(context: *mut c_void);
    fn stela_linux_task_test_service_cancel(context: *mut c_void);
    fn stela_linux_task_test_clock_service(context: *mut c_void);
    fn stela_linux_task_test_runnable_boundary(context: *mut c_void);
    fn stela_linux_task_test_closed_stack();
    fn stela_linux_atomic_callback_prepared_fixture(task: *mut CTask, context: *const TaskContext);
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
// SAFETY: real exclusive OS mapping, PROT_NONE guard, kept through every
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
    stacks_count(dropped, usable, 4)
}
fn stacks_count(dropped: &Arc<AtomicU64>, usable: usize, count: usize) -> Vec<Stack> {
    (0..count)
        .map(|_| {
            #[cfg(target_os = "macos")]
            let anonymous = 0x1000;
            #[cfg(not(target_os = "macos"))]
            let anonymous = 0x20;
            let bytes = usable + 4096;
            // SAFETY: OS-owned anonymous RW memory; no preexisting frames.
            let base = unsafe { mmap(ptr::null_mut(), bytes, 3, 2 | anonymous, -1, 0) };
            assert_ne!(base as usize, usize::MAX);
            // SAFETY: first page of this owned mapping becomes unmapped.
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
// real native producer is claimed. Runtime still uses switched stacks.
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
    bindings: [Mutex<Option<Arc<TaskBinding<16>>>>; 3],
    service_target: Mutex<Option<TargetTask<16>>>,
    scope_target: Mutex<Option<TargetTask<16>>>,
    service_domain: Mutex<Option<Arc<service::Domain<16>>>>,
    ticks: AtomicU64,
    tick_goal: AtomicU64,
    boundary_mode: AtomicU64,
    boundary_ready: AtomicBool,
    clock_reads: Arc<AtomicU64>,
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
            bindings: core::array::from_fn(|_| Mutex::new(None)),
            service_target: Mutex::new(None),
            scope_target: Mutex::new(None),
            service_domain: Mutex::new(None),
            ticks: AtomicU64::new(0),
            tick_goal: AtomicU64::new(2),
            boundary_mode: AtomicU64::new(0),
            boundary_ready: AtomicBool::new(false),
            clock_reads: Arc::new(AtomicU64::new(0)),
            wake: Mutex::new(None),
            late: Mutex::new(None),
            trees: AtomicU64::new(0),
            refused: AtomicBool::new(false),
        })
    }
    unsafe fn runtime(&self) -> Pin<&Runtime<16>> {
        self.cpu.check_cpu().unwrap();
        // SAFETY: harness owns pinned executor through all callbacks/retirement;
        // Queue keeps this fixture. This private process-only helper cannot
        // escape into an IRQ waker; production run_scoped keeps a real borrow.
        unsafe { Pin::new_unchecked(&*self.runtime.load(Ordering::Acquire)) }
    }
    fn binding(&self, index: usize) -> Arc<TaskBinding<16>> {
        if let Some(binding) = self.bindings[index].lock().unwrap().clone() {
            return binding;
        }
        // SAFETY: hosted checked process thread before Linux entry.
        let binding = unsafe { TaskBinding::new() }.unwrap();
        // SAFETY: the harness keeps the pinned executor through every callback and
        // retirement.
        binding.bind_current(unsafe { self.runtime() }).unwrap();
        *self.bindings[index].lock().unwrap() = Some(binding.clone());
        binding
    }
}
unsafe fn fixture<'a>(context: *mut c_void) -> &'a Fixture {
    // SAFETY: Queue owner keeps this private fixture through callback.
    unsafe { &*context.cast::<Fixture>() }
}
unsafe extern "C" fn worker(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    let binding = f.binding(1);
    // SAFETY: shared Runtime/fixture live through complete scoped C body.
    unsafe { binding.run_scoped(f.runtime(), stela_linux_task_test_worker, context) }.unwrap();
    let wake = f.wake.lock().unwrap().take().unwrap();
    wake.wake().unwrap();
    // SAFETY: the same real worker now exercises original
    // schedule's distinct process preempt0 sleep/wake boundary.
    unsafe { binding.run_scoped(f.runtime(), stela_linux_task_test_schedule_worker, context) }
        .unwrap();
}
unsafe extern "C" fn unprepared(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    // SAFETY: the C test hook only checks task state on this thread's entered continuation.
    unsafe { stela_linux_task_test_unprepared_begin() };
    let before = runtime.current_context().unwrap();
    // Direct generic yield cannot silently suspend an entered C lease. A
    // refusal keeps the SAME task, native flags and service owner.
    assert_eq!(runtime.yield_now(), Err(WorkError::Busy));
    assert_eq!(
        runtime.current_context().unwrap().context_id,
        before.context_id
    );
    assert_eq!(cpu_flags(f), 0x202);
    // SAFETY: the C test hook only checks task state on this thread's entered continuation.
    unsafe { stela_linux_task_test_unprepared_end() };
}
fn cpu_flags(f: &Fixture) -> u64 {
    f.cpu.flags.load(Ordering::Acquire)
}
unsafe extern "C" fn foreground(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    let binding = f.binding(0);
    let prepared_view = runtime.current_context().unwrap();
    // SAFETY: this real attached current has no Linux owner/scope yet. The
    // C fixture keeps its own scope and checks before-effect refusal.
    unsafe { stela_linux_atomic_callback_prepared_fixture(binding.task.as_ptr(), &prepared_view) };
    let wake = binding.current_wake().unwrap();
    *f.late.lock().unwrap() = Some(wake.clone());
    *f.wake.lock().unwrap() = Some(wake);
    // Worker executes only after the blocked foreground released its
    // prepared owner lease. It wakes this exact old job's signal.
    // SAFETY: the callbacks are static, never unwind, and take the fixture the queue keeps
    // until completion.
    unsafe { runtime.queue().execute(Kind::General, worker, context) }.unwrap();
    // Refuse an unprepared entered lease without leaving or changing identity.
    // SAFETY: the callbacks are static, never unwind, and take the fixture the queue keeps
    // through every suspension.
    unsafe { binding.run_scoped(runtime, unprepared, context) }.unwrap();
    let view = runtime.current_context().unwrap();
    // Additional C fixture checks all entered IRQ/BH/RCU/preempt refusals.
    // SAFETY: the callbacks are static, never unwind, and take the fixture the queue keeps
    // through every suspension.
    unsafe { binding.run_scoped(runtime, stela_linux_task_test_foreground, context) }.unwrap();
    assert_eq!(
        runtime.current_context().unwrap().context_id,
        view.context_id
    );
    binding.current_wake().unwrap().wake().unwrap();
    // SAFETY: this job and scope keep the pending generic wake;
    // the C fixture checks schedule's state restoration without a switch.
    unsafe { binding.run_scoped(runtime, stela_linux_task_test_pending_schedule, context) }
        .unwrap();
}
unsafe extern "C" fn trees_body(_: *mut c_void) {
    // SAFETY: reused foreground job, old worker metadata kept.
    unsafe { stela_linux_task_test_closed_stack() };
    // SAFETY: same real attached task and RunScoped body; this callable
    // fixture enters/exits its own owner and keeps no callback/context.
    unsafe { stela_linux_percpu_fixture(ptr::null_mut()) };
    // SAFETY: C task, entered by the unchanged fixture body.
    assert_eq!(unsafe { stela_linux_trees_fixture() }, 0);
}
unsafe extern "C" fn trees(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    let binding = f.binding(0);
    // SAFETY: scope keeps shared Runtime and all owner/model backing.
    unsafe { binding.run_scoped(f.runtime(), trees_body, context) }.unwrap();
    f.trees.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn reject_large_stack(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    // SAFETY: process context on the runtime CPU with the hosted heap initialized.
    let binding = unsafe { TaskBinding::<16>::new() }.unwrap();
    assert_eq!(
        // SAFETY: the harness keeps the pinned executor through every callback and
        // retirement.
        binding.bind_current(unsafe { f.runtime() }),
        Err(WorkError::CorruptContext)
    );
    // Rejected initial attach installed no C task or binding; unique metadata
    // rollback occurs here in process context, never IF=0 hooks.
    // SAFETY: the runtime detached this binding and no job or waker still uses it.
    assert!(unsafe { binding.release_quiescent() }.is_ok());
    f.refused.store(true, Ordering::Release);
}

/// Invoked in its own current unit-test executable, so C globals and
/// permanent canonical registry cannot race parallel parent unit fixtures.
pub(crate) fn run_trees_child() {
    assert_eq!(
        super::stack_requirement(),
        stela_driver_base::platform::work::StackRequirement::exact(16 * 1024, 16 * 1024, 4096)
    );
    let executable = std::env::current_exe().unwrap();
    let output = std::process::Command::new(executable)
        .args([
            "--exact",
            "linux::task::tests::trees_child",
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
    // tests. Require named execution AND exactly one passing test.
    let named = stdout
        .lines()
        .any(|line| line == "test linux::task::tests::trees_child ... ok");
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
#[ignore = "isolation: child"]
fn trees_child() {
    // SAFETY: isolated single test child; same canonical GlobalAlloc owns this
    // real raw span and ordinary System storage until exact-layout free.
    assert!(unsafe { crate::linux::heap::register(try_allocate) }.is_ok());
    // SAFETY: the C test hook only checks task state on this thread's entered continuation.
    unsafe { stela_linux_task_test_taskless() };
    // SAFETY: taskless dispatcher, before any TaskBinding attach;
    // the observer requires a trap before backing allocation is attempted.
    unsafe { stela_linux_percpu_taskless_fixture() };
    let dropped = Arc::new(AtomicU64::new(0));
    // A larger generic Runtime stack is real, but not this Linux THREAD_SIZE.
    {
        let cpu = CpuModel::new();
        let f = Fixture::new(cpu.clone());
        // SAFETY: the fixture is the queue's owner, and only this test thread produces
        // work.
        let queue = unsafe { Queue::<16>::new(cpu, f.clone()) }.unwrap();
        let executor = Executor::new_hosted_for_test(queue, stacks(&dropped, 32 * 1024)).unwrap();
        let runtime = executor.runtime();
        f.runtime.store(
            runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>,
            Ordering::Release,
        );
        // SAFETY: the callbacks are static, never unwind, and take the fixture the queue
        // keeps until completion.
        unsafe {
            runtime.call_foreground(reject_large_stack, Arc::as_ptr(&f) as *mut c_void, 10000)
        }
        .unwrap();
        assert!(f.refused.load(Ordering::Acquire));
        runtime.queue().close().unwrap();
        // SAFETY: the queue is closed and this test thread is the only producer; pending work
        // is a checked refusal.
        unsafe { runtime.retire() }.unwrap();
    }
    assert_eq!(dropped.load(Ordering::Relaxed), 4);
    let cpu = CpuModel::new();
    let f = Fixture::new(cpu.clone());
    // SAFETY: the fixture is the queue's owner, and only this test thread produces
    // work.
    let queue = unsafe { Queue::<16>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor = Executor::new_hosted_for_test(queue, stacks(&dropped, 16 * 1024)).unwrap();
    let runtime = executor.runtime();
    f.runtime.store(
        runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>,
        Ordering::Release,
    );
    let context = Arc::as_ptr(&f) as *mut c_void;
    assert_eq!(runtime.current_context(), Err(WorkError::Unavailable));
    // SAFETY: the callbacks are static, never unwind, and take the fixture the queue keeps
    // until completion.
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
    // Reuse the SAME continuation/C task with a new existing job ticket.
    // SAFETY: the callbacks are static, never unwind, and take the fixture the queue keeps
    // until completion.
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
    // SAFETY: the queue is closed and this test thread is the only producer; pending work is a
    // checked refusal.
    assert_eq!(unsafe { runtime.retire() }, Err(WorkError::Pending));
    for slot in &f.bindings {
        let Some(binding) = slot.lock().unwrap().take() else {
            continue;
        };
        // SAFETY: both callbacks completed, no C waiter/foreign producer;
        // no registered IRQ producer or C task reference escapes this child.
        let retained = unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
        assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
        drop(retained); // after flags restoration; break the binding/Queue cycle
        // SAFETY: the runtime detached this binding and no job or waker still uses it.
        assert!(unsafe { binding.release_quiescent() }.is_ok());
    }
    f.late.lock().unwrap().take();
    // SAFETY: the queue is closed and this test thread is the only producer; pending work is a
    // checked refusal.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 8);
    assert_eq!(quarantined(), 0);
    // SAFETY: the C test hook only checks task state on this thread's entered continuation.
    unsafe { stela_linux_task_test_taskless() };
    service_roundtrip();
    clock_service_roundtrip(0);
    clock_service_roundtrip(1);
    clock_service_roundtrip(2);
    stack_catalog_capacity();
}

unsafe extern "C" fn service_wait(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    assert_eq!(runtime.service_current(), Ok(true));
    let binding = f.binding(2);
    *f.service_target.lock().unwrap() = Some(binding.target_current().unwrap());
    // SAFETY: reserved continuation and kept fixture/code roots.
    unsafe { binding.run_scoped(runtime, stela_linux_task_test_service_wait, context) }.unwrap();
}
unsafe extern "C" fn service_cancel_and_wake(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    let target = f.service_target.lock().unwrap().as_ref().unwrap().clone();
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    assert_eq!(
        // SAFETY: callback from the entered same-CPU foreground C owner.
        unsafe { target.signal(runtime, WaitSignal::Interrupt) },
        Err(WorkError::Unavailable)
    );
    assert_eq!(
        // SAFETY: this is the entered same-CPU continuation inside `run_scoped`, with the
        // service roots kept.
        unsafe { target.signal(runtime, WaitSignal::Fatal) },
        Err(WorkError::Unavailable)
    );
    target.wake.wake().unwrap();
}
#[repr(C)]
struct ServiceCall {
    context: *mut c_void,
    cancel_and_wake: unsafe extern "C" fn(*mut c_void),
}
unsafe extern "C" fn service_caller(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    assert_eq!(runtime.service_current(), Ok(false));
    let binding = f.binding(0);
    let mut call = ServiceCall {
        context,
        cancel_and_wake: service_cancel_and_wake,
    };
    // SAFETY: stack-local call and real scope remain live through C return.
    unsafe {
        binding.run_scoped(
            runtime,
            stela_linux_task_test_service_cancel,
            (&mut call as *mut ServiceCall).cast(),
        )
    }
    .unwrap();
}
fn service_roundtrip() {
    let cpu = CpuModel::new();
    let f = Fixture::new(cpu.clone());
    // SAFETY: the fixture is the queue's owner, and only this test thread produces
    // work.
    let queue = unsafe { Queue::<16>::new(cpu.clone(), f.clone()) }.unwrap();
    let dropped = Arc::new(AtomicU64::new(0));
    let executor =
        Executor::new_hosted_service_for_test(queue, stacks_count(&dropped, 16 * 1024, 5)).unwrap();
    let runtime = executor.runtime();
    f.runtime.store(
        runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>,
        Ordering::Release,
    );
    let context = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: fixture roots keep both callbacks through join below.
    let service = unsafe { runtime.start_service(service_wait, context) }.unwrap();
    assert!(runtime.step().unwrap());
    assert!(!runtime.queue().completed(service).unwrap());
    // SAFETY: the callbacks are static, never unwind, and take the fixture the queue keeps
    // until completion.
    unsafe { runtime.call_foreground(service_caller, context, 10000) }.unwrap();
    runtime.drain(10000).unwrap();
    assert!(runtime.queue().completed(service).unwrap());
    assert_eq!(
        // SAFETY: the queue owner keeps the fixture, and this service binds its task before
        // any admission.
        unsafe { runtime.start_service(service_wait, context) },
        Err(WorkError::Busy)
    );
    let target = f.service_target.lock().unwrap().take().unwrap();
    assert_eq!(target.wake.wake(), Err(WorkError::Closed));
    drop(target);
    runtime.queue().close().unwrap();
    for slot in &f.bindings {
        let Some(binding) = slot.lock().unwrap().take() else {
            continue;
        };
        // SAFETY: all real service/caller frames completed; no C/IRQ producer.
        let retained = unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
        drop(retained);
        // SAFETY: the runtime detached this binding and no job or waker still uses it.
        assert!(unsafe { binding.release_quiescent() }.is_ok());
    }
    // SAFETY: the queue is closed and this test thread is the only producer; pending work is a
    // checked refusal.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 5);
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
    assert_eq!(quarantined(), 0);
}

struct ServiceClock {
    cpu: Arc<dyn Cpu>,
    reads: Arc<AtomicU64>,
    start: std::time::Instant,
}
// SAFETY: hosted monotonic clock; no native IRQ attestation.
unsafe impl service::Clock for ServiceClock {
    fn cpu(&self) -> &Arc<dyn Cpu> {
        &self.cpu
    }
    fn now_ns(&self) -> Result<u64, WorkError> {
        self.cpu.check_cpu()?;
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.start
            .elapsed()
            .as_nanos()
            .try_into()
            .map_err(|_| WorkError::Exhausted)
    }
}
struct ServiceIdle {
    clock: Arc<dyn service::Clock>,
    owner: thread::Thread,
    waits: AtomicU64,
}
// SAFETY: hosted park/unpark event token; no native ISR is admitted.
// Unpark is held across check-to-park and never runs a callback inline.
unsafe impl service::Idle for ServiceIdle {
    fn clock(&self) -> &Arc<dyn service::Clock> {
        &self.clock
    }
    fn notify(&self) -> Result<(), WorkError> {
        self.owner.unpark();
        Ok(())
    }
    fn wait_until_ns(&self, deadline: Option<u64>) -> Result<(), WorkError> {
        self.clock.cpu().check_cpu()?;
        self.waits.fetch_add(1, Ordering::Relaxed);
        if let Some(deadline) = deadline {
            let now = self.clock.now_ns()?;
            if now < deadline {
                thread::park_timeout(std::time::Duration::from_nanos(deadline - now));
            }
        } else {
            thread::park();
        }
        Ok(())
    }
}
#[repr(C)]
struct ClockServiceCall {
    context: *mut c_void,
    boundary: unsafe extern "C" fn(*mut c_void) -> bool,
}
unsafe extern "C" fn clock_boundary(context: *mut c_void) -> bool {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    assert_eq!(runtime.service_current(), Ok(true));
    let domain = f.service_domain.lock().unwrap().as_ref().unwrap().clone();
    if let Some(batch) = domain.begin(runtime).unwrap() {
        assert!(batch.tick() && !batch.raised() && !batch.timer());
        if f.boundary_mode.load(Ordering::Relaxed) == 0 || f.boundary_ready.load(Ordering::Acquire)
        {
            f.ticks.fetch_add(1, Ordering::Relaxed);
        }
        if f.boundary_mode.load(Ordering::Relaxed) == 2 {
            let target = f.scope_target.lock().unwrap().as_ref().unwrap().clone();
            assert_eq!(
                // SAFETY: same-CPU entered service; target has returned its
                // body and is in its private scope-end switch.
                unsafe { target.signal(runtime, WaitSignal::Interrupt) },
                Err(WorkError::Busy)
            );
            assert_eq!(
                // SAFETY: this is the entered same-CPU continuation inside `run_scoped`, with
                // the service roots kept.
                unsafe { target.signal(runtime, WaitSignal::Fatal) },
                Err(WorkError::Busy)
            );
            target.wake.wake().unwrap();
        }
        // SAFETY: reserved task delivered this fixture's counter
        // consumer. No original IRQ-work/timer storage is admitted by it.
        unsafe { domain.finish(runtime, batch, None) }.unwrap();
    }
    f.ticks.load(Ordering::Relaxed) >= f.tick_goal.load(Ordering::Relaxed)
}
unsafe extern "C" fn clock_service(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    let binding = f.binding(2);
    let domain = f.service_domain.lock().unwrap().as_ref().unwrap().clone();
    domain.bind_current(runtime).unwrap();
    let mut call = ClockServiceCall {
        context,
        boundary: clock_boundary,
    };
    // SAFETY: real kept C task/stack and stack-local callback descriptor.
    unsafe {
        binding.run_scoped(
            runtime,
            stela_linux_task_test_clock_service,
            (&mut call as *mut ClockServiceCall).cast(),
        )
    }
    .unwrap();
    domain.stop_producers().unwrap();
}
#[repr(C)]
struct RunnableBoundaryCall {
    context: *mut c_void,
    mode: u32,
    make_due: unsafe extern "C" fn(*mut c_void),
    reads: unsafe extern "C" fn(*mut c_void) -> u64,
    ticks: unsafe extern "C" fn(*mut c_void) -> u64,
}
unsafe extern "C" fn boundary_make_due(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    f.boundary_ready.store(true, Ordering::Release);
    // Real elapsed hosted time, with the Runtime task still Running.
    // This invokes no Runtime park/yield, fake tick or service callback.
    thread::sleep(std::time::Duration::from_millis(2));
}
unsafe extern "C" fn boundary_reads(context: *mut c_void) -> u64 {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    unsafe { fixture(context) }
        .clock_reads
        .load(Ordering::Relaxed)
}
unsafe extern "C" fn boundary_ticks(context: *mut c_void) -> u64 {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    unsafe { fixture(context) }.ticks.load(Ordering::Relaxed)
}
unsafe extern "C" fn runnable_boundary(context: *mut c_void) {
    // SAFETY: the queue owner keeps the fixture behind `context` through this callback.
    let f = unsafe { fixture(context) };
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    let binding = f.binding(0);
    if f.boundary_mode.load(Ordering::Relaxed) == 2 {
        *f.scope_target.lock().unwrap() = Some(binding.target_current().unwrap());
    }
    let mut call = RunnableBoundaryCall {
        context,
        mode: f.boundary_mode.load(Ordering::Relaxed) as u32,
        make_due: boundary_make_due,
        reads: boundary_reads,
        ticks: boundary_ticks,
    };
    // SAFETY: same-CPU C scope keeps descriptor and providers.
    unsafe {
        binding.run_scoped(
            runtime,
            stela_linux_task_test_runnable_boundary,
            (&mut call as *mut RunnableBoundaryCall).cast(),
        )
    }
    .unwrap();
    assert_eq!(
        f.ticks.load(Ordering::Relaxed),
        1,
        "cond_resched/scope-end must deliver before this runnable task returns"
    );
    f.scope_target.lock().unwrap().take();
}
fn clock_service_roundtrip(mode: u64) {
    let cpu = CpuModel::new();
    let f = Fixture::new(cpu.clone());
    f.boundary_mode.store(mode, Ordering::Relaxed);
    f.tick_goal
        .store(if mode == 0 { 2 } else { 1 }, Ordering::Relaxed);
    // SAFETY: the fixture is the queue's owner, and only this test thread produces
    // work.
    let queue = unsafe { Queue::<16>::new(cpu.clone(), f.clone()) }.unwrap();
    let dropped = Arc::new(AtomicU64::new(0));
    let executor =
        Executor::new_hosted_service_for_test(queue, stacks_count(&dropped, 16 * 1024, 5)).unwrap();
    let runtime = executor.runtime();
    f.runtime.store(
        runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>,
        Ordering::Release,
    );
    let clock: Arc<dyn service::Clock> = Arc::new(ServiceClock {
        cpu: cpu.clone(),
        reads: f.clock_reads.clone(),
        start: std::time::Instant::now(),
    });
    let idle = Arc::new(ServiceIdle {
        clock: clock.clone(),
        owner: thread::current(),
        waits: AtomicU64::new(0),
    });
    let domain = service::Domain::new(clock, idle.clone()).unwrap();
    runtime.attach_service_domain(domain.clone()).unwrap();
    *f.service_domain.lock().unwrap() = Some(domain.clone());
    let context = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: fixture and registered domain keep all code/providers.
    let ticket = unsafe { runtime.start_service(clock_service, context) }.unwrap();
    if mode == 0 {
        let mut attempts = 0;
        while !runtime.queue().completed(ticket).unwrap() {
            assert!(
                attempts < 32,
                "real service did not complete after bounded event waits"
            );
            runtime.step_or_idle().unwrap();
            attempts += 1;
        }
        assert!(idle.waits.load(Ordering::Relaxed) > 0);
        assert_eq!(
            cpu.time.load(Ordering::Relaxed),
            0,
            "Cpu::ticks is not nanoseconds"
        );
    } else {
        assert!(runtime.step().unwrap()); // service setup/block
        // SAFETY: rooted caller; it must remain Runtime-runnable.
        unsafe { runtime.call_foreground(runnable_boundary, context, 10000) }.unwrap();
        assert!(runtime.queue().completed(ticket).unwrap());
        assert_eq!(idle.waits.load(Ordering::Relaxed), 0);
    }
    assert_eq!(
        f.ticks.load(Ordering::Relaxed),
        f.tick_goal.load(Ordering::Relaxed)
    );
    domain.stop_producers().unwrap();
    // SAFETY: service job completed, no original C timer/work/storage
    // was admitted; the fixture consumer has no outstanding callback/user.
    unsafe { domain.retire() }.unwrap();
    for slot in &f.bindings {
        let Some(binding) = slot.lock().unwrap().take() else {
            continue;
        };
        // SAFETY: service and caller jobs/consumers are now joined.
        let retained = unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
        drop(retained);
        // SAFETY: the runtime detached this binding and no job or waker still uses it.
        assert!(unsafe { binding.release_quiescent() }.is_ok());
    }
    runtime.queue().close().unwrap();
    // SAFETY: the queue is closed and this test thread is the only producer; pending work is a
    // checked refusal.
    unsafe { runtime.retire() }.unwrap();
    f.service_domain.lock().unwrap().take();
    drop(domain);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 5);
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
    assert_eq!(quarantined(), 0);
}

struct CatalogFixture {
    cpu: Arc<CpuModel>,
    runtime: AtomicPtr<Runtime<64>>,
    bindings: Mutex<Vec<Arc<TaskBinding<64>>>>,
    refused: AtomicBool,
}
impl CatalogFixture {
    fn new(cpu: Arc<CpuModel>) -> Arc<Self> {
        Arc::new(Self {
            cpu,
            runtime: AtomicPtr::new(ptr::null_mut()),
            bindings: Mutex::new(Vec::new()),
            refused: AtomicBool::new(false),
        })
    }
    unsafe fn runtime(&self) -> Pin<&Runtime<64>> {
        self.cpu.check_cpu().unwrap();
        // SAFETY: fixture owner keeps this pinned runtime through
        // all admitted callbacks, detach and process-context metadata free.
        unsafe { Pin::new_unchecked(&*self.runtime.load(Ordering::Acquire)) }
    }
    fn publish(&self, runtime: Pin<&Runtime<64>>) {
        self.runtime.store(
            runtime.get_ref() as *const Runtime<64> as *mut Runtime<64>,
            Ordering::Release,
        );
    }
    fn detach(&self, runtime: Pin<&Runtime<64>>) {
        let bindings = core::mem::take(&mut *self.bindings.lock().unwrap());
        for binding in bindings {
            // SAFETY: all real jobs completed, no source/storage/foreign refs.
            let retained =
                unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
            drop(retained);
            // SAFETY: the runtime detached this binding and no job or waker still uses it.
            assert!(unsafe { binding.release_quiescent() }.is_ok());
        }
    }
}
unsafe extern "C" fn catalog_bind(context: *mut c_void) {
    // SAFETY: rooted fixture owns this pointer through completion.
    let f = unsafe { &*context.cast::<CatalogFixture>() };
    // SAFETY: process context on the runtime CPU with the hosted heap initialized.
    let binding = unsafe { TaskBinding::<64>::new() }.unwrap();
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    binding.bind_current(unsafe { f.runtime() }).unwrap();
    f.bindings.lock().unwrap().push(binding);
}
unsafe extern "C" fn catalog_refused(context: *mut c_void) {
    // SAFETY: same rooted fixture/stack, with a full original catalog.
    let f = unsafe { &*context.cast::<CatalogFixture>() };
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    let before = runtime.current_context().unwrap();
    // SAFETY: process context on the runtime CPU with the hosted heap initialized.
    let binding = unsafe { TaskBinding::<64>::new() }.unwrap();
    assert_eq!(binding.bind_current(runtime), Err(WorkError::Full));
    assert_eq!(runtime.current_context(), Ok(before));
    // SAFETY: admission failed before original metadata/publication effects.
    assert!(unsafe { binding.release_quiescent() }.is_ok());
    f.refused.store(true, Ordering::Release);
}
fn stack_catalog_capacity() {
    let cpu = CpuModel::new();
    let dropped = Arc::new(AtomicU64::new(0));
    let first = CatalogFixture::new(cpu.clone());
    // SAFETY: the fixture is the queue's owner, and only this test thread produces
    // work.
    let queue = unsafe { Queue::<64>::new(cpu.clone(), first.clone()) }.unwrap();
    let executor = Executor::new_hosted_policy_for_test(
        queue,
        stacks_count(&dropped, 16 * 1024, 32),
        stela_driver_base::platform::work::ReservationPolicy::NativeFirmware32Protected {
            gpe: stela_driver_base::platform::work::GpeQueueBudget::QUALIFICATION,
        },
    )
    .unwrap();
    let runtime = executor.runtime();
    first.publish(runtime);
    let context = Arc::as_ptr(&first) as *mut c_void;
    // SAFETY: each role/worker callback borrows first, kept by queue through detach.
    unsafe { runtime.start_service(catalog_bind, context) }.unwrap();
    // SAFETY: independent control worker, same immutable fixture owner.
    unsafe { runtime.start_firmware(catalog_bind, context) }.unwrap();
    // SAFETY: serial GPE has one mapped worker; its callback owner survives join.
    unsafe { runtime.queue().execute_gpe(catalog_bind, context) }.unwrap();
    for _ in 0..2 {
        // SAFETY: each accepted Notify permit owns a distinct stack.
        unsafe { runtime.queue().execute(Kind::Notify, catalog_bind, context) }.unwrap();
        // SAFETY: each accepted Portal permit owns a distinct stack.
        unsafe { runtime.queue().execute_portal(catalog_bind, context) }.unwrap();
    }
    for _ in 0..24 {
        // SAFETY: each General callback keeps first and binds one mapped continuation.
        unsafe {
            runtime
                .queue()
                .execute(Kind::General, catalog_bind, context)
        }
        .unwrap();
    }
    // SAFETY: Foreground's mapped stack is distinct from all31 peers above.
    unsafe { runtime.call_foreground(catalog_bind, context, 10000) }.unwrap();
    runtime.drain(10000).unwrap();
    let mut ids: Vec<_> = first
        .bindings
        .lock()
        .unwrap()
        .iter()
        .map(|binding| binding.context_id().unwrap().get())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 32);
    let second = CatalogFixture::new(cpu.clone());
    // SAFETY: the fixture is the queue's owner, and only this test thread produces
    // work.
    let queue = unsafe { Queue::<64>::new(cpu.clone(), second.clone()) }.unwrap();
    let refused = Executor::new_hosted_for_test(queue, stacks(&dropped, 16 * 1024)).unwrap();
    let rejected = refused.runtime();
    second.publish(rejected);
    // SAFETY: the callbacks are static, never unwind, and take the fixture the queue keeps
    // until completion.
    unsafe {
        rejected.call_foreground(catalog_refused, Arc::as_ptr(&second) as *mut c_void, 10000)
    }
    .unwrap();
    assert!(second.refused.load(Ordering::Acquire));
    rejected.queue().close().unwrap();
    // SAFETY: the queue is closed and this test thread is the only producer; pending work is a
    // checked refusal.
    unsafe { rejected.retire() }.unwrap();
    drop(refused);
    runtime.queue().close().unwrap();
    first.detach(runtime);
    // SAFETY: the queue is closed and this test thread is the only producer; pending work is a
    // checked refusal.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 36);
    // Every retired slot is available to fresh mappings again.
    let third = CatalogFixture::new(cpu.clone());
    // SAFETY: the fixture is the queue's owner, and only this test thread produces
    // work.
    let queue = unsafe { Queue::<64>::new(cpu.clone(), third.clone()) }.unwrap();
    let reused = Executor::new_hosted_for_test(queue, stacks(&dropped, 16 * 1024)).unwrap();
    let available = reused.runtime();
    third.publish(available);
    // SAFETY: the callbacks are static, never unwind, and take the fixture the queue keeps
    // until completion.
    unsafe { available.call_foreground(catalog_bind, Arc::as_ptr(&third) as *mut c_void, 10000) }
        .unwrap();
    assert_eq!(third.bindings.lock().unwrap().len(), 1);
    available.queue().close().unwrap();
    third.detach(available);
    // SAFETY: the queue is closed and this test thread is the only producer; pending work is a
    // checked refusal.
    unsafe { available.retire() }.unwrap();
    drop(reused);
    assert_eq!(dropped.load(Ordering::Relaxed), 40);
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
    assert_eq!(quarantined(), 0);
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
            jobs: core::array::from_fn(|role| {
                Box::new(MutexRole {
                    fixture: weak.clone(),
                    scenario,
                    role,
                })
            }),
            completed: AtomicU64::new(0),
            signals: AtomicU64::new(0),
            stale: AtomicU64::new(0),
            prepare_signals: AtomicU64::new(0),
            self_signals: AtomicU64::new(0),
        })
    }
    unsafe fn runtime(&self) -> Pin<&Runtime<16>> {
        self.cpu.check_cpu().unwrap();
        // SAFETY: this private hosted fixture's executor owns the
        // exact pinned Runtime until all callbacks end and bindings detach.
        unsafe { Pin::new_unchecked(&*self.runtime.load(Ordering::Acquire)) }
    }
    fn binding(&self, index: usize) -> Arc<TaskBinding<16>> {
        if let Some(binding) = self.bindings[index].lock().unwrap().clone() {
            return binding;
        }
        // SAFETY: real process stack/CPU, outside entered C/IF0 hooks.
        let binding = unsafe { TaskBinding::new() }.unwrap();
        // SAFETY: the harness keeps the pinned executor through every callback and
        // retirement.
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
        // only increments kept owners, with nonfinal drops afterward.
        self.targets[role]
            .try_lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone()
    }
    fn enqueue(&self, role: usize) {
        let lane = if role == 1 || role == 4 {
            Kind::Notify
        } else {
            Kind::General
        };
        // SAFETY: fixture owns stable job storage until every real callback
        // completes. Enqueue is bounded, with no callback or heap allocation.
        unsafe {
            self.runtime()
                .queue()
                .execute(lane, mutex_role, self.context(role))
        }
        .unwrap();
    }
}
unsafe fn mutex_job<'a>(context: *mut c_void) -> &'a MutexRole {
    // SAFETY: stable boxed role kept by the Queue fixture owner.
    unsafe { &*context.cast::<MutexRole>() }
}
unsafe extern "C" fn mutex_checkpoint(context: *mut c_void, event: u32) {
    // SAFETY: the queue owner keeps this boxed role through the callback.
    let job = unsafe { mutex_job(context) };
    let f = job.fixture.upgrade().unwrap();
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
    let runtime = unsafe { f.runtime() };
    match event {
        1 => {
            f.enqueue(1);
            if job.scenario == 0 {
                f.enqueue(2);
                f.enqueue(3);
            }
        }
        2..=4 => {
            let target = f.target(1);
            let kind = if event == 3 {
                WaitSignal::Fatal
            } else {
                WaitSignal::Interrupt
            };
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
            assert_eq!(
                // SAFETY: this is the entered same-CPU continuation inside `run_scoped`, with
                // the service roots kept.
                unsafe { old.signal(runtime, WaitSignal::Fatal) },
                Err(WorkError::Closed)
            );
            f.stale.fetch_add(1, Ordering::Relaxed);
        }
        6 => f.enqueue(4),
        7 | 8 => {
            let target = f.target(0);
            let kind = if event == 7 {
                WaitSignal::Interrupt
            } else {
                WaitSignal::Fatal
            };
            // SAFETY: entered current posts to its own expected job.
            unsafe { target.signal(runtime, kind) }.unwrap();
            f.self_signals.fetch_add(1, Ordering::Relaxed);
        }
        10 => {
            let target = f.target(1);
            let wake = (*target.wake).clone();
            drop(target);
            // Explicit hosted IRQ model: only the generic atomic
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
    // SAFETY: the queue owner keeps this boxed role through the callback.
    let job = unsafe { mutex_job(context) };
    let f = job.fixture.upgrade().unwrap();
    // SAFETY: the harness keeps the pinned executor through every callback and retirement.
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
    // SAFETY: only shared kept Runtime/owner roots span suspension;
    // call is an immovable stack local until this C body returns.
    unsafe {
        binding.run_scoped(
            runtime,
            stela_linux_mutex_test_run,
            ptr::from_mut(&mut call).cast(),
        )
    }
    .unwrap();
    f.completed.fetch_add(1, Ordering::Relaxed);
}

fn exact_mutex_child(selector: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            selector,
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
    let expected = std::format!("test {selector} ... ok");
    let named = stdout.lines().any(|line| line == expected);
    let one = stdout
        .lines()
        .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    assert!(
        output.status.success() && named && one,
        "mutex child did not execute/pass exactly once ({}):\n{}{}",
        output.status,
        stdout,
        stderr
    );
}
pub(crate) fn run_mutex_child() {
    exact_mutex_child("linux::task::tests::mutex_child");
    exact_mutex_child("linux::task::tests::mutex_quarantine_child");
}

#[test]
#[ignore = "isolation: child"]
fn mutex_child() {
    // SAFETY: isolated canonical allocator registry, same real GlobalAlloc
    // owns ordinary and raw-span allocations and their exact-layout frees.
    assert!(unsafe { crate::linux::heap::register(try_allocate) }.is_ok());
    assert_eq!(core::mem::size_of::<MutexCall>(), 24);
    let dropped = Arc::new(AtomicU64::new(0));
    for scenario in 0..11 {
        let cpu = CpuModel::new();
        let f = MutexFixture::new(cpu.clone(), scenario);
        // SAFETY: the fixture is the queue's owner, and only this test thread produces
        // work.
        let queue = unsafe { Queue::<16>::new(cpu.clone(), f.clone()) }.unwrap();
        let executor = Executor::new_hosted_for_test(queue, stacks(&dropped, 16 * 1024)).unwrap();
        let runtime = executor.runtime();
        f.runtime.store(
            runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>,
            Ordering::Release,
        );
        // SAFETY: guarded stacks and kept fixture/job roots, no
        // C owner/ref survives completion, no native admission is asserted.
        unsafe { runtime.call_foreground(mutex_role, f.context(0), 100000) }.unwrap();
        assert_eq!(
            f.completed.load(Ordering::Relaxed),
            if scenario == 0 { 5 } else { 2 }
        );
        assert_eq!(
            f.prepare_signals.load(Ordering::Relaxed),
            u64::from(scenario == 5)
        );
        assert_eq!(
            f.stale.load(Ordering::Relaxed),
            if scenario == 0 { 2 } else { 0 }
        );
        let expected_signals = match scenario {
            1 | 3 | 4 | 6 | 9 => 1,
            2 => 2,
            _ => 0,
        };
        assert_eq!(f.signals.load(Ordering::Relaxed), expected_signals);
        assert_eq!(
            f.self_signals.load(Ordering::Relaxed),
            if scenario < 7 || scenario == 10 { 2 } else { 0 }
        );
        // All expected-job snapshots are now inert even though metadata is
        // still held. Taking them in process context breaks Arc cycles.
        for slot in &f.targets {
            if let Some(target) = slot.lock().unwrap().take() {
                assert_eq!(target.wake.wake(), Err(WorkError::Closed));
                drop(target);
            }
        }
        assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
        runtime.queue().close().unwrap();
        // SAFETY: the queue is closed and this test thread is the only producer; pending work
        // is a checked refusal.
        assert_eq!(unsafe { runtime.retire() }, Err(WorkError::Pending));
        for slot in &f.bindings {
            if let Some(binding) = slot.lock().unwrap().take() {
                let retained =
                        // SAFETY: the queue is closed and no producer, task or waker still uses
                        // this binding.
                        unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
                assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
                drop(retained);
                // SAFETY: jobs completed; C refs, waiters, signal
                // snapshots and all producer borrows ended independently.
                assert!(unsafe { binding.release_quiescent() }.is_ok());
            }
        }
        // SAFETY: the queue is closed and this test thread is the only producer; pending work
        // is a checked refusal.
        unsafe { runtime.retire() }.unwrap();
        drop(executor);
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            (u64::from(scenario) + 1) * 4
        );
        assert_eq!(quarantined(), 0);
        assert!(!RAW.occupied.load(Ordering::Acquire));
        // SAFETY: the C test hook only checks task state on this thread's entered continuation.
        unsafe { stela_linux_task_test_taskless() };
    }
}

unsafe extern "C" fn quarantine_targets(context: *mut c_void) {
    // No Linux entry is needed for capture/drop mechanics. Runtime still
    // provides current/C task identity on its real guarded stack.
    // SAFETY: the queue owner keeps this boxed role through the callback.
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
#[ignore = "isolation: child"]
fn mutex_quarantine_child() {
    let dropped = Arc::new(AtomicU64::new(0));
    let cpu = CpuModel::new();
    let f = MutexFixture::new(cpu.clone(), 0);
    // SAFETY: the fixture is the queue's owner, and only this test thread produces
    // work.
    let queue = unsafe { Queue::<16>::new(cpu, f.clone()) }.unwrap();
    let executor = Executor::new_hosted_for_test(queue, stacks(&dropped, 16 * 1024)).unwrap();
    let runtime = executor.runtime();
    f.runtime.store(
        runtime.get_ref() as *const Runtime<16> as *mut Runtime<16>,
        Ordering::Release,
    );
    // SAFETY: the callbacks are static, never unwind, and take the fixture the queue keeps
    // until completion.
    unsafe { runtime.call_foreground(quarantine_targets, f.context(0), 100000) }.unwrap();
    runtime.queue().close().unwrap();
    let binding = f.bindings[0].lock().unwrap().take().unwrap();
    // SAFETY: the queue is closed and no producer, task or waker still uses this binding.
    let retained = unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
    drop(retained);
    // The two improper drops kept real metadata owners. A
    // claimed unique release must refuse; no final C free is smuggled into
    // the foreign thread/IRQ model or inferred from task usage alone.
    // SAFETY: the runtime detached this binding and no job or waker still uses it.
    let unreleased = unsafe { binding.release_quiescent() }.err().unwrap();
    assert_eq!(Arc::strong_count(&unreleased), 3);
    drop(unreleased); // nonfinal process-context drop; two kept owners remain
    // SAFETY: the queue is closed and this test thread is the only producer; pending work is a
    // checked refusal.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 4);
    assert_eq!(quarantined(), 2);
}
