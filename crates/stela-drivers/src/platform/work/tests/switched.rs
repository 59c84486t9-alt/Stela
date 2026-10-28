//! Hosted context switching on guarded POSIX mappings.
use super::*;
use core::arch::asm;
use std::sync::Mutex;
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
    stacks_count(dropped, 4)
}
fn stacks_count(dropped: Arc<AtomicU64>, count: usize) -> Vec<Stack> {
    (0..count)
        .map(|_| {
            #[cfg(target_os = "macos")]
            let anonymous = 0x1000;
            #[cfg(not(target_os = "macos"))]
            let anonymous = 0x20;
            let bytes = 128 * 1024 + 4096;
            let base = unsafe { mmap(core::ptr::null_mut(), bytes, 3, 2 | anonymous, -1, 0) };
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
mod ranked;

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
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<16>))
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
    setup_with_service(false)
}
fn setup_with_service(
    reserve_service: bool,
) -> (Executor<16>, Arc<Fixture>, Arc<CpuModel>, Arc<AtomicU64>) {
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
    let runtime = Runtime::with_service_controls(
        q,
        stacks_count(dropped.clone(), if reserve_service { 5 } else { 4 }),
        unsafe { context::read_controls() },
        reserve_service,
    )
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
unsafe extern "C" fn reserved_service(p: *mut c_void) {
    let f = unsafe { fixture(p) };
    let runtime = unsafe { f.runtime() };
    assert_eq!(runtime.service_current(), Ok(true));
    f.event(50);
    runtime.yield_now().unwrap();
    assert_eq!(runtime.service_current(), Ok(true));
    f.event(51);
}
#[test]
fn optional_service_owns_a_fifth_distinct_guarded_stack_and_cannot_use_default_lane() {
    let (ordinary, _, _, ordinary_dropped) = setup();
    let runtime = ordinary.runtime();
    // SAFETY: rejected before admission; no callback/context is retained.
    assert_eq!(
        unsafe { runtime.start_service(noop, core::ptr::null_mut()) },
        Err(WorkError::Unavailable)
    );
    runtime.queue().close().unwrap();
    unsafe { runtime.retire() }.unwrap();
    drop(ordinary);
    assert_eq!(ordinary_dropped.load(Ordering::Relaxed), 4);

    let (executor, f, cpu, dropped) = setup_with_service(true);
    let runtime = executor.runtime();
    let context = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: fixture retains callback/context/code through actual join.
    let service = unsafe { runtime.start_service(reserved_service, context) }.unwrap();
    assert!(f.events.lock().unwrap().is_empty());
    unsafe { runtime.call_foreground(foreground, context, 10000) }.unwrap();
    assert!(runtime.queue().completed(service).unwrap());
    assert_eq!(
        unsafe { runtime.start_service(reserved_service, context) },
        Err(WorkError::Busy)
    );
    let events = f.events.lock().unwrap();
    let service_id = events.iter().find(|event| event.0 == 50).unwrap().1;
    assert_eq!(
        events.iter().find(|event| event.0 == 51).unwrap().1,
        service_id
    );
    let mut ids: Vec<_> = events.iter().map(|event| event.1).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        5,
        "Foreground/Notify/service/two General identities"
    );
    drop(events);
    runtime.queue().close().unwrap();
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 5);
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
}
#[test]
fn actual_x86_continuations_have_distinct_stacks_ids_fifo_and_control_state() {
    let (executor, f, cpu, dropped) = setup();
    let r = executor.runtime();
    assert_eq!(r.current_id(), Err(WorkError::Unavailable));
    let original = unsafe { context::read_controls() };
    unsafe { r.call_foreground(foreground, Arc::as_ptr(&f) as *mut c_void, 10000) }.unwrap();
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
        let result = Runtime::with_controls(view.clone(), stacks(dropped.clone()), unsafe {
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
            executor
                .runtime()
                .call_foreground(suspended, Arc::as_ptr(&f) as *mut c_void, 20)
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
mod bound;
