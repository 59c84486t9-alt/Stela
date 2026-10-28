//! Independent firmware/Linux reservation on genuine hosted guarded stacks.
use super::*;

pub(super) struct Parked {
    id: AtomicU64,
    blocked: AtomicBool,
}
impl Parked {
    fn verify(&self, view: &TaskContext, active: bool) {
        assert_eq!(view.context_id, self.id.load(Ordering::Acquire));
        assert_eq!(
            (view.stack_start..view.stack_end).contains(&context::stack_pointer()),
            active
        );
    }
}
// SAFETY: this hosted fixture has no C task or producer. It validates each real
// continuation's identity/RSP; hooks touch only retained atomics, never switch,
// allocate, mutate roots or release an owner. Final detach follows actual join.
unsafe impl SwitchBinding for Parked {
    unsafe fn attach(&self, view: &TaskContext) -> Result<(), WorkError> {
        self.id.store(view.context_id, Ordering::Release);
        self.verify(view, true);
        Ok(())
    }
    unsafe fn still_blocked(&self, view: &TaskContext) -> Result<bool, WorkError> {
        self.verify(view, true);
        Ok(self.blocked.load(Ordering::Acquire))
    }
    unsafe fn leave(&self, view: &TaskContext, _: LeaveReason) -> Result<(), WorkError> {
        self.verify(view, true);
        Ok(())
    }
    unsafe fn arrive(&self, view: &TaskContext, _: bool) -> Result<(), WorkError> {
        self.verify(view, true);
        Ok(())
    }
    unsafe fn complete(&self, view: &TaskContext) -> Result<(), WorkError> {
        self.verify(view, true);
        assert!(!self.blocked.load(Ordering::Acquire));
        Ok(())
    }
    unsafe fn detach(&self, view: &TaskContext) -> Result<(), WorkError> {
        self.verify(view, false);
        Ok(())
    }
}

unsafe extern "C" fn occupy_general(p: *mut c_void) {
    // SAFETY: the callback receives this queue's retained Fixture allocation.
    let f = unsafe { fixture(p) };
    // SAFETY: setup published this pinned Runtime, retained until join below.
    let runtime = unsafe { f.runtime() };
    assert_eq!(runtime.service_current(), Ok(false));
    assert_eq!(runtime.firmware_current(), Ok(false));
    let binding = Arc::new(Parked {
        id: AtomicU64::new(0),
        blocked: AtomicBool::new(true),
    });
    let wake = runtime.bind_current(binding.clone()).unwrap();
    f.parked.lock().unwrap().push((binding, wake));
    f.event(70);
    assert_eq!(runtime.park_if_blocked(), Ok(ParkOutcome::Resumed));
    assert!(f.done.load(Ordering::Acquire));
    f.event(71);
}
unsafe extern "C" fn firmware(p: *mut c_void) {
    // SAFETY: the callback receives this queue's retained Fixture allocation.
    let f = unsafe { fixture(p) };
    // SAFETY: setup published this pinned Runtime, retained until join below.
    let runtime = unsafe { f.runtime() };
    for event in [60, 61] {
        assert_eq!(runtime.firmware_current(), Ok(true));
        assert_eq!(runtime.service_current(), Ok(false));
        f.event(event);
        runtime.yield_now().unwrap();
    }
    f.done.store(true, Ordering::Release);
    for (binding, wake) in &*f.parked.lock().unwrap() {
        binding.blocked.store(false, Ordering::Release);
        wake.wake().unwrap();
    }
}
unsafe extern "C" fn queued_general(p: *mut c_void) {
    // SAFETY: the callback receives this queue's retained Fixture allocation.
    let f = unsafe { fixture(p) };
    assert!(f.done.load(Ordering::Acquire));
    f.event(80);
}

#[test]
fn general_saturation_preserves_both_service_continuations() {
    let (executor, f, cpu, dropped) = setup_with_reservations(true, true);
    let runtime = executor.runtime();
    let p = Arc::as_ptr(&f) as *mut c_void;
    assert_eq!(runtime.firmware_current(), Err(WorkError::Unavailable));
    for _ in 0..2 {
        // SAFETY: queue retains f, and executor retains runtime/stacks through join.
        unsafe { runtime.queue.execute(Kind::General, occupy_general, p) }.unwrap();
        assert_eq!(runtime.step(), Ok(true));
    }
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.0 == 70)
            .count(),
        2
    );
    for _ in 0..12 {
        // SAFETY: the same retained Fixture owns all callback state until retirement.
        unsafe { runtime.queue.execute(Kind::General, queued_general, p) }.unwrap();
    }
    assert_eq!(
        // SAFETY: Full admission retains no callback; the fixture remains live anyway.
        unsafe { runtime.queue.execute(Kind::General, queued_general, p) },
        Err(WorkError::Full)
    );
    // SAFETY: both static callbacks use the retained Fixture and return before retirement.
    let linux = unsafe { runtime.start_service(reserved_service, p) }.unwrap();
    // SAFETY: firmware's repeated yields keep its exact owned continuation alive.
    let fw = unsafe { runtime.start_firmware(firmware, p) }.unwrap();
    assert_eq!(
        f.events.lock().unwrap().len(),
        2,
        "submission is never inline"
    );
    runtime.drain(10000).unwrap();
    assert_eq!(runtime.queue.completed(linux), Ok(true));
    assert_eq!(runtime.queue.completed(fw), Ok(true));
    assert_eq!(
        // SAFETY: rejection retains no callback; Fixture and code remain live regardless.
        unsafe { runtime.start_firmware(firmware, p) },
        Err(WorkError::Busy)
    );
    let events = f.events.lock().unwrap();
    let linux_id = events.iter().find(|e| e.0 == 50).unwrap().1;
    let firmware_id = events.iter().find(|e| e.0 == 60).unwrap().1;
    assert_ne!(linux_id, firmware_id);
    assert_eq!(events.iter().find(|e| e.0 == 51).unwrap().1, linux_id);
    assert_eq!(events.iter().find(|e| e.0 == 61).unwrap().1, firmware_id);
    for event in events.iter().filter(|e| matches!(e.0, 70 | 71 | 80)) {
        assert_ne!(event.1, linux_id);
        assert_ne!(event.1, firmware_id);
    }
    assert_eq!(events.iter().filter(|e| e.0 == 71).count(), 2);
    assert_eq!(events.iter().filter(|e| e.0 == 80).count(), 12);
    drop(events);
    for (binding, wake) in f.parked.lock().unwrap().drain(..) {
        #[cfg(feature = "linux-kernel")]
        assert_eq!(wake.service_reserved(), Ok(false));
        // SAFETY: callback joined after the predicate was cleared and this exact
        // wake delivered. No external producer or C entry references the binding.
        drop(
            unsafe { runtime.detach_binding(ContextId(binding.id.load(Ordering::Acquire))) }
                .unwrap(),
        );
        drop(wake);
    }
    runtime.queue.close().unwrap();
    // SAFETY: all jobs joined, with no external producer/binding or live callback.
    unsafe { runtime.retire() }.unwrap();
    assert_eq!(
        // SAFETY: retired runtime rejects callback admission before retaining anything.
        unsafe { runtime.start_firmware(firmware, p) },
        Err(WorkError::Closed)
    );
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 6);
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
}

#[test]
fn legacy_constructors_do_not_reserve_firmware() {
    for linux in [false, true] {
        let (executor, _, _, dropped) = setup_with_service(linux);
        let runtime = executor.runtime();
        assert_eq!(
            // SAFETY: unreserved constructor rejects before retaining static noop/null.
            unsafe { runtime.start_firmware(noop, core::ptr::null_mut()) },
            Err(WorkError::Unavailable)
        );
        runtime.queue.close().unwrap();
        // SAFETY: no jobs or foreign producers were admitted on this dispatcher.
        unsafe { runtime.retire() }.unwrap();
        drop(executor);
        assert_eq!(dropped.load(Ordering::Relaxed), if linux { 5 } else { 4 });
    }
}

#[test]
fn occupied_reserved_slots_preserve_preexisting_jobs_on_failure() {
    let cpu = CpuModel::new();
    // SAFETY: all callbacks below are static noop with null contexts; this owner
    // and qualified CpuModel cover every real queued callback and stack switch.
    let queue = unsafe { Queue::<16>::new(cpu.clone(), Arc::new(())) }.unwrap();
    let mut tickets = Vec::new();
    for _ in 0..16 {
        // SAFETY: static noop ignores its null context and returns without resources.
        tickets.push(unsafe { queue.execute(Kind::General, noop, core::ptr::null_mut()) }.unwrap());
    }
    let dropped = Arc::new(AtomicU64::new(0));
    // SAFETY: unprivileged snapshot of this hosted process's enabled x87/SSE controls.
    let controls = unsafe { context::read_controls() };
    assert!(matches!(
        Runtime::with_reserved_controls(
            queue.clone(),
            stacks_count(dropped.clone(), 6),
            controls,
            true,
            true
        ),
        Err(WorkError::Busy)
    ));
    assert_eq!(dropped.load(Ordering::Relaxed), 6);
    assert!(!queue.executor_claimed.load(Ordering::Acquire));
    for ticket in &tickets {
        assert_eq!(queue.completed(*ticket), Ok(false));
    }
    let executor = Executor {
        runtime: ManuallyDrop::new(
            Runtime::with_controls(queue.clone(), stacks_count(dropped.clone(), 4), controls)
                .unwrap(),
        ),
    };
    let runtime = executor.runtime();
    runtime.drain(10000).unwrap();
    for ticket in tickets {
        assert_eq!(queue.completed(ticket), Ok(true));
    }
    queue.close().unwrap();
    // SAFETY: every preexisting noop joined; no binding or external producer exists.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 10);
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
}

#[test]
fn both_services_require_ordinary_admission_capacity() {
    let cpu = CpuModel::new();
    // SAFETY: no callbacks are admitted; owner covers this bounded constructor test.
    let queue = unsafe { Queue::<2>::new(cpu.clone(), Arc::new(())) }.unwrap();
    let dropped = Arc::new(AtomicU64::new(0));
    // SAFETY: unprivileged snapshot of this hosted process's enabled x87/SSE controls.
    let controls = unsafe { context::read_controls() };
    assert!(matches!(
        Runtime::with_reserved_controls(
            queue.clone(),
            stacks_count(dropped.clone(), 6),
            controls,
            true,
            true
        ),
        Err(WorkError::Unavailable)
    ));
    assert!(!queue.executor_claimed.load(Ordering::Acquire));
    assert_eq!(dropped.load(Ordering::Relaxed), 6);
    queue.close().unwrap();
    // SAFETY: queue never admitted a producer or callback, and construction failed.
    unsafe { queue.retire() }.unwrap();
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
}
