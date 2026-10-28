//! Priority dispatch, deboost and wake ordering on switched stacks.
use super::super::super::{
    scheduling::{BasePolicy, SchedulingHandle, Snapshot},
    service,
};
use super::*;
struct Binding {
    id: AtomicU64,
    blocked: AtomicBool,
    late_wake: AtomicBool,
    handle: Mutex<Option<WakeHandle<16>>>,
}
impl Binding {
    fn verify(&self, view: &TaskContext, active: bool) {
        assert_eq!(self.id.load(Ordering::Acquire), view.context_id);
        assert_eq!(
            (view.stack_start..view.stack_end).contains(&context::stack_pointer()),
            active
        );
    }
}
// SAFETY: no C owner or foreign state exists in this hosted scheduler
// fixture. Actual retained Runtime stacks/CPU/tickets remain real; hooks
// perform only bounded metadata checks, never allocation/drop or switching.
unsafe impl SwitchBinding for Binding {
    unsafe fn attach(&self, view: &TaskContext) -> Result<(), WorkError> {
        self.id.store(view.context_id, Ordering::Release);
        self.verify(view, true);
        Ok(())
    }
    unsafe fn still_blocked(&self, view: &TaskContext) -> Result<bool, WorkError> {
        self.verify(view, true);
        Ok(self.blocked.load(Ordering::Acquire))
    }
    unsafe fn leave(&self, view: &TaskContext, reason: LeaveReason) -> Result<(), WorkError> {
        self.verify(view, true);
        if reason == LeaveReason::Blocked && self.late_wake.swap(false, Ordering::AcqRel) {
            self.handle
                .try_lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .wake()
                .unwrap();
        }
        Ok(())
    }
    unsafe fn arrive(&self, view: &TaskContext, _: bool) -> Result<(), WorkError> {
        self.verify(view, true);
        Ok(())
    }
    unsafe fn complete(&self, view: &TaskContext) -> Result<(), WorkError> {
        self.verify(view, true);
        Ok(())
    }
    unsafe fn detach(&self, view: &TaskContext) -> Result<(), WorkError> {
        self.verify(view, false);
        Ok(())
    }
}
struct Clock {
    cpu: Arc<dyn Cpu>,
    start: std::time::Instant,
}
// SAFETY: hosted same-thread monotonic elapsed nanoseconds, no callback.
unsafe impl service::Clock for Clock {
    fn cpu(&self) -> &Arc<dyn Cpu> {
        &self.cpu
    }
    fn now_ns(&self) -> Result<u64, WorkError> {
        self.cpu.check_cpu()?;
        u64::try_from(self.start.elapsed().as_nanos()).map_err(|_| WorkError::Exhausted)
    }
}
struct Idle {
    clock: Arc<dyn service::Clock>,
    thread: thread::Thread,
}
// SAFETY: real same-thread hosted park/event wait using exact elapsed clock;
// no simulated flags change, callback or inline dispatch.
unsafe impl service::Idle for Idle {
    fn clock(&self) -> &Arc<dyn service::Clock> {
        &self.clock
    }
    fn notify(&self) -> Result<(), WorkError> {
        self.thread.unpark();
        Ok(())
    }
    fn wait_until_ns(&self, deadline: Option<u64>) -> Result<(), WorkError> {
        if let Some(deadline) = deadline {
            let now = self.clock.now_ns()?;
            if let Some(delay) = deadline.checked_sub(now) {
                thread::park_timeout(std::time::Duration::from_nanos(delay));
            }
        } else {
            thread::park();
        }
        Ok(())
    }
}
struct Ranked {
    runtime: AtomicU64,
    bindings: [Arc<Binding>; 4],
    handles: Mutex<[Option<SchedulingHandle<16>>; 4]>,
    wakes: Mutex<[Option<WakeHandle<16>>; 4]>,
    domain: Mutex<Option<Arc<service::Domain<16>>>>,
    events: Mutex<Vec<u32>>,
    stop: AtomicBool,
    mode: u64,
}
impl Ranked {
    /// # Safety
    /// setup must have published the live pinned Executor runtime, and that
    /// Executor must remain retained while this reference is used.
    unsafe fn runtime(&self) -> Pin<&Runtime<16>> {
        // SAFETY: setup wrote this pointer from the already pinned Runtime before
        // callback admission. The Executor retains that allocation through every use here.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<16>))
        }
    }
    fn bind(&self, index: usize) {
        // SAFETY: setup published this pinned Runtime pointer before callback admission.
        // The fixture is used while its Executor is live, including all suspended callbacks.
        let r = unsafe { self.runtime() };
        let wake = r.bind_current(self.bindings[index].clone()).unwrap();
        *self.bindings[index].handle.lock().unwrap() = Some(wake.clone());
        self.wakes.lock().unwrap()[index] = Some(wake);
        self.handles.lock().unwrap()[index] = Some(r.scheduling_handle().unwrap());
    }
    fn handle(&self, index: usize) -> SchedulingHandle<16> {
        self.handles.lock().unwrap()[index]
            .as_ref()
            .unwrap()
            .clone()
    }
    fn rank(&self, index: usize, base: BasePolicy, effective: u8, head: bool) {
        let handle = self.handle(index);
        let before = handle.snapshot().unwrap();
        // SAFETY: This same-thread scheduler fixture has no foreign C priority state.
        // The snapshots are serialized here; invalid/closed cases are checked before updates.
        unsafe { handle.update(before, Snapshot { base, effective }, head) }.unwrap();
    }
    fn event(&self, value: u32) {
        self.events.lock().unwrap().push(value);
    }
}
/// # Safety
/// p must be the queue-retained Arc pointer for Ranked; the returned borrow
/// must end before that owner can be released.
unsafe fn ranked<'a>(p: *mut c_void) -> &'a Ranked {
    // SAFETY: The caller supplies the aligned Arc::as_ptr allocation of this fixture
    // type. Its queue retains the Arc while callbacks use this shared reference.
    unsafe { &*p.cast::<Ranked>() }
}
unsafe extern "C" fn timer(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { ranked(p) };
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    let r = unsafe { f.runtime() };
    f.bind(0);
    let domain = f.domain.lock().unwrap().as_ref().unwrap().clone();
    domain.bind_current(r).unwrap();
    // Reserved service base/rank refuses before changing the sidecar.
    let h = f.handle(0);
    let normal = h.snapshot().unwrap();
    assert_eq!(
        // SAFETY: This same-thread scheduler fixture has no foreign C priority state.
        // The snapshots are serialized here; invalid/closed cases are checked before updates.
        unsafe {
            h.update(
                normal,
                Snapshot {
                    base: BasePolicy::Fifo(99),
                    effective: 0,
                },
                false,
            )
        },
        Err(WorkError::Unavailable)
    );
    // Base remains NORMAL; a genuine process-lock donor may still boost
    // effective service priority. Restore it before actual completion.
    let boosted = Snapshot {
        base: BasePolicy::Normal,
        effective: 0,
    };
    // SAFETY: This same-thread scheduler fixture has no foreign C priority state.
    // The snapshots are serialized here; invalid/closed cases are checked before updates.
    unsafe { h.update(normal, boosted, false) }.unwrap();
    // SAFETY: This same-thread scheduler fixture has no foreign C priority state.
    // The snapshots are serialized here; invalid/closed cases are checked before updates.
    unsafe { h.update(boosted, normal, false) }.unwrap();
    while !f.stop.load(Ordering::Acquire) {
        if let Some(batch) = domain.begin(r).unwrap() {
            if f.mode == 3 {
                f.event(100);
            }
            // SAFETY: generic fixture consumer only; no original C timers
            // or IRQ-work storage is admitted by this scheduler test.
            // SAFETY: begin returned this batch for the current service continuation.
            // This generic fixture has no C timer/IRQ storage requiring a foreign callback.
            unsafe { domain.finish(r, batch, None) }.unwrap();
        }
        f.bindings[0].blocked.store(true, Ordering::Release);
        r.park_if_blocked().unwrap();
    }
}
unsafe extern "C" fn low(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { ranked(p) };
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    let r = unsafe { f.runtime() };
    f.bind(1);
    r.yield_now().unwrap();
    let normal = f.handle(1).snapshot().unwrap();
    for (after, head) in [
        (
            Snapshot {
                base: BasePolicy::Fifo(0),
                effective: 0,
            },
            false,
        ),
        (
            Snapshot {
                base: BasePolicy::Normal,
                effective: 119,
            },
            false,
        ),
        (normal, true),
    ] {
        assert_eq!(
            // SAFETY: This same-thread scheduler fixture has no foreign C priority state.
            // The snapshots are serialized here; invalid/closed cases are checked before updates.
            unsafe { f.handle(1).update(normal, after, head) },
            Err(WorkError::Unavailable)
        );
        assert_eq!(f.handle(1).snapshot().unwrap(), normal);
    }
    if f.mode == 2 {
        f.rank(1, BasePolicy::Fifo(60), 39, false);
        f.rank(2, BasePolicy::Fifo(1), 98, false);
        f.rank(3, BasePolicy::Fifo(1), 98, false);
        f.bindings[1].blocked.store(true, Ordering::Release);
        f.bindings[1].late_wake.store(true, Ordering::Release);
        assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
        f.bindings[1].blocked.store(false, Ordering::Release);
        f.event(20);
        f.rank(1, BasePolicy::Normal, 120, false);
        return;
    }
    if f.mode == 1 {
        f.rank(1, BasePolicy::Fifo(60), 0, false); // donated boost over base39
        f.rank(2, BasePolicy::Fifo(60), 39, false);
        f.rank(3, BasePolicy::Fifo(1), 98, false);
        f.rank(1, BasePolicy::Fifo(60), 39, true);
        r.reschedule().unwrap();
        f.event(10); // deboost head before equal B
        r.yield_now().unwrap();
        f.event(13); // yield tail behind equal B
        f.rank(1, BasePolicy::Normal, 120, false);
        return;
    }
    f.rank(1, BasePolicy::Fifo(20), 79, false);
    f.rank(2, BasePolicy::Fifo(60), 39, false);
    f.rank(3, BasePolicy::Fifo(80), 19, false);
    r.reschedule().unwrap();
    f.event(2); // high genuinely blocked; boosted low runs before medium
    assert_eq!(f.handle(1).snapshot().unwrap().effective, 19);
    f.rank(1, BasePolicy::Fifo(20), 79, true); // deboost before actual wake
    f.bindings[3].blocked.store(false, Ordering::Release);
    f.wakes.lock().unwrap()[3].as_ref().unwrap().wake().unwrap();
    r.reschedule().unwrap();
    f.event(5);
    f.rank(1, BasePolicy::Normal, 120, false);
}
unsafe extern "C" fn medium(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { ranked(p) };
    f.bind(2);
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    unsafe { f.runtime() }.yield_now().unwrap();
    if f.mode == 2 {
        f.event(21);
        f.rank(2, BasePolicy::Normal, 120, false);
        return;
    }
    if f.mode == 1 {
        f.event(11);
        // SAFETY: setup published this pinned Runtime pointer before callback admission.
        // The fixture is used while its Executor is live, including all suspended callbacks.
        unsafe { f.runtime() }.reschedule().unwrap();
        f.event(12);
        // SAFETY: setup published this pinned Runtime pointer before callback admission.
        // The fixture is used while its Executor is live, including all suspended callbacks.
        unsafe { f.runtime() }.yield_now().unwrap();
        f.event(14);
        f.rank(2, BasePolicy::Normal, 120, false);
        return;
    }
    f.event(4);
    f.rank(2, BasePolicy::Normal, 120, false);
}
unsafe extern "C" fn high(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { ranked(p) };
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    let r = unsafe { f.runtime() };
    f.bind(3);
    r.yield_now().unwrap();
    if f.mode == 2 {
        f.event(22);
        f.rank(3, BasePolicy::Normal, 120, false);
        return;
    }
    if f.mode == 1 {
        f.event(15);
        f.rank(3, BasePolicy::Normal, 120, false);
        return;
    }
    f.event(1);
    f.rank(1, BasePolicy::Fifo(20), 19, false);
    f.bindings[3].blocked.store(true, Ordering::Release);
    assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
    f.event(3);
    f.rank(3, BasePolicy::Normal, 120, false);
}
unsafe extern "C" fn stale(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { ranked(p) };
    assert_eq!(f.handle(1).snapshot(), Err(WorkError::Closed));
    let before = Snapshot {
        base: BasePolicy::Normal,
        effective: 120,
    };
    assert_eq!(
        // SAFETY: This same-thread scheduler fixture has no foreign C priority state.
        // The snapshots are serialized here; invalid/closed cases are checked before updates.
        unsafe { f.handle(1).update(before, before, false) },
        Err(WorkError::Closed)
    );
    assert_eq!(
        // SAFETY: setup published this pinned Runtime pointer before callback admission.
        // The fixture is used while its Executor is live, including all suspended callbacks.
        unsafe { f.runtime() }
            .scheduling_handle()
            .unwrap()
            .snapshot(),
        Ok(before)
    );
}
unsafe extern "C" fn fifo_peer(p: *mut c_void) {
    // SAFETY: p is this queue's retained Ranked Arc through callback join.
    let f = unsafe { ranked(p) };
    // SAFETY: setup published this retained pinned Runtime before submission.
    let r = unsafe { f.runtime() };
    f.bind(1);
    f.rank(1, BasePolicy::Fifo(60), 39, false);
    for event in 1..=5 {
        f.event(event);
        r.yield_now().unwrap();
    }
    f.rank(1, BasePolicy::Normal, 120, false);
}
unsafe fn normal_peer(p: *mut c_void, index: usize) {
    // SAFETY: caller forwards this queue's retained Ranked Arc and real task index.
    let f = unsafe { ranked(p) };
    f.bind(index);
    // SAFETY: setup published this retained pinned Runtime before submission.
    unsafe { f.runtime() }.yield_now().unwrap();
}
unsafe extern "C" fn normal_peer_two(p: *mut c_void) {
    // SAFETY: queue retains the matching Ranked fixture, whose binding two is idle.
    unsafe { normal_peer(p, 2) };
}
unsafe extern "C" fn normal_peer_three(p: *mut c_void) {
    // SAFETY: queue retains the matching Ranked fixture, whose binding three is idle.
    unsafe { normal_peer(p, 3) };
}
unsafe extern "C" fn firmware_turns(p: *mut c_void) {
    // SAFETY: p is this queue's retained Ranked Arc, and the executor remains
    // pinned with all guarded mappings until every firmware turn has joined.
    let f = unsafe { ranked(p) };
    // SAFETY: setup published the retained pinned Runtime before submission.
    let r = unsafe { f.runtime() };
    for turn in 0..8 {
        assert_eq!(r.firmware_current(), Ok(true));
        assert_eq!(r.service_current(), Ok(false));
        assert!(matches!(r.scheduling_handle(), Err(WorkError::Unavailable)));
        if turn == 1 {
            assert!(
                f.events.lock().unwrap().contains(&100),
                "due Linux service precedes the next firmware turn"
            );
        }
        f.event(90 + turn);
        if turn == 0 {
            f.domain
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .raised_work()
                .unwrap()
                .raise()
                .unwrap();
        }
        r.yield_now().unwrap();
    }
}
#[test]
fn firmware_turns_remain_independent_of_linux_fifo() {
    roundtrip(3);
}
#[test]
fn priority_dispatch_and_wake_order() {
    roundtrip(0);
    roundtrip(1);
    roundtrip(2);
}
fn roundtrip(mode: u64) {
    let cpu = CpuModel::new();
    let f = Arc::new(Ranked {
        runtime: AtomicU64::new(0),
        bindings: core::array::from_fn(|_| {
            Arc::new(Binding {
                id: AtomicU64::new(0),
                blocked: AtomicBool::new(false),
                late_wake: AtomicBool::new(false),
                handle: Mutex::new(None),
            })
        }),
        handles: Mutex::new(core::array::from_fn(|_| None)),
        wakes: Mutex::new(core::array::from_fn(|_| None)),
        domain: Mutex::new(None),
        events: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
        mode,
    });
    // SAFETY: The queue retains the fixture Arc and same-thread CpuModel. setup stores
    // the pinned runtime pointer before admitting any callback that can read it.
    let queue = unsafe { Queue::<16>::new(cpu.clone(), f.clone()) }.unwrap();
    let dropped = Arc::new(AtomicU64::new(0));
    // SAFETY: The hosted x86-64 process has x87/SSE enabled. read_controls only
    // snapshots their control registers into local storage; it performs no privileged access.
    let controls = unsafe { context::read_controls() };
    let executor = Executor {
        runtime: ManuallyDrop::new(
            Runtime::with_reserved_controls(
                queue,
                stacks_count(dropped.clone(), if mode == 3 { 7 } else { 6 }),
                controls,
                true,
                mode == 3,
            )
            .unwrap(),
        ),
    };
    let r = executor.runtime();
    f.runtime
        .store(r.get_ref() as *const Runtime<16> as u64, Ordering::Release);
    let clock: Arc<dyn service::Clock> = Arc::new(Clock {
        cpu: cpu.clone(),
        start: std::time::Instant::now(),
    });
    let idle = Arc::new(Idle {
        clock: clock.clone(),
        thread: thread::current(),
    });
    let domain = service::Domain::new(clock, idle).unwrap();
    r.attach_service_domain(domain.clone()).unwrap();
    *f.domain.lock().unwrap() = Some(domain.clone());
    let p = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: The service callback receives the queue-retained fixture Arc pointer.
    // The pinned executor and its dedicated service stack survive until service join.
    let service = unsafe { r.start_service(timer, p) }.unwrap();
    assert!(r.step().unwrap());
    let firmware = if mode == 3 {
        // SAFETY: the queue retains this Ranked Arc and static callback through
        // all yielded firmware frames, which are joined before stack release.
        Some(unsafe { r.start_firmware(firmware_turns, p) }.unwrap())
    } else {
        None
    };
    let callbacks: [Callback; 3] = if mode == 3 {
        [fifo_peer, normal_peer_two, normal_peer_three]
    } else {
        [low, medium, high]
    };
    let jobs = callbacks
        // SAFETY: The callback and context identify this queue's retained fixture Arc.
        // The owning Executor keeps its pinned runtime/stacks alive while the job is suspended.
        .map(|callback| unsafe { r.queue().execute(Kind::General, callback, p) }.unwrap());
    let mut attempts = 0;
    while jobs
        .iter()
        .chain(firmware.iter())
        .any(|ticket| !r.queue().completed(*ticket).unwrap())
    {
        assert!(attempts < 128);
        assert!(r.step().unwrap());
        attempts += 1;
    }
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|value| *value < 90)
            .collect::<Vec<_>>(),
        match mode {
            0 | 3 => std::vec![1, 2, 3, 4, 5],
            1 => std::vec![10, 11, 12, 13, 14, 15],
            _ => std::vec![20, 21, 22],
        }
    );
    if mode == 3 {
        let events = f.events.lock().unwrap();
        let position = |value| events.iter().position(|event| *event == value).unwrap();
        assert!(
            position(90) < position(5),
            "Linux FIFO cannot starve firmware"
        );
        assert!(
            position(1) < position(97),
            "persistent firmware readiness cannot starve Linux work"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| (90..98).contains(*event))
                .count(),
            8
        );
    }
    // SAFETY: The callback and context identify this queue's retained fixture Arc.
    // The owning Executor keeps its pinned runtime/stacks alive while the job is suspended.
    let reuse = unsafe { r.queue().execute(Kind::General, stale, p) }.unwrap();
    while !r.queue().completed(reuse).unwrap() {
        assert!(r.step().unwrap());
    }
    f.stop.store(true, Ordering::Release);
    domain.stop_producers().unwrap();
    while !r.queue().completed(service).unwrap() {
        assert!(r.step().unwrap());
    }
    // SAFETY: stop_producers ran and the service ticket completed above. No
    // external producer can publish more work; this test still retains the domain Arc.
    unsafe { domain.retire() }.unwrap();
    for binding in &f.bindings {
        let retained =
            // SAFETY: Binding storage is retained by the fixture on the dispatcher thread.
            // The runtime checks completed/pending state before returning or releasing that owner.
            unsafe { r.detach_binding(ContextId(binding.id.load(Ordering::Acquire))) }.unwrap();
        drop(retained);
        binding.handle.lock().unwrap().take();
    }
    f.handles.lock().unwrap().iter_mut().for_each(|handle| {
        handle.take();
    });
    f.wakes.lock().unwrap().iter_mut().for_each(|wake| {
        wake.take();
    });
    f.domain.lock().unwrap().take();
    r.queue().close().unwrap();
    // SAFETY: This test has no asynchronous producers and calls on the dispatcher.
    // Completed jobs/bindings permit retirement; pending continuations keep their owners.
    unsafe { r.retire() }.unwrap();
    drop(domain);
    drop(executor);
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        if mode == 3 { 7 } else { 6 }
    );
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
}
