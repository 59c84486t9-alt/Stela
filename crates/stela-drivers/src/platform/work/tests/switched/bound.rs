//! Task binding, cancellation and wake races on switched stacks.
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
        assert!((context.stack_start..context.stack_end).contains(&context.stack_pointer));
        assert_eq!(context.guard_end, context.stack_start);
        assert!(context.guard_end - context.guard_start >= 4096);
        assert_eq!(
            (context.stack_start..context.stack_end).contains(&context::stack_pointer()),
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
    unsafe fn leave(&self, context: &TaskContext, reason: LeaveReason) -> Result<(), WorkError> {
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
            if let Err(error) = self.handle.try_lock().unwrap().as_ref().unwrap().wake() {
                self.cpu.fatal(error);
            }
        }
        Ok(())
    }
    unsafe fn arrive(&self, context: &TaskContext, new_job: bool) -> Result<(), WorkError> {
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
        if self.refs.load(Ordering::Acquire) != 1 || self.sequence.load(Ordering::Acquire) != 0 {
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
    /// # Safety
    /// setup must have published the live pinned Executor runtime, and that
    /// Executor must remain retained while this reference is used.
    unsafe fn runtime(&self) -> Pin<&Runtime<16>> {
        // SAFETY: test Queue retains this fixture; actual executor
        // allocation stays pinned/owned through completion/quarantine.
        // SAFETY: setup wrote this pointer from the already pinned Runtime before
        // callback admission. The Executor retains that allocation through every use here.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<16>))
        }
    }
    fn event(&self, n: u64) {
        // SAFETY: setup published this pinned Runtime pointer before callback admission.
        // The fixture is used while its Executor is live, including all suspended callbacks.
        let runtime = unsafe { self.runtime() };
        let context = runtime.current_context().unwrap();
        assert_eq!(
            context.context_id,
            self.globals.current.load(Ordering::Acquire)
        );
        self.events
            .lock()
            .unwrap()
            .push((n, context.context_id, context::stack_pointer()));
    }
    fn bind(&self, index: usize) {
        let binding = self.bindings[index].clone();
        // SAFETY: setup published this pinned Runtime pointer before callback admission.
        // The fixture is used while its Executor is live, including all suspended callbacks.
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
            // SAFETY: Binding storage is retained by the fixture on the dispatcher thread.
            // The runtime checks completed/pending state before returning or releasing that owner.
            let retained = unsafe { self.runtime().detach_binding(ContextId(id)) }.unwrap();
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
    // SAFETY: The queue retains the fixture Arc and same-thread CpuModel. setup stores
    // the pinned runtime pointer before admitting any callback that can read it.
    let queue = unsafe { Queue::<16>::new(cpu, f.clone()) }.unwrap();
    let dropped = Arc::new(AtomicU64::new(0));
    let executor = Executor::new_hosted_for_test(queue, stacks(dropped.clone())).unwrap();
    f.runtime.store(
        executor.runtime().get_ref() as *const Runtime<16> as u64,
        Ordering::Release,
    );
    (executor, f, dropped)
}
/// # Safety
/// p must be the queue-retained Arc pointer for BoundFixture; the returned borrow
/// must end before that owner can be released.
unsafe fn bound<'a>(p: *mut c_void) -> &'a BoundFixture {
    // SAFETY: The caller supplies the aligned Arc::as_ptr allocation of this fixture
    // type. Its queue retains the Arc while callbacks use this shared reference.
    unsafe { &*p.cast::<BoundFixture>() }
}
unsafe extern "C" fn park_until_cancelled(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { bound(p) };
    f.bind(0);
    let binding = &f.bindings[0];
    binding.enter(1, 0x200);
    binding.blocked.store(true, Ordering::Release);
    binding.prepared.store(true, Ordering::Release);
    f.event(1);
    assert_eq!(
        // SAFETY: setup published this pinned Runtime pointer before callback admission.
        // The fixture is used while its Executor is live, including all suspended callbacks.
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
fn blocked_task_cancel_and_retirement() {
    let (executor, f, dropped) = bound_setup();
    let r = executor.runtime();
    let p = Arc::as_ptr(&f) as *mut c_void;
    assert_eq!(r.current_context(), Err(WorkError::Unavailable));
    assert_eq!(r.park_if_blocked(), Err(WorkError::Unavailable));
    assert_eq!(
        // SAFETY: The context is the queue-retained fixture Arc pointer for this callback.
        // The Executor keeps its pinned runtime and guarded stacks through join or quarantine.
        unsafe { r.call_foreground(park_until_cancelled, p, 10000) },
        Err(WorkError::Pending)
    );
    assert!(!r.step().unwrap());
    assert_eq!(r.drain(10000), Err(WorkError::Pending));
    // SAFETY: This test has no asynchronous producers and calls on the dispatcher.
    // Completed jobs/bindings permit retirement; pending continuations keep their owners.
    assert_eq!(unsafe { r.retire() }, Err(WorkError::Pending));
    let handle = f.bindings[0]
        .handle
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(
        // SAFETY: Binding storage is retained by the fixture on the dispatcher thread.
        // The runtime checks completed/pending state before returning or releasing that owner.
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
        // SAFETY: Binding storage is retained by the fixture on the dispatcher thread.
        // The runtime checks completed/pending state before returning or releasing that owner.
        unsafe { r.detach_binding(handle.context_id()) }.err(),
        Some(WorkError::Pending)
    );
    // SAFETY: This test has no asynchronous producers and calls on the dispatcher.
    // Completed jobs/bindings permit retirement; pending continuations keep their owners.
    assert_eq!(unsafe { r.retire() }, Err(WorkError::Pending));
    f.bindings[0].refs.store(1, Ordering::Release);
    f.detach_all();
    // SAFETY: This test has no asynchronous producers and calls on the dispatcher.
    // Completed jobs/bindings permit retirement; pending continuations keep their owners.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Acquire), 4);
    assert_eq!(handle.wake(), Err(WorkError::Closed));
    drop(handle);
}
unsafe extern "C" fn peer_waiter(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { bound(p) };
    f.bind(1);
    let binding = &f.bindings[1];
    binding.enter(1, 0x200);
    binding.blocked.store(true, Ordering::Release);
    binding.prepared.store(true, Ordering::Release);
    f.event(20);
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    unsafe { f.runtime() }.park_if_blocked().unwrap();
    assert!(f.cancelled.load(Ordering::Acquire));
    assert_eq!(f.data.load(Ordering::Acquire), 99);
    assert_eq!(f.globals.preempt.load(Ordering::Acquire), 1);
    f.event(21);
    binding.exit();
}
unsafe extern "C" fn peer_waker(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { bound(p) };
    f.bind(0);
    let binding = &f.bindings[0];
    binding.enter(3, 0);
    f.event(10);
    // SAFETY: the retained fixture owns p and its guarded-stack
    // Runtime until this queued peer completes on the same CPU.
    // SAFETY: The callback and context identify this queue's retained fixture Arc.
    // The owning Executor keeps its pinned runtime/stacks alive while the job is suspended.
    unsafe { f.runtime().queue.execute(Kind::General, peer_waiter, p) }.unwrap();
    binding.prepared.store(true, Ordering::Release);
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    unsafe { f.runtime() }.yield_now().unwrap();
    assert_eq!(f.globals.preempt.load(Ordering::Acquire), 3);
    assert_eq!(f.globals.virtual_irq.load(Ordering::Acquire), 0);
    f.event(11);
    // Pending peers are blocked; drain returns, it cannot poll them.
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    assert_eq!(unsafe { f.runtime() }.drain(10000), Err(WorkError::Pending));
    f.data.store(99, Ordering::Release);
    f.cancelled.store(true, Ordering::Release);
    f.bindings[1].blocked.store(false, Ordering::Release);
    f.bindings[1].wake();
    binding.prepared.store(true, Ordering::Release);
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    unsafe { f.runtime() }.yield_now().unwrap();
    assert_eq!(f.globals.preempt.load(Ordering::Acquire), 3);
    binding.exit();
    f.event(12);
}
#[test]
fn binding_state_survives_switch() {
    let (executor, f, dropped) = bound_setup();
    let r = executor.runtime();
    // SAFETY: The context is the queue-retained fixture Arc pointer for this callback.
    // The Executor keeps its pinned runtime and guarded stacks through join or quarantine.
    unsafe { r.call_foreground(peer_waker, Arc::as_ptr(&f) as *mut c_void, 10000) }.unwrap();
    let events = f.events.lock().unwrap();
    let pos = |n| events.iter().position(|e| e.0 == n).unwrap();
    assert!(pos(10) < pos(20) && pos(20) < pos(11) && pos(11) < pos(21) && pos(21) < pos(12));
    assert_eq!(events[pos(10)].1, events[pos(11)].1);
    assert_ne!(events[pos(10)].1, events[pos(20)].1);
    assert_ne!(events[pos(10)].2, events[pos(20)].2);
    drop(events);
    assert_eq!(f.globals.current.load(Ordering::Acquire), 0);
    f.detach_all();
    // SAFETY: This test has no asynchronous producers and calls on the dispatcher.
    // Completed jobs/bindings permit retirement; pending continuations keep their owners.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Acquire), 4);
}
unsafe extern "C" fn races_and_refusals(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { bound(p) };
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
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
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue retains that owner across every suspension and callback return.
    let f = unsafe { bound(p) };
    let binding = &f.bindings[0];
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    let handle = unsafe { f.runtime() }.wake_handle().unwrap();
    assert_eq!(
        handle.sequence(),
        binding.handle.lock().unwrap().as_ref().unwrap().sequence()
    );
    assert_eq!(
        // SAFETY: setup published this pinned Runtime pointer before callback admission.
        // The fixture is used while its Executor is live, including all suspended callbacks.
        unsafe { f.runtime() }.current_id().unwrap(),
        handle.context_id()
    );
    binding.enter(0, 0x200);
    f.event(31);
    binding.exit();
}
#[test]
fn wake_races_and_worker_reuse() {
    let (executor, f, dropped) = bound_setup();
    let r = executor.runtime();
    let p = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: The context is the queue-retained fixture Arc pointer for this callback.
    // The Executor keeps its pinned runtime and guarded stacks through join or quarantine.
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
    // SAFETY: The context is the queue-retained fixture Arc pointer for this callback.
    // The Executor keeps its pinned runtime and guarded stacks through join or quarantine.
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
    // SAFETY: This test has no asynchronous producers and calls on the dispatcher.
    // Completed jobs/bindings permit retirement; pending continuations keep their owners.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Acquire), 4);
    drop(old);
}
#[test]
fn blocked_executor_quarantine() {
    let (executor, f, dropped) = bound_setup();
    let r = executor.runtime();
    assert_eq!(
        // SAFETY: The context is the queue-retained fixture Arc pointer for this callback.
        // The Executor keeps its pinned runtime and guarded stacks through join or quarantine.
        unsafe { r.call_foreground(park_until_cancelled, Arc::as_ptr(&f) as *mut c_void, 10000,) },
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
mod saturated_drain;
