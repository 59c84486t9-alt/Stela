//! Named-role admission/progress on real guarded hosted continuations.
//! CPU/IRQ/root state is a model; this never installs native producer services.
extern crate std;
use super::super::*;
use std::sync::Mutex;

struct Binding {
    id: AtomicU64,
    blocked: AtomicBool,
}
impl Binding {
    fn verify(&self, view: &TaskContext, active: bool) {
        assert_eq!(view.context_id, self.id.load(Ordering::Acquire));
        assert_eq!(
            (view.stack_start..view.stack_end).contains(&context::stack_pointer()),
            active
        );
    }
}
// SAFETY: real same-thread hosted frames are retained by the executor. Hooks
// only inspect identity/stack and atomics; no allocation, owner drop or switch.
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
struct Scene {
    runtime: AtomicU64,
    blocked: Mutex<Vec<(u8, Arc<Binding>, WakeHandle<32>)>>,
    events: Mutex<Vec<(u8, ContextId, Option<FirmwareRole>)>>,
}
impl Scene {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            runtime: AtomicU64::new(0),
            blocked: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
        })
    }
    fn runtime(&self) -> Pin<&Runtime<32>> {
        // SAFETY: setup publishes the live pinned executor before admission;
        // every fixture use ends before successful retirement and executor drop.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<32>))
        }
    }
    fn event(&self, tag: u8) {
        let r = self.runtime();
        self.events.lock().unwrap().push((
            tag,
            r.current_id().unwrap(),
            r.firmware_role_current().unwrap(),
        ));
    }
    fn release(&self, tag: Option<u8>) {
        for (kind, binding, wake) in &*self.blocked.lock().unwrap() {
            if tag.is_none() || tag == Some(*kind) {
                binding.blocked.store(false, Ordering::Release);
                wake.wake().unwrap();
            }
        }
    }
    fn finish(&self) {
        let r = self.runtime();
        r.drain(r.queue.cpu.ticks() + 1_000_000_000).unwrap();
        for (_, _, wake) in core::mem::take(&mut *self.blocked.lock().unwrap()) {
            // SAFETY: every callback completed and no foreign producer/task exists.
            // The exact retained binding is idle and this fixture still owns it.
            drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
        }
        // SAFETY: all fixture sources are stopped, callbacks joined and bindings detached.
        unsafe { r.retire() }.unwrap();
    }
}
unsafe fn scene<'a>(p: *mut c_void) -> &'a Scene {
    // SAFETY: every caller supplies this queue-retained Scene Arc allocation.
    unsafe { &*p.cast::<Scene>() }
}
unsafe fn block(p: *mut c_void, tag: u8, role: Option<FirmwareRole>) {
    // SAFETY: callback forwards the matching queue-retained Scene pointer.
    let f = unsafe { scene(p) };
    let r = f.runtime();
    assert_eq!(r.firmware_role_current(), Ok(role));
    assert_eq!(r.service_current(), Ok(tag == 1));
    let binding = Arc::new(Binding {
        id: AtomicU64::new(0),
        blocked: AtomicBool::new(true),
    });
    let wake = r.bind_current(binding.clone()).unwrap();
    f.blocked.lock().unwrap().push((tag, binding, wake));
    f.event(tag);
    assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
    f.event(tag + 100);
}
unsafe extern "C" fn general(p: *mut c_void) {
    /* SAFETY: matching retained fixture; no role grant. */
    unsafe { block(p, 0, None) };
}
unsafe extern "C" fn service(p: *mut c_void) {
    /* SAFETY: matching retained fixture on Linux service. */
    unsafe { block(p, 1, None) };
}
unsafe extern "C" fn control(p: *mut c_void) {
    /* SAFETY: matching retained fixture on short control lane. */
    unsafe { block(p, 2, Some(FirmwareRole::Control)) };
}
unsafe extern "C" fn portal(p: *mut c_void) {
    /* SAFETY: matching retained fixture on portal worker. */
    unsafe { block(p, 3, Some(FirmwareRole::PortalAml)) };
}
unsafe extern "C" fn notify(p: *mut c_void) {
    /* SAFETY: matching retained fixture on Notify worker. */
    unsafe { block(p, 4, Some(FirmwareRole::Notify)) };
}
unsafe extern "C" fn gpe(p: *mut c_void) {
    /* SAFETY: matching retained fixture on serial GPE worker. */
    unsafe { block(p, 5, Some(FirmwareRole::Gpe)) };
}
unsafe extern "C" fn foreground(p: *mut c_void) {
    /* SAFETY: matching retained fixture on foreground. */
    unsafe { block(p, 6, None) };
}
unsafe extern "C" fn marker(p: *mut c_void) {
    // SAFETY: queue retains this exact Scene through callback completion.
    let f = unsafe { scene(p) };
    assert_eq!(
        f.runtime().firmware_role_current(),
        Ok(Some(FirmwareRole::Gpe))
    );
    f.event(50);
}
unsafe extern "C" fn rejected(p: *mut c_void) {
    /* SAFETY: fixture remains live even if an incorrect admission occurred. */
    unsafe { scene(p) }.event(99);
}
unsafe extern "C" fn signal_portal(p: *mut c_void) {
    // SAFETY: callback receives this retained Scene on a distinct actual worker.
    let f = unsafe { scene(p) };
    assert_eq!(
        f.runtime().firmware_role_current(),
        Ok(Some(FirmwareRole::PortalAml))
    );
    f.event(8);
    f.release(Some(3));
}
unsafe extern "C" fn signal_notify(p: *mut c_void) {
    // SAFETY: callback receives this retained Scene on a distinct actual worker.
    let f = unsafe { scene(p) };
    assert_eq!(
        f.runtime().firmware_role_current(),
        Ok(Some(FirmwareRole::Notify))
    );
    f.event(7);
    f.release(Some(4));
}
fn setup() -> (
    Executor<32>,
    Arc<Scene>,
    Arc<test_support::CpuModel>,
    Arc<core::sync::atomic::AtomicUsize>,
) {
    let f = Scene::new();
    let (executor, cpu, dropped) = test_support::executor(f.clone());
    f.runtime.store(
        executor.runtime().get_ref() as *const Runtime<32> as u64,
        Ordering::Release,
    );
    (executor, f, cpu, dropped)
}
#[test]
fn all_roles_remain_distinct_when_general_workers_are_parked() {
    let (executor, f, cpu, dropped) = setup();
    let r = executor.runtime();
    let p = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: static callbacks use the queue-retained Scene until actual join.
    unsafe { r.start_service(service, p) }.unwrap();
    // SAFETY: static short control fixture/context survives its parked frame.
    unsafe { r.start_firmware(control, p) }.unwrap();
    for _ in 0..8 {
        /* SAFETY: queue retains Scene and all callbacks finish before retirement. */
        unsafe { r.queue.execute(Kind::General, general, p) }.unwrap();
    }
    for _ in 0..2 {
        // SAFETY: each accepted portal callback is covered by Scene's retained lifetime.
        unsafe { r.queue.execute_portal(portal, p) }.unwrap();
        // SAFETY: each accepted Notify callback is covered by Scene's retained lifetime.
        unsafe { r.queue.execute(Kind::Notify, notify, p) }.unwrap();
    }
    // SAFETY: GPE context remains retained independently from the other lanes.
    unsafe { r.queue.execute_gpe(gpe, p) }.unwrap();
    assert!(f.events.lock().unwrap().is_empty());
    assert_eq!(
        // SAFETY: foreground callback/context remain live through pending and resume.
        unsafe { r.call_foreground(foreground, p, r.queue.cpu.ticks() + 1_000_000_000) },
        Err(WorkError::Pending)
    );
    assert_eq!(f.blocked.lock().unwrap().len(), 16);
    assert_eq!(
        // SAFETY: Full must reject before retaining this valid static callback/context.
        unsafe { r.queue.execute_portal(rejected, p) },
        Err(WorkError::Full)
    );
    assert_eq!(
        // SAFETY: both Notify workers are genuinely blocked; rejection transfers nothing.
        unsafe { r.queue.execute(Kind::Notify, rejected, p) },
        Err(WorkError::Full)
    );
    // SAFETY: pending GPE callback uses the same retained Scene until serial execution.
    let pending = unsafe { r.queue.execute_gpe(marker, p) }.unwrap();
    assert_eq!(r.step(), Ok(false));
    assert_eq!(r.queue.completed(pending), Ok(false));
    r.queue.close().unwrap();
    assert_eq!(
        // SAFETY: closed admission must not retain this valid callback/context.
        unsafe { r.queue.execute_portal(rejected, p) },
        Err(WorkError::Closed)
    );
    f.release(None);
    f.finish();
    let events = f.events.lock().unwrap();
    assert!(!events.iter().any(|e| e.0 == 99));
    assert_eq!(events.iter().filter(|e| e.0 == 50).count(), 1);
    let mut ids = events
        .iter()
        .filter(|e| e.0 < 7)
        .map(|e| e.1.get())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 16);
    drop(events);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert_eq!(cpu.flags(), 0x202);
}
#[test]
fn portal_and_notify_can_signal_a_blocked_peer_without_start_reordering() {
    for is_notify in [false, true] {
        let (executor, f, cpu, dropped) = setup();
        let r = executor.runtime();
        let p = Arc::as_ptr(&f) as *mut c_void;
        if is_notify {
            // SAFETY: both static callbacks share the retained fixture through join.
            unsafe { r.queue.execute(Kind::Notify, notify, p) }.unwrap();
            // SAFETY: a second distinct Notify continuation can signal the first.
            unsafe { r.queue.execute(Kind::Notify, signal_notify, p) }.unwrap();
        } else {
            // SAFETY: both static callbacks share the retained fixture through join.
            unsafe { r.queue.execute_portal(portal, p) }.unwrap();
            // SAFETY: a second distinct portal continuation can signal the first.
            unsafe { r.queue.execute_portal(signal_portal, p) }.unwrap();
        }
        f.finish();
        let events = f.events.lock().unwrap();
        let tags = events.iter().map(|e| e.0).collect::<Vec<_>>();
        assert_eq!(
            tags,
            if is_notify {
                vec![4, 7, 104]
            } else {
                vec![3, 8, 103]
            }
        );
        assert_ne!(events[0].1, events[1].1);
        assert_eq!(events[0].1, events[2].1);
        drop(events);
        drop(executor);
        assert_eq!(dropped.load(Ordering::Relaxed), 16);
        assert_eq!(cpu.flags(), 0x202);
    }
}

unsafe extern "C" fn count_queued(p: *mut c_void) {
    // SAFETY: the queue retains this exact AtomicUsize allocation until join.
    unsafe { &*p.cast::<core::sync::atomic::AtomicUsize>() }.fetch_add(1, Ordering::Relaxed);
}
#[test]
fn native_admission_rejects_legacy_jobs_without_claiming_or_reinterpreting_them() {
    let count = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let cpu = test_support::CpuModel::new();
    // SAFETY: this same-thread modeled queue retains the actual callback context.
    let queue = unsafe { Queue::<32>::new(cpu.clone(), count.clone()) }.unwrap();
    // SAFETY: the queue owns count through the eventual legacy executor join.
    let ticket = unsafe {
        queue.execute(
            Kind::Notify,
            count_queued,
            Arc::as_ptr(&count) as *mut c_void,
        )
    }
    .unwrap();
    let dropped = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let stacks = test_support::stacks(&dropped);
    Runtime::validate_stacks(&queue, &stacks).unwrap();
    // SAFETY: this is only an unprivileged real x87/SSE control snapshot.
    let controls = unsafe { context::read_controls() };
    assert!(matches!(
        Runtime::with_layout_controls(queue.clone(), stacks, controls, Layout::NativeFirmware16),
        Err(WorkError::Busy)
    ));
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert!(!queue.executor_claimed.load(Ordering::Acquire));
    assert_eq!(queue.lock().unwrap().state().layout, Layout::Ordinary);
    assert_eq!(queue.completed(ticket), Ok(false));
    assert_eq!(count.load(Ordering::Relaxed), 0);
    // The old constructor can still consume the unchanged legacy queue.
    let runtime =
        Runtime::with_controls(queue.clone(), test_support::stacks(&dropped), controls).unwrap();
    let executor = Executor {
        runtime: ManuallyDrop::new(runtime),
    };
    assert_eq!(
        executor
            .runtime()
            .join_firmware(FirmwareQueue::Gpe, cpu.ticks() + 1_000_000_000),
        Err(WorkError::Unavailable)
    );
    assert_eq!(
        executor.runtime().check_firmware_join(FirmwareQueue::Gpe),
        Err(WorkError::Unavailable)
    );
    assert_eq!(
        executor
            .runtime()
            .check_firmware_join(FirmwareQueue::Notify),
        Err(WorkError::Unavailable)
    );
    queue.close().unwrap();
    executor
        .runtime()
        .drain(cpu.ticks() + 1_000_000_000)
        .unwrap();
    assert_eq!(queue.completed(ticket), Ok(true));
    assert_eq!(count.load(Ordering::Relaxed), 1);
    // SAFETY: close rejected new admissions and every accepted callback joined.
    unsafe { executor.runtime().retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
    assert_eq!(cpu.flags(), 0x202);
}

unsafe extern "C" fn firmware_turns(p: *mut c_void) {
    // SAFETY: Scene is the queue-retained allocation, live through every yield.
    let f = unsafe { scene(p) };
    let r = f.runtime();
    let tag = match r.firmware_role_current().unwrap().unwrap() {
        FirmwareRole::Control => 20,
        FirmwareRole::PortalAml => 21,
        FirmwareRole::Gpe => 22,
        FirmwareRole::Notify => 23,
    };
    for _ in 0..20 {
        assert_eq!(r.service_current(), Ok(false));
        f.event(tag);
        r.yield_now().unwrap();
    }
}
unsafe extern "C" fn service_turns(p: *mut c_void) {
    // SAFETY: this retained Scene survives all Linux service continuation yields.
    let f = unsafe { scene(p) };
    for _ in 0..20 {
        assert_eq!(f.runtime().service_current(), Ok(true));
        assert_eq!(f.runtime().firmware_role_current(), Ok(None));
        f.event(91);
        f.runtime().yield_now().unwrap();
    }
}
unsafe extern "C" fn ordinary_turn(p: *mut c_void) {
    // SAFETY: this queued callback borrows only the retained Scene allocation.
    let f = unsafe { scene(p) };
    assert_eq!(f.runtime().service_current(), Ok(false));
    assert_eq!(f.runtime().firmware_role_current(), Ok(None));
    f.event(90);
}
#[test]
fn continuously_ready_firmware_roles_share_bounded_turns_with_linux_work() {
    let (executor, f, cpu, dropped) = setup();
    let r = executor.runtime();
    let p = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: each static callback's Scene remains retained through every yield/join.
    unsafe { r.start_service(service_turns, p) }.unwrap();
    // SAFETY: this distinct retained control frame never borrows another role's stack.
    unsafe { r.start_firmware(firmware_turns, p) }.unwrap();
    for _ in 0..2 {
        // SAFETY: both actual portal worker frames retain the queue-owned Scene.
        unsafe { r.queue.execute_portal(firmware_turns, p) }.unwrap();
        // SAFETY: both actual Notify worker frames retain the queue-owned Scene.
        unsafe { r.queue.execute(Kind::Notify, firmware_turns, p) }.unwrap();
    }
    // SAFETY: this serial GPE worker retains the same Scene through completion.
    unsafe { r.queue.execute_gpe(firmware_turns, p) }.unwrap();
    // SAFETY: ordinary progress uses a separate actual General continuation.
    unsafe { r.queue.execute(Kind::General, ordinary_turn, p) }.unwrap();
    f.finish();
    let events = f.events.lock().unwrap();
    assert_eq!(events.len(), 141);
    assert_eq!(events.iter().filter(|e| e.0 == 90).count(), 1);
    assert_eq!(events.iter().filter(|e| e.0 == 91).count(), 20);
    assert!(events.iter().position(|e| e.0 == 90).unwrap() < 4);
    assert!(events.iter().position(|e| e.0 == 91).unwrap() < 4);
    let last_linux = events.iter().rposition(|e| e.0 == 91).unwrap();
    for pair in events[..=last_linux].windows(2) {
        assert!(
            pair[0].0 >= 90 || pair[1].0 >= 90,
            "ready firmware must not skip an eligible Linux turn"
        );
    }
    let mut firmware_ids = events
        .iter()
        .filter(|e| e.0 < 90)
        .map(|e| e.1)
        .collect::<Vec<_>>();
    firmware_ids.sort_unstable_by_key(|id| id.get());
    firmware_ids.dedup();
    assert_eq!(firmware_ids.len(), 6);
    for id in firmware_ids {
        assert_eq!(events.iter().filter(|e| e.1 == id).count(), 20);
        assert!(events.iter().position(|e| e.1 == id).unwrap() < 16);
    }
    drop(events);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert_eq!(cpu.flags(), 0x202);
}

unsafe extern "C" fn notify_tail(p: *mut c_void) {
    // SAFETY: matching Scene is retained through this late callback's join.
    unsafe { scene(p) }.event(34);
}
unsafe extern "C" fn notify_chain(p: *mut c_void) {
    // SAFETY: Scene is queue-owned through both accepted Notify callbacks.
    let f = unsafe { scene(p) };
    f.event(32);
    // SAFETY: the later work borrows the same retained provider allocation.
    unsafe { f.runtime().queue.execute(Kind::Notify, notify_tail, p) }.unwrap();
    f.event(33);
}
unsafe extern "C" fn gpe_chain(p: *mut c_void) {
    // SAFETY: Scene is queue-owned through GPE and the posted Notify work.
    let f = unsafe { scene(p) };
    f.event(30);
    // SAFETY: the new queue's callback/context stay retained independently.
    unsafe { f.runtime().queue.execute(Kind::Notify, notify_chain, p) }.unwrap();
    f.event(31);
}
#[test]
fn firmware_flush_captures_gpe_then_notify_and_excludes_later_same_queue_chains() {
    let (executor, f, cpu, dropped) = setup();
    let r = executor.runtime();
    let p = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: Scene retains all callback contexts through both flushes and close.
    unsafe { r.queue.execute_gpe(gpe_chain, p) }.unwrap();
    r.join_firmware(FirmwareQueue::Gpe, cpu.ticks() + 1_000_000_000)
        .unwrap();
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>(),
        vec![30, 31]
    );
    r.join_firmware(FirmwareQueue::Notify, cpu.ticks() + 1_000_000_000)
        .unwrap();
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>(),
        vec![30, 31, 32, 33]
    );
    // Same-queue work posted after the Notify capture is a later flush color,
    // even though its enqueuer belonged to the first captured prefix.
    r.join_firmware(FirmwareQueue::Notify, cpu.ticks() + 1_000_000_000)
        .unwrap();
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>(),
        vec![30, 31, 32, 33, 34]
    );
    f.finish();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert_eq!(cpu.flags(), 0x202);
}
unsafe extern "C" fn gpe_self_join(p: *mut c_void) {
    // SAFETY: live queue-owned Scene, executing on the actual GPE frame.
    let f = unsafe { scene(p) };
    f.event(40);
    assert_eq!(
        f.runtime().check_firmware_join(FirmwareQueue::Gpe),
        Err(WorkError::WouldDeadlock)
    );
    assert_eq!(
        f.runtime().check_firmware_join(FirmwareQueue::Notify),
        Ok(())
    );
    assert_eq!(
        f.runtime().join_firmware(
            FirmwareQueue::Gpe,
            f.runtime().queue.cpu.ticks() + 1_000_000_000
        ),
        Err(WorkError::WouldDeadlock)
    );
    f.event(41);
}
unsafe extern "C" fn notify_self_join(p: *mut c_void) {
    // SAFETY: live queue-owned Scene, executing on an actual Notify frame.
    let f = unsafe { scene(p) };
    f.event(42);
    assert_eq!(
        f.runtime().check_firmware_join(FirmwareQueue::Notify),
        Err(WorkError::WouldDeadlock)
    );
    assert_eq!(f.runtime().check_firmware_join(FirmwareQueue::Gpe), Ok(()));
    assert_eq!(
        f.runtime().join_firmware(
            FirmwareQueue::Notify,
            f.runtime().queue.cpu.ticks() + 1_000_000_000
        ),
        Err(WorkError::WouldDeadlock)
    );
    f.event(43);
}
#[test]
fn firmware_self_join_refuses_without_completing_or_discarding_the_active_job() {
    let (executor, f, cpu, dropped) = setup();
    let r = executor.runtime();
    let p = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: both callbacks/context survive the refusal and eventual real completion.
    let gpe = unsafe { r.queue.execute_gpe(gpe_self_join, p) }.unwrap();
    // SAFETY: Notify borrows the same retained provider until actual callback return.
    let notify = unsafe { r.queue.execute(Kind::Notify, notify_self_join, p) }.unwrap();
    f.finish();
    assert_eq!(r.queue.completed(gpe), Ok(true));
    assert_eq!(r.queue.completed(notify), Ok(true));
    let events = f.events.lock().unwrap();
    let tags = events.iter().map(|e| e.0).collect::<Vec<_>>();
    assert_eq!(
        tags.iter()
            .filter(|tag| **tag == 40 || **tag == 41)
            .copied()
            .collect::<Vec<_>>(),
        vec![40, 41]
    );
    assert_eq!(
        tags.iter()
            .filter(|tag| **tag == 42 || **tag == 43)
            .copied()
            .collect::<Vec<_>>(),
        vec![42, 43]
    );
    drop(events);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert_eq!(cpu.flags(), 0x202);
}
unsafe extern "C" fn portal_queue_join(p: *mut c_void) {
    // SAFETY: this actual Portal frame borrows the queue-retained Scene.
    let f = unsafe { scene(p) };
    f.event(50);
    assert_eq!(f.runtime().check_firmware_join(FirmwareQueue::Gpe), Ok(()));
    assert_eq!(
        f.runtime().check_firmware_join(FirmwareQueue::Notify),
        Ok(())
    );
    f.runtime()
        .join_firmware(
            FirmwareQueue::Gpe,
            f.runtime().queue.cpu.ticks() + 1_000_000_000,
        )
        .unwrap();
    f.event(51);
    f.runtime()
        .join_firmware(
            FirmwareQueue::Notify,
            f.runtime().queue.cpu.ticks() + 1_000_000_000,
        )
        .unwrap();
    f.event(52);
}
#[test]
fn portal_flush_excludes_parked_linux_service_and_general_callbacks() {
    let (executor, f, cpu, dropped) = setup();
    let r = executor.runtime();
    let p = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: this blocked service retains Scene until explicit release/join.
    unsafe { r.start_service(service, p) }.unwrap();
    for _ in 0..8 {
        // SAFETY: all General contexts are retained by Scene through release.
        unsafe { r.queue.execute(Kind::General, general, p) }.unwrap();
    }
    for _ in 0..9 {
        assert_eq!(r.step(), Ok(true));
    }
    assert_eq!(f.blocked.lock().unwrap().len(), 9);
    // SAFETY: GPE and its posted Notify callbacks share the retained Scene.
    unsafe { r.queue.execute_gpe(gpe_chain, p) }.unwrap();
    // SAFETY: Portal stays retained while its finite queue-prefix joins suspend.
    let portal = unsafe { r.queue.execute_portal(portal_queue_join, p) }.unwrap();
    for _ in 0..24 {
        if r.queue.completed(portal).unwrap() {
            break;
        }
        assert_eq!(r.step(), Ok(true));
    }
    assert_eq!(r.queue.completed(portal), Ok(true));
    let tags = f
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|e| e.0)
        .collect::<Vec<_>>();
    assert!(tags.contains(&52));
    assert!(!tags.contains(&100) && !tags.contains(&101));
    assert_eq!(f.blocked.lock().unwrap().len(), 9);
    r.queue.close().unwrap();
    f.release(None);
    f.finish();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert_eq!(cpu.flags(), 0x202);
}

#[test]
fn minimum_sixteen_slot_queue_reserves_foreground_after_general_saturation() {
    let count = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let (executor, cpu, dropped) = test_support::executor::<16>(count.clone());
    let r = executor.runtime();
    let p = Arc::as_ptr(&count) as *mut c_void;
    for _ in 0..8 {
        // SAFETY: queue retains this atomic allocation through every callback/join.
        unsafe { r.queue.execute(Kind::General, count_queued, p) }.unwrap();
    }
    assert_eq!(
        // SAFETY: Full rejects this valid pointer without accepting another callback.
        unsafe { r.queue.execute(Kind::General, count_queued, p) },
        Err(WorkError::Full)
    );
    // SAFETY: Linux service callback's exact allocation stays retained through join.
    unsafe { r.start_service(count_queued, p) }.unwrap();
    // SAFETY: independent control callback's exact allocation stays retained through join.
    unsafe { r.start_firmware(count_queued, p) }.unwrap();
    // SAFETY: independent serial GPE callback has the same retained atomic context.
    unsafe { r.queue.execute_gpe(count_queued, p) }.unwrap();
    for _ in 0..2 {
        // SAFETY: each actual portal worker borrows the retained atomic allocation.
        unsafe { r.queue.execute_portal(count_queued, p) }.unwrap();
        // SAFETY: each actual Notify worker borrows the retained atomic allocation.
        unsafe { r.queue.execute(Kind::Notify, count_queued, p) }.unwrap();
    }
    assert_eq!(count.load(Ordering::Relaxed), 0);
    let next = r.queue.lock().unwrap().state().next;
    let flags = cpu.flags();
    assert_eq!(r.check_firmware_join(FirmwareQueue::Gpe), Ok(()));
    assert_eq!(r.check_firmware_join(FirmwareQueue::Notify), Ok(()));
    assert_eq!(r.queue.lock().unwrap().state().next, next);
    assert_eq!(count.load(Ordering::Relaxed), 0);
    assert_eq!(cpu.flags(), flags);
    assert_eq!(r.current_id(), Err(WorkError::Unavailable));
    // SAFETY: Foreground retains the context across admission and every switched peer.
    unsafe { r.call_foreground(count_queued, p, cpu.ticks() + 1_000_000_000) }.unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 16);
    // SAFETY: no producer remains and all16 admitted callbacks actually returned.
    unsafe { r.retire() }.unwrap();
    assert_eq!(
        r.check_firmware_join(FirmwareQueue::Gpe),
        Err(WorkError::Closed)
    );
    assert_eq!(
        r.check_firmware_join(FirmwareQueue::Notify),
        Err(WorkError::Closed)
    );
    assert_eq!(
        r.join_firmware(FirmwareQueue::Gpe, cpu.ticks() + 1_000_000_000),
        Err(WorkError::Closed)
    );
    assert_eq!(
        r.join_firmware(FirmwareQueue::Notify, cpu.ticks() + 1_000_000_000),
        Err(WorkError::Closed)
    );
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert_eq!(cpu.flags(), 0x202);
}

mod protected_gpe;
