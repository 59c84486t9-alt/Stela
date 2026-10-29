//! Compatible reservations, bounded setup and fail-closed ownership tests.
use super::*;
use core::cell::Cell;
use std::{println, process::Command, string::String};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Drop,
    MetadataFailure,
    Commit,
    Exhaust,
    Closed,
    Pressure,
    StaleScope,
    StaleCurrent,
    BadNonce,
    Forgotten,
    Denied,
    NoProfile,
    CommitExhaust,
    BoundWorker,
}
struct HarnessCpu {
    model: Arc<test_support::CpuModel>,
    dropped: Arc<AtomicUsize>,
    mode: Mode,
}
// SAFETY: delegates the same hosted-thread/flag model, with no native
// CPU/root grant. Negative fixtures stop the subprocess at the mandatory fatal
// boundary while asserting no real mapping owner was reclaimed.
unsafe impl Cpu for HarnessCpu {
    fn check_cpu(&self) -> Result<(), WorkError> {
        self.model.check_cpu()
    }
    fn in_interrupt(&self) -> bool {
        self.model.in_interrupt()
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.model.save_disable()
    }
    unsafe fn restore(&self, flags: u64) {
        // SAFETY: caller supplies this model's enclosing save_disable flags.
        unsafe { self.model.restore(flags) }
    }
    fn ticks(&self) -> u64 {
        self.model.ticks()
    }
    fn fatal(&self, error: WorkError) -> ! {
        if matches!(
            self.mode,
            Mode::StaleScope | Mode::StaleCurrent | Mode::BadNonce | Mode::Forgotten
        ) {
            assert_eq!(
                error,
                if self.mode == Mode::Forgotten {
                    WorkError::Pending
                } else {
                    WorkError::Closed
                }
            );
            assert_eq!(self.dropped.load(Ordering::Relaxed), 0);
            println!("STELA_RESERVATION_FATAL_RETAINED {:?}", self.mode);
            std::process::exit(91);
        }
        panic!("unexpected reservation fixture fatal: {error:?}")
    }
}
struct Authority {
    cpu: Arc<HarnessCpu>,
    active: Cell<bool>,
}
// SAFETY: explicit hosted model only. It borrows this callback's model
// scope, checks its constructing OS thread and active state without allocation,
// waits or callbacks, including IF0. Production must use real DriverExecution.
unsafe impl EnteredProcess for Authority {
    fn check(&self) -> Result<(), WorkError> {
        self.cpu.check_cpu()?;
        if self.active.get() {
            Ok(())
        } else {
            Err(WorkError::Unavailable)
        }
    }
}
struct Scene {
    runtime: AtomicU64,
    cpu: Arc<HarnessCpu>,
    dropped: Arc<AtomicUsize>,
    mode: Mode,
    child: AtomicUsize,
    ordinary: AtomicUsize,
    assigned: Mutex<Option<AssignedGeneral>>,
    actual: Mutex<Option<TaskContext>>,
    occupied: Mutex<Option<(Arc<Binding>, WakeHandle<64>)>>,
}
impl Scene {
    fn runtime(&self) -> Pin<&Runtime<64>> {
        // SAFETY: constructor publishes this exact pinned allocation before
        // admission; queue keeps Scene through join or full quarantine.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>))
        }
    }
}
unsafe extern "C" fn child(pointer: *mut c_void) {
    // SAFETY: Scene and code remain held by this queue until real completion.
    let f = unsafe { &*pointer.cast::<Scene>() };
    let r = f.runtime();
    let view = r.current_context().unwrap();
    assert_eq!(view.stack_end - view.stack_start, 16 * 1024);
    assert!(view.stack_start.is_multiple_of(16 * 1024));
    assert!((view.stack_start..view.stack_end).contains(&context::stack_pointer()));
    *f.actual.lock().unwrap() = Some(view);
    f.child.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn bind_retained_worker(pointer: *mut c_void) {
    // SAFETY: queue keeps Scene until the binding is joined/detached.
    let f = unsafe { &*pointer.cast::<Scene>() };
    let r = f.runtime();
    let binding = Arc::new(Binding {
        id: AtomicU64::new(0),
        blocked: AtomicBool::new(false),
    });
    let wake = r.bind_current(binding.clone()).unwrap();
    *f.occupied.lock().unwrap() = Some((binding, wake));
}
unsafe extern "C" fn ordinary_marker(pointer: *mut c_void) {
    // SAFETY: the same queue keeps Scene through each ordinary marker completion.
    let f = unsafe { &*pointer.cast::<Scene>() };
    assert!(
        f.runtime().current_context().unwrap().stack_end
            - f.runtime().current_context().unwrap().stack_start
            >= 128 * 1024
    );
    f.ordinary.fetch_add(1, Ordering::Relaxed);
}
fn failed_metadata(r: Pin<&Runtime<64>>, authority: &dyn EnteredProcess) -> Result<(), WorkError> {
    let _permit = r.reserve_general(authority, kernel())?;
    // Fallible capacity rejection exercises caller-setup error rollback.
    // This does not claim physical allocator exhaustion or a Linux OOM service.
    let mut metadata = Vec::<u8>::new();
    metadata
        .try_reserve_exact(usize::MAX)
        .map_err(|_| WorkError::Full)?;
    unreachable!()
}
unsafe extern "C" fn creator(pointer: *mut c_void) {
    // SAFETY: accepted Foreground owns Scene and its live runtime view.
    let f = unsafe { &*pointer.cast::<Scene>() };
    let r = f.runtime();
    let authority = Authority {
        cpu: f.cpu.clone(),
        active: Cell::new(true),
    };
    let before = r.current_context().unwrap();
    let next = r.queue.lock().unwrap().state().next;
    match f.mode {
        Mode::BoundWorker => {
            let mut permits = Vec::new();
            for _ in 0..19 {
                permits.push(r.reserve_general(&authority, kernel()).unwrap());
            }
            assert!(matches!(
                r.reserve_general(&authority, kernel()),
                Err(WorkError::Full)
            ));
            drop(permits);
        }
        Mode::Denied => {
            authority.active.set(false);
            assert!(matches!(
                r.reserve_general(&authority, kernel()),
                Err(WorkError::Unavailable)
            ));
            authority.active.set(true);
        }
        Mode::NoProfile => {
            assert!(matches!(
                r.reserve_general(&authority, kernel()),
                Err(WorkError::Unavailable)
            ));
        }
        Mode::CommitExhaust => {
            let permit = r.reserve_general(&authority, kernel()).unwrap();
            r.queue.lock().unwrap().state().next = u64::MAX;
            assert_eq!(
                // SAFETY: provider-owned Scene stays held; counter exhaustion must transfer nothing.
                unsafe { permit.commit(child, pointer) },
                Err(WorkError::Exhausted)
            );
            assert_eq!(r.queue.lock().unwrap().state().next, u64::MAX);
            r.queue.lock().unwrap().state().next = next;
        }
        Mode::Drop => {
            let permit = r.reserve_general(&authority, kernel()).unwrap();
            assert_eq!(r.pending_reservations.get(), 1);
            assert_eq!(r.yield_now(), Err(WorkError::Busy));
            assert_eq!(r.reschedule(), Err(WorkError::Busy));
            assert_eq!(r.park_if_blocked(), Err(WorkError::Busy));
            assert_eq!(f.cpu.model.flags(), 0x202);
            assert_eq!(f.child.load(Ordering::Relaxed), 0);
            drop(permit);
        }
        Mode::MetadataFailure => assert_eq!(failed_metadata(r, &authority), Err(WorkError::Full)),
        Mode::Commit => {
            let permit = r.reserve_general(&authority, kernel()).unwrap();
            // SAFETY: queue-kept Scene/code fit exact kernel geometry;
            // no borrowed permission is stored in the child callback/context.
            let assigned = unsafe { permit.commit(child, pointer) }.unwrap();
            assert_eq!(f.child.load(Ordering::Relaxed), 0);
            assert_eq!(r.queue.completed(assigned.ticket()), Ok(false));
            assert_ne!(assigned.context_id().get(), before.context_id);
            *f.assigned.lock().unwrap() = Some(assigned);
            assert_eq!(r.pending_reservations.get(), 0);
            drop(authority); // Commit consumed its short borrow before any child wait.
            r.yield_now().unwrap();
            return;
        }
        Mode::Exhaust => {
            let mut permits = Vec::new();
            for _ in 0..4 {
                permits.push(r.reserve_general(&authority, ordinary()).unwrap());
            }
            assert!(matches!(
                r.reserve_general(&authority, ordinary()),
                Err(WorkError::Full)
            ));
            for permit in permits {
                permit.cancel().unwrap();
            }
            assert_eq!(r.pending_reservations.get(), 0);
            r.queue.lock().unwrap().state().next_reservation = u64::MAX;
            assert!(matches!(
                r.reserve_general(&authority, kernel()),
                Err(WorkError::Exhausted)
            ));
            assert!(
                r.queue
                    .lock()
                    .unwrap()
                    .state()
                    .reservations
                    .iter()
                    .all(|nonce| *nonce == 0)
            );
        }
        Mode::Closed => {
            let permit = r.reserve_general(&authority, kernel()).unwrap();
            r.queue.close().unwrap();
            assert_eq!(
                // SAFETY: error keeps provider-owned Scene and admits no callback.
                unsafe { permit.commit(child, pointer) },
                Err(WorkError::Closed)
            );
            assert_eq!(r.pending_reservations.get(), 0);
        }
        Mode::Pressure => {
            let permit = r.reserve_general(&authority, kernel()).unwrap();
            for _ in 0..54 {
                // SAFETY: all kept ordinary markers fit actual128KiB workers.
                unsafe { r.queue.execute(Kind::General, ordinary_marker, pointer) }.unwrap();
            }
            assert_eq!(
                // SAFETY: the private reserved slot must not accept ordinary work.
                unsafe { r.queue.execute(Kind::General, ordinary_marker, pointer) },
                Err(WorkError::Full)
            );
            permit.cancel().unwrap();
            // SAFETY: exact released slot becomes ordinary admission again; no child was published.
            unsafe { r.queue.execute(Kind::General, ordinary_marker, pointer) }.unwrap();
            assert!(matches!(
                r.reserve_general(&authority, kernel()),
                Err(WorkError::Full)
            ));
            return;
        }
        Mode::StaleScope => {
            let permit = r.reserve_general(&authority, kernel()).unwrap();
            let old = quarantined_owners();
            authority.active.set(false);
            assert_eq!(permit.cancel(), Err(WorkError::Unavailable));
            assert!(r.queue.abandoned.load(Ordering::Acquire));
            assert!(quarantined_owners() > old);
            assert_eq!(f.dropped.load(Ordering::Relaxed), 0);
            assert_eq!(f.child.load(Ordering::Relaxed), 0);
            println!("STELA_RESERVATION_UNCERTAIN_RETAINED");
            return;
        }
        Mode::StaleCurrent => {
            let permit = r.reserve_general(&authority, kernel()).unwrap();
            let flags = f.cpu.save_disable().unwrap();
            // SAFETY: deliberate isolated corruption of this current test
            // job's sequence, with IF0 and no foreign task. Fatal must keep it.
            unsafe {
                (*r.task(r.current.get())).job.as_mut().unwrap().1.sequence += 1;
            }
            // SAFETY: exact local save_disable flags above, no borrow survives.
            unsafe { f.cpu.restore(flags) };
            assert_eq!(permit.cancel(), Err(WorkError::CorruptContext));
            println!("STELA_RESERVATION_UNCERTAIN_RETAINED");
            return;
        }
        Mode::BadNonce => {
            let permit = r.reserve_general(&authority, kernel()).unwrap();
            let mut guard = r.queue.lock().unwrap();
            let slot = guard
                .state()
                .reservations
                .iter()
                .position(|nonce| *nonce != 0)
                .unwrap();
            guard.state().reservations[slot] += 1;
            drop(guard);
            assert_eq!(permit.cancel(), Err(WorkError::CorruptContext));
            println!("STELA_RESERVATION_UNCERTAIN_RETAINED");
            return;
        }
        Mode::Forgotten => {
            let permit = r.reserve_general(&authority, kernel()).unwrap();
            core::mem::forget(permit);
            assert_eq!(f.dropped.load(Ordering::Relaxed), 0);
            assert_eq!(f.child.load(Ordering::Relaxed), 0);
            println!("STELA_RESERVATION_FORGOTTEN_RETAINED");
            return;
        }
    }
    assert_eq!(r.queue.lock().unwrap().state().next, next);
    assert_eq!(r.pending_reservations.get(), 0);
    assert_eq!(r.current_context().unwrap().context_id, before.context_id);
    assert_eq!(r.current_context().unwrap().sequence, before.sequence);
    assert_eq!(f.child.load(Ordering::Relaxed), 0);
}
fn run(mode: Mode) {
    let model = test_support::CpuModel::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let cpu = Arc::new(HarnessCpu {
        model,
        dropped: dropped.clone(),
        mode,
    });
    let f = Arc::new(Scene {
        runtime: AtomicU64::new(0),
        cpu: cpu.clone(),
        dropped: dropped.clone(),
        mode,
        child: AtomicUsize::new(0),
        ordinary: AtomicUsize::new(0),
        assigned: Mutex::new(None),
        actual: Mutex::new(None),
        occupied: Mutex::new(None),
    });
    // SAFETY: same-thread hosted CPU and kept exact Scene; no native grant.
    let q = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor = if mode == Mode::NoProfile {
        Executor::new_hosted_for_test(q, test_support::stacks(&dropped)).unwrap()
    } else {
        Executor::new_hosted_profile_for_test(q, support::stacks(&dropped, 20), policy(), profile())
            .unwrap()
    };
    let r = executor.runtime();
    f.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    if mode == Mode::BoundWorker {
        // SAFETY: queue-kept Scene binds a compatible worker; its real binding remains attached.
        unsafe {
            r.queue.execute_general_with_requirement(
                kernel(),
                bind_retained_worker,
                Arc::as_ptr(&f) as *mut c_void,
            )
        }
        .unwrap();
        r.drain(cpu.ticks() + 1_000_000_000).unwrap();
        assert!(f.occupied.lock().unwrap().is_some());
    }
    // SAFETY: Foreground stack and Scene remain held through join or fatal.
    unsafe {
        r.call_foreground(
            creator,
            Arc::as_ptr(&f) as *mut c_void,
            cpu.ticks() + 1_000_000_000,
        )
    }
    .unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    if mode == Mode::Commit {
        let assigned = f.assigned.lock().unwrap().unwrap();
        assert_eq!(r.queue.completed(assigned.ticket()), Ok(true));
        assert_eq!(
            f.actual.lock().unwrap().unwrap().context_id,
            assigned.context_id().get()
        );
        assert_eq!(f.child.load(Ordering::Relaxed), 1);
    } else {
        assert_eq!(f.child.load(Ordering::Relaxed), 0);
    }
    assert_eq!(
        f.ordinary.load(Ordering::Relaxed),
        if mode == Mode::Pressure { 55 } else { 0 }
    );
    if let Some((binding, wake)) = f.occupied.lock().unwrap().take() {
        // SAFETY: bound callback returned; fixture stopped every producer before detaching this idle owner.
        drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
        drop(binding);
        drop(wake);
    }
    r.queue.close().unwrap();
    // SAFETY: no producer exists; every accepted callback returned and all bindings were detached.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        if mode == Mode::NoProfile { 16 } else { 32 }
    );
    assert_eq!(cpu.model.flags(), 0x202);
}
#[test]
fn dropped_and_failed_metadata_setup_restore_actual_worker_without_ticket() {
    run(Mode::Drop);
    run(Mode::MetadataFailure);
}
#[test]
fn committed_actual_child_runs_after_borrow_release_on_its_reserved_geometry() {
    run(Mode::Commit);
}
#[test]
fn real_worker_slot_nonce_exhaustion_and_closed_commit_transfer_nothing() {
    run(Mode::Exhaust);
    run(Mode::Closed);
    run(Mode::Pressure);
}
fn isolated(name: &str, mode: &str) {
    let test = format!("{}::{name}", module_path!().split_once("::").unwrap().1);
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
        .env("STELA_RESERVATION_TEST_MODE", mode)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(91));
    assert!(String::from_utf8_lossy(&output.stdout).contains("STELA_RESERVATION_FATAL_RETAINED"));
}
#[test]
fn stale_scope_current_and_nonce_keep_real_owners_before_mandatory_stop() {
    if let Ok(mode) = std::env::var("STELA_RESERVATION_TEST_MODE") {
        run(match mode.as_str() {
            "scope" => Mode::StaleScope,
            "current" => Mode::StaleCurrent,
            "nonce" => Mode::BadNonce,
            _ => panic!("wrong fixture mode"),
        });
        unreachable!();
    }
    for mode in ["scope", "current", "nonce"] {
        isolated(
            "stale_scope_current_and_nonce_keep_real_owners_before_mandatory_stop",
            mode,
        );
    }
}
#[test]
fn forgotten_permit_stops_before_return_or_owner_release() {
    if std::env::var("STELA_RESERVATION_TEST_MODE").as_deref() == Ok("forgotten") {
        run(Mode::Forgotten);
        unreachable!();
    }
    isolated(
        "forgotten_permit_stops_before_return_or_owner_release",
        "forgotten",
    );
}

#[test]
fn actual_authority_profile_and_ticket_exhaustion_refuse_before_publication() {
    run(Mode::Denied);
    run(Mode::NoProfile);
    run(Mode::CommitExhaust);
}

#[test]
fn physically_idle_but_retained_binding_is_not_an_unowned_spawn_stack() {
    run(Mode::BoundWorker);
}
