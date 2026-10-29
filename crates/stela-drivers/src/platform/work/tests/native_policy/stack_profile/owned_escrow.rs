//! Owned exclusions across real hosted park/resume; no native scope or C loan.
use super::*;
use core::cell::Cell;
use std::{println, process::Command, string::String};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    RoundTrip,
    Pressure,
    Exhaust,
    ClosedConversion,
    ClosedCancel,
    TotalOverflow,
    CreatorOverflow,
    Stale,
    WrongJob,
    Nonce,
    Foreign,
    Drop,
    ForeignDrop,
    Forgotten,
    ForgottenParked,
}
struct ModelCpu {
    model: Arc<test_support::CpuModel>,
    dropped: Arc<AtomicUsize>,
    mode: Mode,
}
// SAFETY: same-thread hosted CPU/IF observation only. Negative subprocesses stop
// at the mandatory retention boundary and assert that no actual mmap was freed.
unsafe impl Cpu for ModelCpu {
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
        // SAFETY: exact enclosing save_disable flags from this actual model.
        unsafe { self.model.restore(flags) }
    }
    fn ticks(&self) -> u64 {
        self.model.ticks()
    }
    fn fatal(&self, error: WorkError) -> ! {
        if matches!(
            self.mode,
            Mode::Stale
                | Mode::WrongJob
                | Mode::Nonce
                | Mode::Foreign
                | Mode::Drop
                | Mode::ForeignDrop
                | Mode::Forgotten
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
            println!("STELA_ESCROW_FATAL_RETAINED {:?}", self.mode);
            std::process::exit(92);
        }
        panic!("unexpected escrow model fatal {error:?}")
    }
}
struct Authority {
    cpu: Arc<ModelCpu>,
    active: Cell<bool>,
}
// SAFETY: hosted scope model borrows the actual callback's CPU model and checks
// its OS thread and active flag without allocation/waits, including IF0. This
// does not implement native DriverExecution generation or Guest reentry.
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
impl Authority {
    fn new(cpu: &Arc<ModelCpu>) -> Self {
        Self {
            cpu: cpu.clone(),
            active: Cell::new(true),
        }
    }
}
struct Scene {
    runtime: AtomicU64,
    cpu: Arc<ModelCpu>,
    mode: Mode,
    ordinary: AtomicUsize,
    parked: AtomicBool,
    binding: Mutex<Option<(Arc<Binding>, WakeHandle<64>)>>,
}
impl Scene {
    fn runtime(&self) -> Pin<&Runtime<64>> {
        // SAFETY: fixture retains the actual pinned executor for every use;
        // uncertain paths retain it permanently before this raw view can dangle.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>))
        }
    }
}
unsafe extern "C" fn marker(pointer: *mut c_void) {
    // SAFETY: queue-retained Scene/code remain valid until this actual job returns.
    let f = unsafe { &*pointer.cast::<Scene>() };
    let r = f.runtime();
    assert!(
        r.current_context().unwrap().stack_end - r.current_context().unwrap().stack_start
            >= 128 * 1024
    );
    f.ordinary.fetch_add(1, Ordering::Relaxed);
    if f.mode == Mode::RoundTrip {
        assert!(f.parked.load(Ordering::Acquire));
        assert_eq!(r.owned_escrows.get(), 1);
        assert_eq!(r.pending_reservations.get(), 0);
        let (binding, wake) = f.binding.lock().unwrap().as_ref().unwrap().clone();
        binding.blocked.store(false, Ordering::Release);
        wake.wake().unwrap();
        // This peer returns with another creator's escrow still live. A global
        // return check would wrongly stop it instead of waking the real creator.
    }
}
unsafe extern "C" fn creator(pointer: *mut c_void) {
    // SAFETY: actual Foreground owns stable Scene and the shared pinned Runtime.
    let f = unsafe { &*pointer.cast::<Scene>() };
    let r = f.runtime();
    let authority = Authority::new(&f.cpu);
    let initial = r.current_context().unwrap();
    let next = r.queue.lock().unwrap().state().next;
    let permit = r.reserve_general(&authority, kernel()).unwrap();
    assert_eq!(r.pending_reservations.get(), 1);
    if matches!(
        f.mode,
        Mode::TotalOverflow | Mode::CreatorOverflow | Mode::ClosedConversion
    ) {
        match f.mode {
            Mode::TotalOverflow => r.owned_escrows.set(usize::MAX),
            Mode::CreatorOverflow => {
                let flags = f.cpu.save_disable().unwrap();
                // SAFETY: deliberate current-fixture counter saturation at IF0;
                // the rejected conversion must publish nothing before reset.
                unsafe {
                    (*r.task(r.current.get())).owned_escrows = usize::MAX;
                }
                // SAFETY: exact model flags above; mutable task borrow ended.
                unsafe { f.cpu.restore(flags) };
            }
            Mode::ClosedConversion => r.queue.close().unwrap(),
            _ => unreachable!(),
        }
        assert!(matches!(
            permit.into_owned(),
            Err(WorkError::Exhausted | WorkError::Closed)
        ));
        r.owned_escrows.set(0);
        // SAFETY: same actual current fixture, rejected conversion owns no escrow.
        unsafe {
            (*r.task(r.current.get())).owned_escrows = 0;
        }
        assert_eq!(r.pending_reservations.get(), 0);
        assert!(
            r.queue
                .lock()
                .unwrap()
                .state()
                .reservations
                .iter()
                .all(|n| *n == 0)
        );
        assert_eq!(r.queue.lock().unwrap().state().next, next);
        return;
    }
    let escrow = permit.into_owned().unwrap();
    assert_eq!(r.pending_reservations.get(), 0);
    assert_eq!(r.owned_escrows.get(), 1);
    assert_eq!(f.cpu.model.flags(), 0x202);
    assert_eq!(r.queue.lock().unwrap().state().next, next);
    match f.mode {
        Mode::RoundTrip | Mode::ForgottenParked => {
            let binding = Arc::new(Binding {
                id: AtomicU64::new(0),
                blocked: AtomicBool::new(true),
            });
            let wake = r.bind_current(binding.clone()).unwrap();
            *f.binding.lock().unwrap() = Some((binding, wake));
            authority.active.set(false);
            drop(authority); // No entered-scope borrow survives the real park.
            if f.mode == Mode::ForgottenParked {
                core::mem::forget(escrow);
            } else {
                f.parked.store(true, Ordering::Release);
                assert_eq!(r.park_if_blocked().unwrap(), ParkOutcome::Resumed);
                let fresh = Authority::new(&f.cpu);
                let resumed = r.current_context().unwrap();
                assert_eq!(resumed.context_id, initial.context_id);
                assert_eq!(resumed.sequence, initial.sequence);
                assert_eq!(r.owned_escrows.get(), 1);
                assert_eq!(f.ordinary.load(Ordering::Relaxed), 1);
                escrow.cancel(&fresh).unwrap();
                assert_eq!(r.owned_escrows.get(), 0);
                assert_eq!(r.pending_reservations.get(), 0);
                return;
            }
            assert_eq!(r.park_if_blocked().unwrap(), ParkOutcome::Resumed);
            unreachable!("forgotten parked creator must never be resumed in this fixture");
        }
        Mode::Pressure => {
            for _ in 0..54 {
                // SAFETY: queue retains Scene/code; markers use actual ordinary stacks.
                unsafe { r.queue.execute(Kind::General, marker, pointer) }.unwrap();
            }
            assert_eq!(
                // SAFETY: same retained fixture; full admission must transfer nothing.
                unsafe { r.queue.execute(Kind::General, marker, pointer) },
                Err(WorkError::Full)
            );
            escrow.cancel(&authority).unwrap();
            // SAFETY: precisely released job slot is now ordinary admission again.
            unsafe { r.queue.execute(Kind::General, marker, pointer) }.unwrap();
        }
        Mode::Exhaust => {
            let mut owned = Vec::new();
            owned.push(escrow);
            for _ in 1..20 {
                owned.push(
                    r.reserve_general(&authority, kernel())
                        .unwrap()
                        .into_owned()
                        .unwrap(),
                );
            }
            assert!(matches!(
                r.reserve_general(&authority, kernel()),
                Err(WorkError::Full)
            ));
            assert_eq!(r.owned_escrows.get(), 20);
            // Real ordinary peers can run without using any of these C-compatible workers.
            // SAFETY: actual queued marker owns stable Scene and fits ordinary geometry.
            unsafe { r.queue.execute(Kind::General, marker, pointer) }.unwrap();
            r.yield_now().unwrap();
            assert_eq!(f.ordinary.load(Ordering::Relaxed), 1);
            for escrow in owned {
                escrow.cancel(&authority).unwrap();
            }
        }
        Mode::ClosedCancel => {
            r.queue.close().unwrap();
            escrow.cancel(&authority).unwrap();
        }
        Mode::Stale => {
            authority.active.set(false);
            assert_eq!(escrow.cancel(&authority), Err(WorkError::Unavailable));
            return;
        }
        Mode::WrongJob => {
            let flags = f.cpu.save_disable().unwrap();
            // SAFETY: isolated negative test corrupts only this actual creator's
            // captured job sequence at IF0; refusal must retain every mapping.
            unsafe {
                (*r.task(r.current.get())).job.as_mut().unwrap().1.sequence += 1;
            }
            // SAFETY: exact save_disable above; no task borrow survives.
            unsafe { f.cpu.restore(flags) };
            assert_eq!(escrow.cancel(&authority), Err(WorkError::CorruptContext));
            return;
        }
        Mode::Nonce => {
            let mut guard = r.queue.lock().unwrap();
            let slot = guard
                .state()
                .reservations
                .iter()
                .position(|n| *n != 0)
                .unwrap();
            guard.state().reservations[slot] += 1;
            drop(guard);
            assert_eq!(escrow.cancel(&authority), Err(WorkError::CorruptContext));
            return;
        }
        Mode::Foreign | Mode::ForeignDrop => {
            let address = Box::into_raw(Box::new(escrow)) as usize;
            let cpu = f.cpu.clone();
            let mode = f.mode;
            std::thread::spawn(move || {
                // SAFETY: deliberate !Send violation confined to an isolated
                // rejection fixture. Parent retains/joins the actual executor;
                // foreign authority fails before any affine Runtime access.
                let owned =
                    unsafe { Box::from_raw(address as *mut OwnedGeneralEscrow<'static, 64>) };
                if mode == Mode::Foreign {
                    assert_eq!(
                        owned.cancel(&Authority::new(&cpu)),
                        Err(WorkError::WrongCpu)
                    );
                } else {
                    drop(owned);
                }
            })
            .join()
            .unwrap();
            return;
        }
        Mode::Drop => {
            drop(escrow);
            return;
        }
        Mode::Forgotten => {
            core::mem::forget(escrow);
            return;
        }
        _ => unreachable!(),
    }
    assert_eq!(r.owned_escrows.get(), 0);
    assert_eq!(r.pending_reservations.get(), 0);
    assert_eq!(f.cpu.model.flags(), 0x202);
}
fn run(mode: Mode) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let cpu = Arc::new(ModelCpu {
        model: test_support::CpuModel::new(),
        dropped: dropped.clone(),
        mode,
    });
    let f = Arc::new(Scene {
        runtime: AtomicU64::new(0),
        cpu: cpu.clone(),
        mode,
        ordinary: AtomicUsize::new(0),
        parked: AtomicBool::new(false),
        binding: Mutex::new(None),
    });
    // SAFETY: this hosted-thread fixture retains Scene/code through join or quarantine.
    let q = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor = Executor::new_hosted_profile_for_test(
        q,
        support::stacks(&dropped, 20),
        policy(),
        profile(),
    )
    .unwrap();
    let r = executor.runtime();
    f.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    let pointer = Arc::as_ptr(&f) as *mut c_void;
    if mode == Mode::RoundTrip {
        // SAFETY: queued wake peer is retained and runs only after creator's actual park.
        unsafe { r.queue.execute(Kind::General, marker, pointer) }.unwrap();
    }
    if mode == Mode::ForgottenParked {
        // Fixture-owned callback/context remain alive permanently if parked.
        r.queue
            .enqueue_lane(Lane::Foreground, creator, pointer)
            .unwrap();
        assert_eq!(r.step(), Ok(true));
        assert_eq!(r.current.get(), NONE);
        assert_eq!(r.owned_escrows.get(), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert_eq!(
            // SAFETY: deliberate refusal probe: owned markers and a real blocked
            // frame reject before the detach path uses assumed quiescence.
            unsafe { r.retire() },
            Err(WorkError::Pending)
        );
        r.queue.close().unwrap();
        assert_eq!(
            // SAFETY: negative queue refusal probe retains every frame/resource;
            // marked ownership rejects before release could use quiescence.
            unsafe { r.queue.retire() },
            Err(WorkError::Pending)
        );
        drop(executor); // Full allocation is retained despite the forgotten value.
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        return;
    }
    // SAFETY: Scene and all actual mapping owners survive accepted work and join.
    unsafe { r.call_foreground(creator, pointer, cpu.ticks() + 1_000_000_000) }.unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    if let Some((binding, wake)) = f.binding.lock().unwrap().take() {
        // SAFETY: real creator and wake peer returned; every fixture producer stopped.
        drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
        drop(binding);
        drop(wake);
    }
    assert_eq!(
        f.ordinary.load(Ordering::Relaxed),
        match mode {
            Mode::RoundTrip | Mode::Exhaust => 1,
            Mode::Pressure => 55,
            _ => 0,
        }
    );
    r.queue.close().unwrap();
    // SAFETY: every accepted callback joined, all bindings detached, no producers remain.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn owned_exclusion_survives_actual_park_and_peer_return_before_fresh_cancel() {
    run(Mode::RoundTrip);
}
#[test]
fn owned_workers_and_job_slots_stay_exclusive_under_actual_pressure() {
    run(Mode::Pressure);
    run(Mode::Exhaust);
}
#[test]
fn conversion_overflow_and_closed_paths_transfer_or_release_nothing_uncertain() {
    run(Mode::TotalOverflow);
    run(Mode::CreatorOverflow);
    run(Mode::ClosedConversion);
    run(Mode::ClosedCancel);
}
fn isolated(name: &str, mode: &str) {
    let test = format!("{}::{name}", module_path!().split_once("::").unwrap().1);
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
        .env("STELA_ESCROW_TEST_MODE", mode)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(92),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("STELA_ESCROW_FATAL_RETAINED"));
}
#[test]
fn stale_foreign_creator_and_private_nonce_refuse_before_affine_release() {
    if let Ok(mode) = std::env::var("STELA_ESCROW_TEST_MODE") {
        run(match mode.as_str() {
            "stale" => Mode::Stale,
            "job" => Mode::WrongJob,
            "nonce" => Mode::Nonce,
            "foreign" => Mode::Foreign,
            _ => panic!("wrong fixture mode"),
        });
        unreachable!();
    }
    for mode in ["stale", "job", "nonce", "foreign"] {
        isolated(
            "stale_foreign_creator_and_private_nonce_refuse_before_affine_release",
            mode,
        );
    }
}
#[test]
fn dropped_foreign_and_forgotten_owned_values_keep_actual_owners_until_stop() {
    if let Ok(mode) = std::env::var("STELA_ESCROW_TEST_MODE") {
        run(match mode.as_str() {
            "drop" => Mode::Drop,
            "foreign-drop" => Mode::ForeignDrop,
            "forget" => Mode::Forgotten,
            _ => panic!("wrong fixture mode"),
        });
        unreachable!();
    }
    for mode in ["drop", "foreign-drop", "forget"] {
        isolated(
            "dropped_foreign_and_forgotten_owned_values_keep_actual_owners_until_stop",
            mode,
        );
    }
}
#[test]
fn forgotten_parked_escrow_blocks_retirement_and_whole_executor_drop_retains_mappings() {
    run(Mode::ForgottenParked);
}
