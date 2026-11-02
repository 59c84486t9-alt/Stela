//! Real cold backing initialization/reseed, with modeled process permission only.
use super::*;
use core::cell::Cell;
use std::{println, process::Command, string::String};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Bytes,
    Hot,
    Park,
    Denied,
    RestoreRefusal,
    Closed,
    Drop,
    Stale,
    Forget,
}
struct ModelCpu {
    model: Arc<test_support::CpuModel>,
    dropped: Arc<AtomicUsize>,
    mode: Mode,
    watch: AtomicU64,
    watch_state: AtomicU64,
    restored: AtomicBool,
}
// SAFETY: same-host-thread flags only. The bounded watch observes an
// exclusively kept unstarted fixture backing; it never calls Runtime,
// allocates, switches or grants a native CPU/root/provider capability.
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
        if flags & 0x200 != 0 {
            let address = self.watch.load(Ordering::Acquire);
            let state = self.watch_state.load(Ordering::Acquire);
            // SAFETY: an armed watch keeps this exact excluded Task field on
            // the model's same OS thread. Earlier checks may restore flags, but
            // only the Preparing transfer makes this the zeroing boundary.
            let preparing = address != 0
                && unsafe { (state as *const TaskState).read() } == TaskState::Preparing;
            if preparing {
                self.watch.store(0, Ordering::Release);
                assert_eq!(
                    // SAFETY: creator armed the exact owned cold usable base
                    // after poisoning it; backing stays held through this read.
                    unsafe { (address as *const u8).read_volatile() },
                    0xa7
                );
                self.restored.store(true, Ordering::Release);
            }
        }
        // SAFETY: flags are this same model's enclosing save_disable.
        unsafe { self.model.restore(flags) }
    }
    fn ticks(&self) -> u64 {
        self.model.ticks()
    }
    fn fatal(&self, error: WorkError) -> ! {
        if matches!(self.mode, Mode::Drop | Mode::Stale | Mode::Forget) {
            assert_eq!(
                error,
                if self.mode == Mode::Forget {
                    WorkError::Pending
                } else {
                    WorkError::Closed
                }
            );
            assert_eq!(self.dropped.load(Ordering::Relaxed), 0);
            println!("STELA_COLD_FATAL_RETAINED {:?}", self.mode);
            std::process::exit(93);
        }
        panic!("unexpected cold fixture fatal {error:?}")
    }
}
struct Authority {
    cpu: Arc<ModelCpu>,
    active: Cell<bool>,
}
impl Authority {
    fn new(cpu: &Arc<ModelCpu>) -> Self {
        Self {
            cpu: cpu.clone(),
            active: Cell::new(true),
        }
    }
}
// SAFETY: hosted callback model checks its OS thread and active borrowed
// segment without allocation/wait, including IF0. Native DriverExecution and
// Guest park/reentry remain separate production validation requirements.
unsafe impl EnteredProcess for Authority {
    fn check(&self) -> Result<(), WorkError> {
        self.cpu.check_cpu()?;
        if self.active.get()
            && !(self.cpu.mode == Mode::RestoreRefusal && self.cpu.restored.load(Ordering::Acquire))
        {
            Ok(())
        } else {
            Err(WorkError::Unavailable)
        }
    }
}
struct Scene {
    runtime: AtomicU64,
    cpu: Arc<ModelCpu>,
    mode: Mode,
    marked: AtomicUsize,
    hot: Mutex<Option<ContextId>>,
    binding: Mutex<Option<(Arc<Binding>, WakeHandle<64>)>>,
}
impl Scene {
    fn runtime(&self) -> Pin<&Runtime<64>> {
        // SAFETY: exact pinned executor is held through every fixture use;
        // fatal paths keep the complete allocation before any destruction.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>))
        }
    }
    fn reserved(&self) -> (usize, core::ops::Range<usize>) {
        let r = self.runtime();
        let flags = self.cpu.save_disable().unwrap();
        // SAFETY: creator/dispatcher fixture holds IF0 and all peers are
        // stopped. These reads inspect immutable kept geometry/history only.
        let found = unsafe {
            (&*r.tasks.get())
                .iter()
                .enumerate()
                .find(|(_, t)| t.state == TaskState::Escrow)
                .map(|(i, t)| (i, t.stack.bounds.clone()))
        }
        .unwrap();
        // SAFETY: enclosing model flags, no task borrow survives restore.
        unsafe { self.cpu.restore(flags) };
        found
    }
}
unsafe extern "C" fn marker(pointer: *mut c_void) {
    // SAFETY: Scene/code remain queue-owned through completion/quarantine.
    let f = unsafe { &*pointer.cast::<Scene>() };
    let r = f.runtime();
    f.marked.fetch_add(1, Ordering::Relaxed);
    if f.mode == Mode::Hot {
        *f.hot.lock().unwrap() = Some(r.current_id().unwrap());
    }
    if f.mode == Mode::Park {
        assert_eq!(r.owned_escrows.get(), 1);
        let (binding, wake) = f.binding.lock().unwrap().as_ref().unwrap().clone();
        binding.blocked.store(false, Ordering::Release);
        wake.wake().unwrap();
    }
}
fn take_prepared<'a>(
    owner: OwnedGeneralEscrow<'a, 64>,
    authority: &dyn EnteredProcess,
) -> GeneralStackPreparation<'a, 64> {
    match unsafe { owner.prepare_stack(authority) } {
        Ok(cold) => cold,
        Err((owner, error)) => {
            unsafe { owner.cancel(authority) }.unwrap();
            panic!("cold precheck failed {error:?}")
        }
    }
}
unsafe extern "C" fn creator(pointer: *mut c_void) {
    // SAFETY: queue owns Scene and this Foreground stack through join.
    let f = unsafe { &*pointer.cast::<Scene>() };
    let r = f.runtime();
    let authority = Authority::new(&f.cpu);
    if f.mode == Mode::Hot {
        let hot = f.hot.lock().unwrap().unwrap();
        let owner = r
            .reserve_general(&authority, kernel())
            .unwrap()
            .into_owned()
            .unwrap();
        let (index, _) = f.reserved();
        assert_eq!(
            // SAFETY: unbound idle reserved worker; no peer can mutate it.
            unsafe { (*r.task(index)).id },
            hot
        );
        // The prior marker actually returned through the native dispatcher;
        // no original C/page/alias user exists in this real-stack fixture.
        // Preserve history and require a NEW source allocation epoch.
        let prepared = match unsafe { owner.prepare_stack(&authority) } {
            Ok(prepared) => prepared,
            Err(_) => panic!("physically returned frame refused"),
        };
        assert!(prepared.epoch().is_some());
        assert!(unsafe { (*r.task(index)).ever_entered });
        assert_eq!(unsafe { (*r.task(index)).completed_sequence }, unsafe {
            (*r.task(index)).returned_sequence
        });
        // SAFETY: this fixture has no foreign C/descriptor/page/alias user.
        unsafe { prepared.cancel(&authority) }.unwrap();
        assert!(unsafe { (*r.task(index)).ever_entered });
    }
    let owner = r
        .reserve_unstarted_general(&authority, kernel())
        .unwrap()
        .into_owned()
        .unwrap();
    let (index, range) = f.reserved();
    assert!(
        // SAFETY: worker is held/excluded/unbound. Private history
        // is written only by real entry, which cannot run while reserved.
        !unsafe { (*r.task(index)).ever_entered }
    );
    if f.mode == Mode::Hot {
        assert_ne!(
            // SAFETY: same excluded worker; only identity is read.
            unsafe { (*r.task(index)).id },
            f.hot.lock().unwrap().unwrap()
        );
    }
    if matches!(f.mode, Mode::Denied | Mode::Closed) {
        if f.mode == Mode::Denied {
            authority.active.set(false);
        } else {
            r.queue.close().unwrap();
        }
        let owner = match unsafe { owner.prepare_stack(&authority) } {
            Err((owner, error)) => {
                assert_eq!(
                    error,
                    if f.mode == Mode::Denied {
                        WorkError::Unavailable
                    } else {
                        WorkError::Closed
                    }
                );
                owner
            }
            _ => panic!("failed precheck mutated"),
        };
        authority.active.set(true);
        unsafe { owner.cancel(&authority) }.unwrap();
        return;
    }
    let top = range.end - 2 * size_of::<usize>();
    // SAFETY: never-entered kept range has only the constructor's
    // two bootstrap words. Copy those initialized words, then poison only the
    // other usable bytes; both PROT_NONE guards and bootstrap remain untouched.
    let before = unsafe {
        let words = (top as *const usize).read();
        let zero = ((top + size_of::<usize>()) as *const usize).read();
        core::ptr::write_bytes(range.start as *mut u8, 0xa7, top - range.start);
        (words, zero)
    };
    // SAFETY: exact excluded worker, immutable Task allocation; the
    // same-thread restore observer reads only its preparation state.
    let state = unsafe { core::ptr::addr_of!((*r.task(index)).state) };
    f.cpu.watch_state.store(state as u64, Ordering::Release);
    f.cpu.watch.store(range.start as u64, Ordering::Release);
    if f.mode == Mode::RestoreRefusal {
        // SAFETY: the real excluded mapping has no C/page/alias users. The
        // actual outer restore observer revokes this scope AFTER transfer.
        let prepared = match unsafe { owner.prepare_stack(&authority) } {
            Err((prepared, WorkError::Unavailable)) => prepared,
            _ => panic!("post-transfer refusal lost exact preparation owner"),
        };
        assert!(f.cpu.restored.load(Ordering::Acquire));
        assert_eq!(prepared.epoch(), Some(1));
        assert_eq!(f.cpu.model.flags(), 0x202);
        // SAFETY: exact excluded backing; the failed fresh scope must prevent
        // every destructive write, including native bootstrap words.
        unsafe {
            assert!(
                core::slice::from_raw_parts(range.start as *const u8, top - range.start)
                    .iter()
                    .all(|byte| *byte == 0xa7)
            );
            assert_eq!((top as *const usize).read(), before.0);
            assert_eq!(
                ((top + size_of::<usize>()) as *const usize).read(),
                before.1
            );
        }
        f.cpu.restored.store(false, Ordering::Release);
        // SAFETY: fresh scope regained; exact transferred owner has no pin or
        // published user, so cancellation must reseed and release only once.
        unsafe { prepared.cancel(&authority) }.unwrap();
        assert_eq!(r.owned_escrows.get(), 0);
        return;
    }
    let cold = take_prepared(owner, &authority);
    assert!(f.cpu.restored.load(Ordering::Acquire));
    assert_eq!(f.cpu.model.flags(), 0x202);
    assert!(
        // SAFETY: Preparing keeps/excludes this entire mapped usable
        // range. Production exposes no byte/address API; zeroing initialized it.
        unsafe { core::slice::from_raw_parts(range.start as *const u8, range.len()) }
            .iter()
            .all(|v| *v == 0)
    );
    match f.mode {
        Mode::Drop => {
            drop(cold);
            return;
        }
        Mode::Stale => {
            authority.active.set(false);
            assert_eq!(
                cancellation_error(unsafe { cold.cancel(&authority) }),
                WorkError::Unavailable
            );
            return;
        }
        Mode::Forget => {
            core::mem::forget(cold);
            return;
        }
        Mode::Park => {
            let binding = Arc::new(Binding {
                id: AtomicU64::new(0),
                blocked: AtomicBool::new(true),
            });
            let wake = r.bind_current(binding.clone()).unwrap();
            *f.binding.lock().unwrap() = Some((binding, wake));
            authority.active.set(false);
            drop(authority);
            assert_eq!(r.park_if_blocked().unwrap(), ParkOutcome::Resumed);
            unsafe { cold.cancel(&Authority::new(&f.cpu)) }.unwrap();
        }
        _ => unsafe { cold.cancel(&authority) }.unwrap(),
    }
    assert_eq!(r.owned_escrows.get(), 0);
    // SAFETY: exact cold frame is reseeded but still never entered. Reading its
    // two initialized bootstrap words and zeroed preceding bytes touches no guard.
    unsafe {
        assert_eq!((top as *const usize).read(), before.0);
        assert_eq!(
            ((top + size_of::<usize>()) as *const usize).read(),
            before.1
        );
        assert!(
            core::slice::from_raw_parts(range.start as *const u8, top - range.start)
                .iter()
                .all(|v| *v == 0)
        );
    }
    if f.mode != Mode::Park {
        // SAFETY: exact queue-kept marker fits real compiled kernel geometry;
        // after reseed/cancel the original entry frame must run normally.
        unsafe {
            r.queue
                .execute_general_with_requirement(kernel(), marker, pointer)
        }
        .unwrap();
    }
}
fn run(mode: Mode) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let cpu = Arc::new(ModelCpu {
        model: test_support::CpuModel::new(),
        dropped: dropped.clone(),
        mode,
        watch: AtomicU64::new(0),
        watch_state: AtomicU64::new(0),
        restored: AtomicBool::new(false),
    });
    let f = Arc::new(Scene {
        runtime: AtomicU64::new(0),
        cpu: cpu.clone(),
        mode,
        marked: AtomicUsize::new(0),
        hot: Mutex::new(None),
        binding: Mutex::new(None),
    });
    // SAFETY: same-thread model and Scene remain held through join/quarantine.
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
    if mode == Mode::Hot {
        // SAFETY: exact kernel-size marker enters one worker.
        unsafe {
            r.queue
                .execute_general_with_requirement(kernel(), marker, pointer)
        }
        .unwrap();
        r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    }
    if mode == Mode::Park {
        // SAFETY: ordinary wake peer cannot run inline and owns no cold bytes.
        unsafe { r.queue.execute(Kind::General, marker, pointer) }.unwrap();
    }
    // SAFETY: real Foreground callback/context and all mappings survive joins.
    unsafe { r.call_foreground(creator, pointer, cpu.ticks() + 1_000_000_000) }.unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    if let Some((binding, wake)) = f.binding.lock().unwrap().take() {
        // SAFETY: callback/wake peer completed; all external fixture producers stopped.
        drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
        drop(binding);
        drop(wake);
    }
    assert_eq!(
        f.marked.load(Ordering::Relaxed),
        match mode {
            Mode::Bytes | Mode::Park => 1,
            Mode::Hot => 2,
            _ => 0,
        }
    );
    r.queue.close().unwrap();
    // SAFETY: no external producer can enqueue/resume; CPU/backing kept.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn cold_usable_bytes_zero_after_if_restore_and_frame_reseed_runs() {
    run(Mode::Bytes);
}
#[test]
fn hot_idle_frame_is_rejected_while_real_unstarted_selection_finds_cold_peer() {
    run(Mode::Hot);
}
#[test]
fn cold_owner_survives_real_park_until_fresh_creator_permission_reseeds() {
    run(Mode::Park);
}
#[test]
fn denied_and_closed_prechecks_return_original_owned_exclusion() {
    run(Mode::Denied);
    run(Mode::Closed);
}
fn isolated(mode: &str) {
    let test = format!(
        "{}::stale_dropped_and_forgotten_cold_values_never_reseed_or_free",
        module_path!().split_once("::").unwrap().1
    );
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
        .env("STELA_COLD_TEST_MODE", mode)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(93),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("STELA_COLD_FATAL_RETAINED"));
}
#[test]
fn stale_dropped_and_forgotten_cold_values_never_reseed_or_free() {
    if let Ok(mode) = std::env::var("STELA_COLD_TEST_MODE") {
        run(match mode.as_str() {
            "stale" => Mode::Stale,
            "drop" => Mode::Drop,
            "forget" => Mode::Forget,
            _ => panic!("wrong fixture mode"),
        });
        unreachable!();
    }
    for mode in ["stale", "drop", "forget"] {
        isolated(mode);
    }
}

mod pinned;

#[test]
fn outer_restore_scope_loss_retains_unzeroed_preparation_until_fresh_cancel() {
    run(Mode::RestoreRefusal);
}
