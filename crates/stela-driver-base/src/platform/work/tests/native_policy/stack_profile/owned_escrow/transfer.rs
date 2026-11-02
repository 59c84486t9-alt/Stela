//! Real reservation counters/guarded continuations; CPU permission is a model.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransferCase {
    Fresh,
    Foreign,
    Nonce,
    EarlyUnwind,
    LateUnwind,
    Abandon,
}
struct TransferCpu {
    model: Arc<test_support::CpuModel>,
    runtime: AtomicU64,
    arm: AtomicBool,
    case: TransferCase,
    dropped: Arc<AtomicUsize>,
}
impl TransferCpu {
    fn runtime(&self) -> Pin<&Runtime<64>> {
        // SAFETY: setup keeps the exact pinned Executor through every fixture
        // callback/join; fatal child processes retain every allocation.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>))
        }
    }
}
// SAFETY: same-host-thread model flags/identity. The armed observer restores
// saved flags first and reads private fixture state only after actual transfer;
// it does not publish work, wait, allocate or claim native hardware authority.
unsafe impl Cpu for TransferCpu {
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
        // SAFETY: this same model's enclosing save_disable flags.
        unsafe { self.model.restore(flags) };
        if flags & 0x200 != 0
            && self.case == TransferCase::LateUnwind
            && self.arm.swap(false, Ordering::AcqRel)
        {
            let r = self.runtime();
            assert_eq!(r.pending_reservations.get(), 0);
            assert_eq!(r.owned_escrows.get(), 1);
            // SAFETY: same fixture CPU, no native switch or foreign mutation.
            assert_eq!(unsafe { (*r.task(r.current.get())).owned_escrows }, 1);
            panic!("injected restore tail after actual owned transfer");
        }
    }
    fn ticks(&self) -> u64 {
        self.model.ticks()
    }
    fn fatal(&self, error: WorkError) -> ! {
        assert!(matches!(
            self.case,
            TransferCase::EarlyUnwind | TransferCase::LateUnwind | TransferCase::Abandon
        ));
        assert_eq!(error, WorkError::Closed);
        let r = self.runtime();
        assert!(r.queue.abandoned.load(Ordering::Acquire));
        assert_eq!(
            r.pending_reservations.get(),
            usize::from(self.case != TransferCase::LateUnwind)
        );
        assert_eq!(
            r.owned_escrows.get(),
            usize::from(self.case == TransferCase::LateUnwind)
        );
        assert_eq!(self.dropped.load(Ordering::Acquire), 0);
        println!("STELA_TRANSFER_RETAINED {:?}", self.case);
        std::process::exit(97)
    }
}
struct Permission {
    cpu: Arc<TransferCpu>,
    active: Cell<bool>,
}
impl Permission {
    fn new(cpu: &Arc<TransferCpu>) -> Self {
        Self {
            cpu: cpu.clone(),
            active: Cell::new(true),
        }
    }
}
// SAFETY: bounded hosted active-scope/thread model only. The fault disarms
// before unwinding, so an implicit borrowed rollback would wrongly succeed and
// be distinguished from the required owned retention by the counter control.
unsafe impl EnteredProcess for Permission {
    fn check(&self) -> Result<(), WorkError> {
        self.cpu.check_cpu()?;
        if self.cpu.case == TransferCase::EarlyUnwind && self.cpu.arm.swap(false, Ordering::AcqRel)
        {
            let r = self.cpu.runtime();
            assert_eq!(r.pending_reservations.get(), 1);
            assert_eq!(r.owned_escrows.get(), 0);
            panic!("injected first transfer permission check");
        }
        if self.active.get() {
            Ok(())
        } else {
            Err(WorkError::Unavailable)
        }
    }
}
struct TransferScene {
    cpu: Arc<TransferCpu>,
}
unsafe extern "C" fn convert(pointer: *mut c_void) {
    // SAFETY: the same Queue retains fixture/code through this exact callback.
    let f = unsafe { &*pointer.cast::<TransferScene>() };
    // SAFETY: setup retains this actual Executor through all native joins.
    let r: Pin<&'static Runtime<64>> = unsafe {
        Pin::new_unchecked(&*(f.cpu.runtime.load(Ordering::Acquire) as *const Runtime<64>))
    };
    let original = r.current_context().unwrap();
    if matches!(
        f.cpu.case,
        TransferCase::EarlyUnwind | TransferCase::LateUnwind
    ) {
        let permission = Permission::new(&f.cpu);
        let reserved = r.reserve_general(&permission, kernel()).unwrap();
        f.cpu.arm.store(true, Ordering::Release);
        assert!(catch_unwind(AssertUnwindSafe(|| reserved.into_owned())).is_err());
        assert_eq!(f.cpu.model.flags(), 0x202);
        assert!(r.queue.abandoned.load(Ordering::Acquire));
        assert_eq!(f.cpu.dropped.load(Ordering::Acquire), 0);
        return; // Native current validation must take the retaining fatal path.
    }
    // This lexical scope is a compile control: no entered-process reference
    // can occur in the value which survives the permission's destruction.
    let failure = {
        let permission = Permission::new(&f.cpu);
        let reserved = r.reserve_general(&permission, kernel()).unwrap();
        permission.active.set(false);
        reserved.into_owned().unwrap_err()
    };
    assert_eq!(failure.error, WorkError::Unavailable);
    assert_eq!(r.pending_reservations.get(), 1);
    assert_eq!(r.owned_escrows.get(), 0);
    assert_eq!(r.yield_now(), Err(WorkError::Busy));
    if f.cpu.case == TransferCase::Abandon {
        drop(failure);
        return;
    }
    let failure = if f.cpu.case == TransferCase::Foreign {
        let address = Box::into_raw(Box::new(failure)) as usize;
        let cpu = f.cpu.clone();
        let address = thread::spawn(move || {
            // SAFETY: actual kept Rust owner moves for this negative test only;
            // foreign permission must reject before any affine Runtime access.
            let failure =
                unsafe { *Box::from_raw(address as *mut OwnedTransferFailure<'static, 64>) };
            let (failure, error) = failure.cancel(&Permission::new(&cpu)).unwrap_err();
            assert_eq!(error, WorkError::WrongCpu);
            Box::into_raw(Box::new(failure)) as usize
        })
        .join()
        .unwrap();
        // SAFETY: exact owner returned from joined thread; original fixture
        // CPU again owns it and all backing was kept during the rejection.
        unsafe { *Box::from_raw(address as *mut OwnedTransferFailure<'static, 64>) }
    } else {
        failure
    };
    let permission = Permission::new(&f.cpu);
    let failure = if f.cpu.case == TransferCase::Nonce {
        let (slot, nonce) = {
            let mut guard = r.queue.lock().unwrap();
            let state = guard.state();
            let slot = state
                .reservations
                .iter()
                .position(|nonce| *nonce != 0)
                .unwrap();
            let nonce = state.reservations[slot];
            state.reservations[slot] = nonce + 1;
            (slot, nonce)
        };
        let (failure, error) = failure.cancel(&permission).unwrap_err();
        assert_eq!(error, WorkError::CorruptContext);
        assert_eq!(r.pending_reservations.get(), 1);
        assert_eq!(r.owned_escrows.get(), 0);
        r.queue.lock().unwrap().state().reservations[slot] = nonce;
        failure
    } else {
        failure
    };
    assert!(!r.queue.abandoned.load(Ordering::Acquire));
    let cancelled = failure.cancel(&permission).unwrap();
    assert_eq!(cancelled.queue_id(), original.queue_id);
    assert_ne!(cancelled.context_id().get(), original.context_id);
    let _cancelled = cancelled;
    assert_eq!(r.pending_reservations.get(), 0);
    assert_eq!(r.owned_escrows.get(), 0);
    assert!(
        r.queue
            .lock()
            .unwrap()
            .state()
            .reservations
            .iter()
            .all(|nonce| *nonce == 0)
    );
    let current = r.current_context().unwrap();
    assert_eq!(current.queue_id, original.queue_id);
    assert_eq!(current.context_id, original.context_id);
    assert_eq!(current.sequence, original.sequence);
}
fn run(case: TransferCase) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let cpu = Arc::new(TransferCpu {
        model: test_support::CpuModel::new(),
        runtime: AtomicU64::new(0),
        arm: AtomicBool::new(false),
        case,
        dropped: dropped.clone(),
    });
    let f = Arc::new(TransferScene { cpu: cpu.clone() });
    // SAFETY: same hosted thread, real protected stacks and retained fixture/code.
    let q = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor = Executor::new_hosted_profile_for_test(
        q,
        support::stacks(&dropped, 20),
        policy(),
        profile(),
    )
    .unwrap();
    let r = executor.runtime();
    cpu.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    // SAFETY: actual callback and fixture survive exact completion or fatal retention.
    unsafe {
        r.call_foreground(
            convert,
            Arc::as_ptr(&f) as *mut c_void,
            cpu.ticks() + 1_000_000_000,
        )
    }
    .unwrap();
    r.queue.close().unwrap();
    // SAFETY: all real callbacks completed and every exclusion was canceled;
    // no source/C/foreign producer exists and admission is closed.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Acquire), 32);
}
#[test]
fn failed_transfer_outlives_borrowed_scope_then_cancels_exact_reservation() {
    run(TransferCase::Fresh);
}
#[test]
fn failed_transfer_foreign_cancel_returns_the_same_owner_for_fresh_scope() {
    run(TransferCase::Foreign);
}
#[test]
fn failed_rollback_cannot_issue_cancel_receipt_or_release_the_exclusion() {
    run(TransferCase::Nonce);
}
#[test]
fn unwind_and_abandoned_transfer_keep_native_counters_and_mappings() {
    if let Ok(mode) = std::env::var("STELA_TRANSFER_MODE") {
        run(match mode.as_str() {
            "early" => TransferCase::EarlyUnwind,
            "late" => TransferCase::LateUnwind,
            "abandon" => TransferCase::Abandon,
            _ => panic!("invalid transfer mode"),
        });
        unreachable!();
    }
    let selector = format!(
        "{}::unwind_and_abandoned_transfer_keep_native_counters_and_mappings",
        module_path!().split_once("::").unwrap().1
    );
    for mode in ["early", "late", "abandon"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &selector, "--nocapture", "--test-threads=1"])
            .env("STELA_TRANSFER_MODE", mode)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(97),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("STELA_TRANSFER_RETAINED"));
    }
}
