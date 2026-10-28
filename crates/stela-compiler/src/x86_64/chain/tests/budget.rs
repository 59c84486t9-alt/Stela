//! Native interruption-gate safety and CPU measurements.
use super::super::*;
use alloc::{boxed::Box, format, vec, vec::Vec};
use core::ffi::c_void;
use std::{
    fs,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
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
struct Mapping {
    page: *mut c_void,
}
impl Mapping {
    fn new() -> Self {
        // SAFETY: one private anonymous page; this object owns it through Drop.
        let page = unsafe { mmap(core::ptr::null_mut(), 4096, 3, 0x22, -1, 0) };
        assert_ne!(page as usize, usize::MAX);
        Self { page }
    }
    fn address(&self) -> u64 {
        self.page as usize as u64
    }
    fn install(&self, code: &[u8]) {
        assert!(code.len() <= 4096);
        // SAFETY: the owned RW page covers code and has no concurrent executor;
        // it becomes RX before run and remains mapped through native return.
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), self.page.cast(), code.len());
            assert_eq!(mprotect(self.page, 4096, 5), 0);
        }
    }
    fn run(&self) -> u128 {
        // SAFETY: installed thunk has the SysV128 return ABI and touches only
        // its retained control/table. It clobbers caller-volatile registers.
        unsafe {
            let enter: unsafe extern "sysv64" fn() -> u128 = core::mem::transmute(self.page);
            enter()
        }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: unique mapping ownership; every executor has returned or joined.
        assert_eq!(unsafe { munmap(self.page, 4096) }, 0);
    }
}
const TARGET: GuestAddress = GuestAddress(0x1234);
const INTERRUPT_TEST_BUDGET: u64 = 100_000_000;
fn direct(mapping: &Mapping, control: u64, policy: Interruption) -> Vec<u8> {
    thunk_with_policy(
        ThunkPlan {
            at: mapping.address(),
            control,
            retired: 7,
            block: 3,
            entry: mapping.address(),
            target: TARGET,
            kind: ExitKind::Direct,
        },
        policy,
    )
    .unwrap()
}
fn exited(value: u128) -> (u64, u64) {
    (value as u64, (value >> 64) as u64)
}

#[test]
fn epoch_mismatch_exits_before_spending_or_changing_accounting() {
    let mut control = Box::new(ChainControl {
        budget: 17,
        retired: 19,
        linked: 23,
        block: 29,
        interrupt_epoch: 1,
        observed_interrupt_epoch: 0,
        ..ChainControl::default()
    });
    let native = Mapping::new();
    native.install(&direct(
        &native,
        (&mut *control as *mut ChainControl) as u64,
        Interruption::Epoch,
    ));
    assert_eq!(exited(native.run()), (TARGET.0, ExitKind::Direct as u64));
    assert_eq!(
        (
            control.budget,
            control.retired,
            control.linked,
            control.block
        ),
        (17, 19, 23, 29)
    );
    control.interrupt_epoch = u64::MAX;
    control.observed_interrupt_epoch = u64::MAX - 1;
    assert_eq!(exited(native.run()), (TARGET.0, ExitKind::Direct as u64));
    assert_eq!(
        (
            control.budget,
            control.retired,
            control.linked,
            control.block
        ),
        (17, 19, 23, 29)
    );
}

#[test]
fn dynamic_lookup_pending_and_saturated_epochs_never_touch_the_invalid_table() {
    for (kind, btype) in [(ExitKind::Return, 0), (ExitKind::Indirect, 3)] {
        let mut control = Box::new(ChainControl {
            budget: 17,
            retired: 19,
            hits: 23,
            linked: 29,
            block: 31,
            table: 1 << 63,
            ..ChainControl::default()
        });
        let native = Mapping::new();
        let mut prefix = Code::new();
        prefix.asm().mov_imm64(Rax, TARGET.0);
        let mut code = prefix.into_bytes();
        code.extend(
            lookup_thunk(
                (&mut *control as *mut ChainControl) as u64,
                7,
                None,
                kind,
                btype,
            )
            .unwrap(),
        );
        native.install(&code);
        for (epoch, observed) in [(1, 0), (u64::MAX, u64::MAX - 1)] {
            control.interrupt_epoch = epoch;
            control.observed_interrupt_epoch = observed;
            let prior = (
                control.budget,
                control.retired,
                control.hits,
                control.linked,
                control.block,
            );
            assert_eq!(exited(native.run()), (TARGET.0, kind as u64));
            assert_eq!(
                (
                    control.budget,
                    control.retired,
                    control.hits,
                    control.linked,
                    control.block
                ),
                prior
            );
        }
    }
}

/// Every Rust access is atomic; native aligned loads/stores implement x86's
/// corresponding atomic-width memory accesses. The native runner alone writes
/// the local prefix; the notifying CPU writes only the separate epoch word.
#[repr(C, align(64))]
struct Shared {
    budget: AtomicU64,
    retired: AtomicU64,
    block: AtomicU64,
    contexts: [AtomicU64; 2],
    table: AtomicU64,
    hits: AtomicU64,
    linked: AtomicU64,
    epoch: AtomicU64,
    observed: AtomicU64,
}
const _: () = assert!(core::mem::offset_of!(Shared, epoch) == INTERRUPT_EPOCH as usize);
const _: () = assert!(core::mem::offset_of!(Shared, observed) == OBSERVED_INTERRUPT_EPOCH as usize);
const _: () = assert!(core::mem::offset_of!(Shared, linked) == LINKED as usize);
impl Shared {
    fn new() -> Self {
        Self {
            budget: AtomicU64::new(INTERRUPT_TEST_BUDGET),
            retired: AtomicU64::new(0),
            block: AtomicU64::new(0),
            contexts: [AtomicU64::new(0), AtomicU64::new(0)],
            table: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            linked: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
            observed: AtomicU64::new(0),
        }
    }
}

#[test]
fn foreign_epoch_interrupts_the_actual_native_backedge_with_at_most_one_more_transfer() {
    let mut interrupted = 0;
    for attempt in 0..128 {
        let control = Arc::new(Shared::new());
        let native = Mapping::new();
        native.install(&direct(
            &native,
            Arc::as_ptr(&control) as u64,
            Interruption::Epoch,
        ));
        let entry = native.address() as usize;
        let retained = Arc::clone(&control);
        let worker = std::thread::spawn(move || {
            // SAFETY: main retains the RX mapping until this join; retained
            // storage keeps every embedded address live. Only this thread
            // writes native local counters, and RDX/RCX/RAX are caller-volatile.
            let result = unsafe {
                let run: unsafe extern "sysv64" fn() -> u128 = core::mem::transmute(entry);
                run()
            };
            (result, retained)
        });
        let began = Instant::now();
        while control.linked.load(Ordering::Acquire) < 1000 {
            if began.elapsed() >= Duration::from_secs(5) {
                control.epoch.fetch_add(1, Ordering::Release);
                let _ = worker.join();
                panic!("native backedge did not reach the bounded observation point");
            }
            std::thread::yield_now();
        }
        // Source publication precedes this Release RMW in the runtime owner.
        control.epoch.fetch_add(1, Ordering::Release);
        let published = control.linked.load(Ordering::Acquire);
        let (result, retained) = worker.join().unwrap();
        let final_count = retained.linked.load(Ordering::Acquire);
        if published >= INTERRUPT_TEST_BUDGET - 1 {
            std::eprintln!(
                "native interruption attempt {attempt} had no provable budget headroom at publication; retrying"
            );
            continue;
        }
        assert!(
            final_count < INTERRUPT_TEST_BUDGET,
            "notification must end the native run before natural exhaustion"
        );
        assert!(
            retained.budget.load(Ordering::Acquire) > 0,
            "interruption leaves a positive local budget"
        );
        assert!(
            final_count <= published + 1,
            "a notification can race only the already-checked boundary"
        );
        assert_eq!(exited(result), (TARGET.0, ExitKind::Direct as u64));
        assert_eq!(retained.retired.load(Ordering::Acquire), final_count * 7);
        assert_eq!(
            retained.budget.load(Ordering::Acquire),
            INTERRUPT_TEST_BUDGET - final_count
        );
        interrupted += 1;
        if interrupted == 32 {
            break;
        }
    }
    assert_eq!(
        interrupted, 32,
        "scheduler did not establish 32 interruption attempts with budget headroom"
    );
}

#[repr(align(64))]
struct Aligned(ChainControl);
#[test]
#[ignore = "manual: opt-in"]
fn native_interruption_gate_costs() {
    const ITERATIONS: u64 = 500_000;
    let output = std::env::var_os("STELA_TEST_CHAIN_BENCH_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("stela-chain-bench-{}", std::process::id()))
        });
    fs::create_dir_all(&output).unwrap();
    let mut report = fs::File::create(output.join("results.txt")).unwrap();
    writeln!(
        report,
        "COMPILER_SHA256={} ITERATIONS={ITERATIONS} SAMPLES=7",
        crate::SOURCE_SHA256
    )
    .unwrap();
    for lookup in [false, true] {
        let mut table = vec![LookupEntry::default(); LOOKUP_ENTRIES];
        let mut control = Box::new(Aligned(ChainControl {
            table: table.as_ptr() as u64,
            contexts: [5, 7],
            ..ChainControl::default()
        }));
        let pointer = (&mut control.0 as *mut ChainControl) as u64;
        for policy in [
            Interruption::Legacy,
            Interruption::LockedBudget,
            Interruption::Flag,
            Interruption::Epoch,
        ] {
            let native = Mapping::new();
            let code = if lookup {
                table[lookup_slot(TARGET.0)] = LookupEntry {
                    pc: TARGET.0,
                    context: 5,
                    entry: native.address(),
                    block: 3,
                    targets: 15,
                };
                lookup_with_policy(pointer, 7, Some(TARGET), ExitKind::Direct, 0, policy).unwrap()
            } else {
                direct(&native, pointer, policy)
            };
            native.install(&code);
            let name = format!("{}-{policy:?}", if lookup { "lookup" } else { "direct" });
            fs::write(output.join(format!("{name}.bin")), &code).unwrap();
            let mut samples = Vec::new();
            for sample in 0..8 {
                control.0.budget = ITERATIONS;
                control.0.retired = 0;
                control.0.hits = 0;
                control.0.linked = 0;
                let start = Instant::now();
                let result = native.run();
                let elapsed = start.elapsed();
                assert_eq!(exited(result), (TARGET.0, ExitKind::Direct as u64));
                assert_eq!(control.0.retired, ITERATIONS * 7);
                assert_eq!(
                    if lookup {
                        control.0.hits
                    } else {
                        control.0.linked
                    },
                    ITERATIONS
                );
                if sample != 0 {
                    samples.push(elapsed.as_nanos() as f64 / ITERATIONS as f64);
                }
            }
            samples.sort_by(f64::total_cmp);
            let line = format!(
                "CASE={name} BYTES={} NS_PER_TRANSFER={:.4} MIN={:.4} MAX={:.4}",
                code.len(),
                samples[3],
                samples[0],
                samples[6]
            );
            std::eprintln!("{line}");
            writeln!(report, "{line}").unwrap();
        }
    }
    std::eprintln!("CHAIN_BENCH_OUTPUT={}", output.display());
}
