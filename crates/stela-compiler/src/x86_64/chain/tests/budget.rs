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
const INTERRUPT_TEST_BUDGET: u64 = 4096;
const RENDEZVOUS_AFTER: u64 = 1000;
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

/// A test successor rendezvous orders the runner's prior plain accounting
/// stores before publication. A notifier-side count load alone cannot do that:
/// x86 permits a later epoch load to pass earlier stores to another address.
#[repr(C, align(64))]
struct Rendezvous {
    ready: AtomicU64,
    release: AtomicU64,
}

#[derive(Debug)]
struct InterruptionOutcome {
    published: u64,
    linked: u64,
    retired: u64,
    budget: u64,
    block: u64,
    epoch: u64,
    observed: u64,
    result: (u64, u64),
}
impl InterruptionOutcome {
    fn interrupted_at_rendezvous(&self) -> bool {
        self.published == RENDEZVOUS_AFTER
            && self.linked == self.published
            && self.linked < INTERRUPT_TEST_BUDGET
            && self.budget == INTERRUPT_TEST_BUDGET - self.linked
            && self.retired == self.linked * 7
            && self.block == 3
            && self.epoch == 1
            && self.observed == 0
            && self.result == (TARGET.0, ExitKind::Direct as u64)
    }
}

/// Only the successor prefix is test synchronization; the thunk is emitted by
/// the production constructor with its normal guard and accounting unchanged.
fn rendezvous_backedge(native: &Mapping, control: u64, gate: u64, policy: Interruption) -> Vec<u8> {
    let mut prefix = Code::new();
    prefix.asm().mov_imm64(Rcx, control);
    prefix.asm().alu_imm32(
        Alu::Cmp,
        Qword,
        Mem::base(Rcx, LINKED),
        RENDEZVOUS_AFTER as i32,
    );
    let ordinary = prefix.asm().jcc8(Cond::Ne);
    prefix.asm().mov_imm64(Rax, gate);
    {
        let mut asm = prefix.asm();
        // This worker-side locked publication orders all earlier native
        // accounting stores; it is absent from the production thunk.
        // Intel SDM Vol. 3: loads/stores are not reordered with locked instructions.
        asm.lock();
        asm.alu_imm8(
            Alu::Add,
            Qword,
            Mem::base(Rax, core::mem::offset_of!(Rendezvous, ready) as i32),
            1,
        );
    }
    let waiting = prefix.len();
    prefix.asm().pause();
    prefix.asm().alu_imm8(
        Alu::Cmp,
        Qword,
        Mem::base(Rax, core::mem::offset_of!(Rendezvous, release) as i32),
        0,
    );
    let wait = prefix.asm().jcc8(Cond::E);
    crate::x86_64::asm::resolve(&mut prefix, wait, waiting);
    prefix.asm().bind(ordinary);
    let thunk = thunk_with_policy(
        ThunkPlan {
            at: native.address() + prefix.len() as u64,
            control,
            retired: 7,
            block: 3,
            entry: native.address(),
            target: TARGET,
            kind: ExitKind::Direct,
        },
        policy,
    )
    .unwrap();
    let mut bytes = prefix.into_bytes();
    bytes.extend(thunk);
    bytes
}

fn interrupt_at_rendezvous(policy: Interruption) -> InterruptionOutcome {
    let control = Arc::new(Shared::new());
    let gate = Arc::new(Rendezvous {
        ready: AtomicU64::new(0),
        release: AtomicU64::new(0),
    });
    let native = Mapping::new();
    native.install(&rendezvous_backedge(
        &native,
        Arc::as_ptr(&control) as u64,
        Arc::as_ptr(&gate) as u64,
        policy,
    ));
    let entry = native.address() as usize;
    let retained = Arc::clone(&control);
    let retained_gate = Arc::clone(&gate);
    let worker = std::thread::spawn(move || {
        // SAFETY: main retains the RX mapping until join; both allocations
        // remain owned, and the generated program writes only their declared
        // native counters/test rendezvous using caller-volatile registers.
        let result = unsafe {
            let run: unsafe extern "sysv64" fn() -> u128 = core::mem::transmute(entry);
            run()
        };
        (result, retained, retained_gate)
    });
    let began = Instant::now();
    while gate.ready.load(Ordering::Acquire) == 0 {
        if began.elapsed() >= Duration::from_secs(5) {
            control.epoch.fetch_add(1, Ordering::Release);
            gate.release.store(1, Ordering::Release);
            let _ = worker.join();
            panic!("native backedge did not reach the ordered rendezvous");
        }
        std::thread::yield_now();
    }
    // Ready synchronizes the native accounting prefix. Publish before opening
    // the rendezvous; the next actual production guard must observe the epoch.
    let published = control.linked.load(Ordering::Acquire);
    control.epoch.fetch_add(1, Ordering::Release);
    gate.release.store(1, Ordering::Release);
    let (result, retained, _retained_gate) = worker.join().unwrap();
    InterruptionOutcome {
        published,
        linked: retained.linked.load(Ordering::Acquire),
        retired: retained.retired.load(Ordering::Acquire),
        budget: retained.budget.load(Ordering::Acquire),
        block: retained.block.load(Ordering::Acquire),
        epoch: retained.epoch.load(Ordering::Acquire),
        observed: retained.observed.load(Ordering::Acquire),
        result: exited(result),
    }
}

#[test]
fn foreign_epoch_interrupts_the_native_backedge_after_an_ordered_rendezvous() {
    for _ in 0..32 {
        let outcome = interrupt_at_rendezvous(Interruption::Epoch);
        assert!(outcome.interrupted_at_rendezvous(), "{outcome:?}");
    }
}

#[test]
fn rendezvous_oracle_rejects_an_ignored_epoch() {
    let outcome = interrupt_at_rendezvous(Interruption::Legacy);
    assert!(!outcome.interrupted_at_rendezvous(), "{outcome:?}");
    assert_eq!(
        (outcome.published, outcome.epoch, outcome.observed),
        (RENDEZVOUS_AFTER, 1, 0)
    );
    assert_eq!(outcome.linked, INTERRUPT_TEST_BUDGET);
    assert_eq!(outcome.budget, u64::MAX);
    assert_eq!(outcome.retired, INTERRUPT_TEST_BUDGET * 7);
    assert_eq!(outcome.result, (TARGET.0, ExitKind::Direct as u64));
}

#[test]
fn an_already_checked_native_boundary_allows_one_transfer_then_stops() {
    let mut control = Box::new(ChainControl {
        budget: 17,
        interrupt_epoch: 1,
        ..ChainControl::default()
    });
    let native = Mapping::new();
    let address = (&mut *control as *mut ChainControl) as u64;
    let mut prefix = Code::new();
    prefix.asm().mov_imm64(Rcx, address);
    prefix.asm().mov_imm64(Rdx, 0);
    let enter_tail = prefix.asm().jmp();
    let at = native.address() + prefix.len() as u64;
    let body = thunk(at, address, 7, 3, at, TARGET, ExitKind::Direct).unwrap();
    // Golden legacy encodings identify the exact post-guard native window.
    // The first entry has already admitted a transfer with the old epoch;
    // its backedge re-enters the full, unchanged production thunk.
    const AFTER_GUARD: usize = 20;
    assert_eq!(
        &body[10..18],
        &[0x48, 0x8b, 0x51, 0x40, 0x48, 0x3b, 0x51, 0x48]
    );
    assert_eq!(body[18], 0x75);
    assert_eq!(
        AFTER_GUARD + usize::from(body[19]),
        body.len() - DIRECT_EXIT_BYTES
    );
    assert_eq!(&body[AFTER_GUARD..AFTER_GUARD + 4], &[0x48, 0x83, 0x29, 1]);
    let distance = relative(
        native.address() + enter_tail.end() as u64,
        at + AFTER_GUARD as u64,
    )
    .unwrap();
    prefix.patch(enter_tail.offset(), distance.to_le_bytes());
    let mut code = prefix.into_bytes();
    code.extend(body);
    native.install(&code);
    assert_eq!(exited(native.run()), (TARGET.0, ExitKind::Direct as u64));
    assert_eq!(
        (
            control.budget,
            control.linked,
            control.retired,
            control.block
        ),
        (16, 1, 7, 3)
    );
    assert_eq!(
        (control.interrupt_epoch, control.observed_interrupt_epoch),
        (1, 0)
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
