//! Real POSIX guarded stacks with explicitly modeled CPU/IRQ state for tests.
//! This never attests CPL0, native roots, interrupt delivery or a production provider.
extern crate std;
use super::*;
use core::ops::Range;
use std::{sync::atomic::AtomicUsize, thread, time::Instant};

pub(crate) struct CpuModel {
    thread: thread::ThreadId,
    flags: AtomicU64,
    start: Instant,
}
impl CpuModel {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            thread: thread::current().id(),
            flags: AtomicU64::new(0x202),
            start: Instant::now(),
        })
    }
    pub(crate) fn flags(&self) -> u64 {
        self.flags.load(Ordering::Acquire)
    }
}
// SAFETY: this is an explicit same-OS-thread flag/IRQ model. It supplies no
// physical CPU/root/interrupt validation; continuations use exclusively
// owned guarded mmap stacks, and no modeled lock invokes/switches callbacks.
unsafe impl Cpu for CpuModel {
    fn check_cpu(&self) -> Result<(), WorkError> {
        if self.thread == thread::current().id() {
            Ok(())
        } else {
            Err(WorkError::WrongCpu)
        }
    }
    fn in_interrupt(&self) -> bool {
        false
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.check_cpu()?;
        Ok(self.flags.fetch_and(!0x200, Ordering::AcqRel))
    }
    unsafe fn restore(&self, flags: u64) {
        self.flags.store(flags, Ordering::Release);
    }
    fn ticks(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_nanos())
            .expect("hosted clock exceeded u64 nanoseconds")
    }
    fn fatal(&self, error: WorkError) -> ! {
        panic!("hosted runtime model fatal: {error:?}")
    }
}
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
    base: usize,
    bytes: usize,
    usable: Range<usize>,
    guard: Range<usize>,
    dropped: Arc<AtomicUsize>,
}
// SAFETY: each owner exclusively keeps its complete successful private mmap;
// both guard pages are PROT_NONE before publication. Runtime retirement precedes
// munmap; uncertain executor drop quarantines the mapping and owner.
unsafe impl StackBacking for Mapping {
    fn bounds(&self) -> Range<usize> {
        self.usable.clone()
    }
    fn guard(&self) -> Range<usize> {
        self.guard.clone()
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        assert_eq!(
            // SAFETY: this is the exact successful mmap extent. No frame was
            // published on constructor failure; after publication only proved
            // retirement releases it. Uncertain executors quarantine the mapping.
            unsafe { munmap(self.base as *mut c_void, self.bytes) },
            0
        );
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
pub(crate) fn stacks(dropped: &Arc<AtomicUsize>) -> Vec<Stack> {
    stacks_count(dropped, 16)
}
pub(crate) fn stacks_count(dropped: &Arc<AtomicUsize>, count: usize) -> Vec<Stack> {
    (0..count)
        .map(|_| {
            #[cfg(target_os = "macos")]
            let anonymous = 0x1000;
            #[cfg(not(target_os = "macos"))]
            let anonymous = 0x20;
            let bytes = 128 * 1024 + 8192;
            // SAFETY: request new anonymous private RW storage, with no supplied
            // address or file. Check success before protecting or publishing it.
            let base = unsafe { mmap(core::ptr::null_mut(), bytes, 3, 2 | anonymous, -1, 0) };
            assert_ne!(base as usize, usize::MAX);
            // SAFETY: both extents are aligned pages entirely inside this successful
            // mapping, protected before Stack construction or callback admission.
            unsafe {
                assert_eq!(mprotect(base, 4096, 0), 0);
                assert_eq!(
                    mprotect((base as *mut u8).add(bytes - 4096).cast(), 4096, 0),
                    0
                );
            }
            Stack::new(Box::new(Mapping {
                base: base as usize,
                bytes,
                usable: base as usize + 4096..base as usize + bytes - 4096,
                guard: base as usize..base as usize + 4096,
                dropped: dropped.clone(),
            }))
            .unwrap()
        })
        .collect()
}
/// Allocate usable/guard/alignment geometry. The offset supplies checked
/// alignment-refusal cases; both guards and padding remain PROT_NONE.
pub(crate) fn backing(
    requirement: StackRequirement,
    offset: usize,
    dropped: &Arc<AtomicUsize>,
) -> Box<dyn StackBacking> {
    #[cfg(target_os = "macos")]
    let anonymous = 0x1000;
    #[cfg(not(target_os = "macos"))]
    let anonymous = 0x20;
    let bytes = requirement.usable_bytes()
        + 2 * requirement.minimum_guard_bytes()
        + requirement.alignment()
        + offset;
    // SAFETY: new anonymous private PROT_NONE extent, without a supplied
    // address or file. Success is checked before any permission change.
    let base = unsafe { mmap(core::ptr::null_mut(), bytes, 0, 2 | anonymous, -1, 0) };
    assert_ne!(base as usize, usize::MAX);
    let start = ((base as usize + requirement.minimum_guard_bytes() + requirement.alignment() - 1)
        & !(requirement.alignment() - 1))
        + offset;
    let end = start + requirement.usable_bytes();
    assert!(end + requirement.minimum_guard_bytes() <= base as usize + bytes);
    assert_eq!(
        // SAFETY: this complete page-aligned usable range is inside the fresh
        // mapping. Both guards and all alignment padding remain PROT_NONE.
        unsafe { mprotect(start as *mut c_void, requirement.usable_bytes(), 3) },
        0
    );
    Box::new(Mapping {
        base: base as usize,
        bytes,
        usable: start..end,
        guard: start - requirement.minimum_guard_bytes()..start,
        dropped: dropped.clone(),
    })
}

pub(crate) fn executor<const N: usize>(
    owner: RetainedOwner,
) -> (Executor<N>, Arc<CpuModel>, Arc<AtomicUsize>) {
    executor_with_policy(owner, ReservationPolicy::NativeFirmware16)
}
pub(crate) fn executor_with_policy<const N: usize>(
    owner: RetainedOwner,
    policy: ReservationPolicy,
) -> (Executor<N>, Arc<CpuModel>, Arc<AtomicUsize>) {
    let cpu = CpuModel::new();
    // SAFETY: caller keeps the fixture state via this queue's owner;
    // all access/switches stay on the modeled constructing thread until join.
    let queue = unsafe { Queue::new(cpu.clone(), owner) }.unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let stacks = stacks_count(&dropped, policy.layout().stack_limit());
    let executor = Executor::new_hosted_policy_for_test(queue, stacks, policy).unwrap();
    (executor, cpu, dropped)
}
