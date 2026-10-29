//! Real guarded mixed-size mappings and retained callback records for profile proofs.
use super::*;
use alloc::vec;
use core::sync::atomic::AtomicUsize;
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
struct Mapped {
    allocation: usize,
    bytes: usize,
    usable: core::ops::Range<usize>,
    guard: core::ops::Range<usize>,
    dropped: Arc<AtomicUsize>,
}
// SAFETY: each owner retains its exact private mmap. The whole allocation starts
// PROT_NONE; only the real usable extent becomes RW. Both guards/padding remain
// absent. Runtime retirement precedes munmap; uncertain executors quarantine it.
unsafe impl StackBacking for Mapped {
    fn bounds(&self) -> core::ops::Range<usize> {
        self.usable.clone()
    }
    fn guard(&self) -> core::ops::Range<usize> {
        self.guard.clone()
    }
}
impl Drop for Mapped {
    fn drop(&mut self) {
        assert_eq!(
            // SAFETY: exact successful mapping, unpublished or genuinely retired;
            // no continuation/source can still reach it. Failed retirement retains us.
            unsafe { munmap(self.allocation as *mut c_void, self.bytes) },
            0
        );
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
pub(super) fn mapped(
    requirement: StackRequirement,
    offset: usize,
    dropped: &Arc<AtomicUsize>,
) -> Stack {
    #[cfg(target_os = "macos")]
    let anonymous = 0x1000;
    #[cfg(not(target_os = "macos"))]
    let anonymous = 0x20;
    let bytes = requirement.usable_bytes()
        + 2 * requirement.minimum_guard_bytes()
        + requirement.alignment()
        + offset;
    // SAFETY: new anonymous private PROT_NONE extent; no supplied address/file or overlap.
    let base = unsafe { mmap(core::ptr::null_mut(), bytes, 0, 2 | anonymous, -1, 0) };
    assert_ne!(base as usize, usize::MAX);
    let start = ((base as usize + requirement.minimum_guard_bytes() + requirement.alignment() - 1)
        & !(requirement.alignment() - 1))
        + offset;
    let end = start + requirement.usable_bytes();
    assert!(end + requirement.minimum_guard_bytes() <= base as usize + bytes);
    assert_eq!(
        // SAFETY: complete page-aligned usable range lies inside this exact mapping;
        // all preceding/following guard and alignment padding remain PROT_NONE.
        unsafe { mprotect(start as *mut c_void, requirement.usable_bytes(), 3) },
        0
    );
    Stack::new(Box::new(Mapped {
        allocation: base as usize,
        bytes,
        usable: start..end,
        guard: start - requirement.minimum_guard_bytes()..start,
        dropped: dropped.clone(),
    }))
    .unwrap()
}
pub(super) fn requirements(kernel_count: usize) -> Vec<StackRequirement> {
    let mut result = vec![ordinary(); 8];
    result[2] = kernel();
    // Rust workers deliberately precede kernel workers: class is geometry, not slot position.
    result.extend(core::iter::repeat_n(ordinary(), 24 - kernel_count));
    result.extend(core::iter::repeat_n(kernel(), kernel_count));
    result
}
pub(super) fn stacks(dropped: &Arc<AtomicUsize>, kernel_count: usize) -> Vec<Stack> {
    requirements(kernel_count)
        .into_iter()
        .map(|r| mapped(r, 0, dropped))
        .collect()
}
pub(super) struct Case {
    owner: usize,
    tag: u32,
    required: StackRequirement,
    block: bool,
}
pub(super) struct Fixture {
    pub runtime: AtomicU64,
    pub seen: Mutex<Vec<(u32, TaskContext)>>,
    pub parked: Mutex<Vec<(Arc<Binding>, WakeHandle<64>)>>,
    calls: Mutex<Vec<Arc<Case>>>,
}
impl Fixture {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            runtime: AtomicU64::new(0),
            seen: Mutex::new(Vec::new()),
            parked: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        })
    }
    pub(super) fn runtime(&self) -> Pin<&Runtime<64>> {
        // SAFETY: setup publishes the real pinned executor before callbacks; fixture
        // owner outlives every accepted job, explicit join/detach and retirement.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>))
        }
    }
    pub(super) fn publish(&self, r: Pin<&Runtime<64>>) {
        self.runtime
            .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    }
    pub(super) fn context(&self, tag: u32, required: StackRequirement, block: bool) -> *mut c_void {
        let case = Arc::new(Case {
            owner: self as *const Self as usize,
            tag,
            required,
            block,
        });
        let pointer = Arc::as_ptr(&case).cast_mut().cast();
        self.calls.lock().unwrap().push(case);
        pointer
    }
    pub(super) fn finish(&self, cpu: &test_support::CpuModel) {
        let r = self.runtime();
        r.queue.close().unwrap();
        for (binding, wake) in &*self.parked.lock().unwrap() {
            binding.blocked.store(false, Ordering::Release);
            wake.wake().unwrap();
        }
        r.drain(cpu.ticks() + 1_000_000_000).unwrap();
        for (_, wake) in core::mem::take(&mut *self.parked.lock().unwrap()) {
            // SAFETY: every fixture callback returned and no producer can wake it again.
            drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
        }
        // SAFETY: no native source exists; queue is closed, all actual frames joined/detached.
        unsafe { r.retire() }.unwrap();
    }
}
pub(super) unsafe extern "C" fn record(context: *mut c_void) {
    // SAFETY: queue retains Fixture and its stable Case allocation until actual completion.
    let case = unsafe { &*context.cast::<Case>() };
    // SAFETY: Case's immutable owner address names that same retained Fixture allocation.
    let f = unsafe { &*(case.owner as *const Fixture) };
    let r = f.runtime();
    let view = r.current_context().unwrap();
    let bytes = view.stack_end - view.stack_start;
    if case.required.is_exact() {
        assert_eq!(bytes, case.required.usable_bytes());
    } else {
        assert!(bytes >= case.required.usable_bytes());
    }
    assert!(view.stack_start.is_multiple_of(case.required.alignment()));
    assert!(view.guard_end - view.guard_start >= case.required.minimum_guard_bytes());
    assert!((view.stack_start..view.stack_end).contains(&context::stack_pointer()));
    f.seen.lock().unwrap().push((case.tag, view));
    if case.block {
        let binding = Arc::new(Binding {
            id: AtomicU64::new(0),
            blocked: AtomicBool::new(true),
        });
        let wake = r.bind_current(binding.clone()).unwrap();
        f.parked.lock().unwrap().push((binding, wake));
        assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
    }
}
pub(super) fn executor(
    f: Arc<Fixture>,
) -> (Executor<64>, Arc<test_support::CpuModel>, Arc<AtomicUsize>) {
    let cpu = test_support::CpuModel::new();
    // SAFETY: same-thread model and exact retained fixture owner; no native qualification.
    let q = unsafe { Queue::new(cpu.clone(), f.clone()) }.unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let executor =
        Executor::new_hosted_profile_for_test(q, stacks(&dropped, 20), policy(), profile())
            .unwrap();
    f.publish(executor.runtime());
    (executor, cpu, dropped)
}
