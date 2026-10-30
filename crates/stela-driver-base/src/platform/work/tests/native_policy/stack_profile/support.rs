//! Real guarded mixed-size mappings and kept callback records for profile proofs.
use super::*;
use alloc::vec;
use core::sync::atomic::AtomicUsize;
pub(super) fn mapped(
    requirement: StackRequirement,
    offset: usize,
    dropped: &Arc<AtomicUsize>,
) -> Stack {
    Stack::new(test_support::backing(requirement, offset, dropped)).unwrap()
}
pub(super) fn requirements(kernel_count: usize) -> Vec<StackRequirement> {
    let mut result = vec![ordinary(); 8];
    result[2] = kernel();
    // Rust workers precede kernel workers: class is geometry, not slot position.
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
        // SAFETY: no native source exists; queue is closed, all frames joined/detached.
        unsafe { r.retire() }.unwrap();
    }
}
pub(super) unsafe extern "C" fn record(context: *mut c_void) {
    // SAFETY: queue keeps Fixture and its stable Case allocation until completion.
    let case = unsafe { &*context.cast::<Case>() };
    // SAFETY: Case's immutable owner address names that same Fixture allocation.
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
    // SAFETY: same-thread model and exact fixture owner.
    let q = unsafe { Queue::new(cpu.clone(), f.clone()) }.unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let executor =
        Executor::new_hosted_profile_for_test(q, stacks(&dropped, 20), policy(), profile())
            .unwrap();
    f.publish(executor.runtime());
    (executor, cpu, dropped)
}
