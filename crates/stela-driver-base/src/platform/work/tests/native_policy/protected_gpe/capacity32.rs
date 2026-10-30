//! Explicit32-stack prototype: worker count, bounded jobs and legacy isolation.
use super::*;
use core::sync::atomic::AtomicUsize;
fn prototype() -> ReservationPolicy {
    ReservationPolicy::NativeFirmware32Protected {
        gpe: GpeQueueBudget::QUALIFICATION,
    }
}
#[test]
fn thirty_three_jobs_and_sixty_four_jobs_admit_all_thirty_two_roles() {
    full_admission_policy::<33>(prototype(), GpeQueueBudget::QUALIFICATION, 24);
    full_admission_policy::<64>(prototype(), GpeQueueBudget::QUALIFICATION, 55);
}
fn refused<const N: usize>(
    count: usize,
    policy: ReservationPolicy,
    queued: bool,
    expected: WorkError,
) {
    let owner = Arc::new(AtomicUsize::new(0));
    let cpu = test_support::CpuModel::new();
    // SAFETY: owned same-thread hosted queue; no hardware or foreign producer exists.
    let q = unsafe { Queue::<N>::new(cpu.clone(), owner.clone()) }.unwrap();
    let pointer = Arc::as_ptr(&owner) as *mut c_void;
    let ticket = if queued {
        // SAFETY: the queue keeps this counter; refused construction may not run/drop it.
        Some(unsafe { q.execute(Kind::General, count_queued, pointer) }.unwrap())
    } else {
        None
    };
    let dropped = Arc::new(AtomicUsize::new(0));
    assert!(
        matches!(Executor::new_hosted_policy_for_test(q.clone(), test_support::stacks_count(&dropped,count),policy),Err(e) if e==expected)
    );
    assert_eq!(dropped.load(Ordering::Relaxed), count);
    assert!(!q.executor_claimed.load(Ordering::Acquire));
    assert_eq!(q.lock().unwrap().state().layout, Layout::Ordinary);
    assert_eq!(owner.load(Ordering::Relaxed), 0);
    if let Some(ticket) = ticket {
        assert_eq!(q.completed(ticket), Ok(false));
    }
    let old = Executor::new_hosted_for_test(q.clone(), test_support::stacks(&dropped)).unwrap();
    q.close().unwrap();
    old.runtime().drain(cpu.ticks() + 1_000_000_000).unwrap();
    assert_eq!(owner.load(Ordering::Relaxed), usize::from(queued));
    // SAFETY: admitted counter callback returned, queue closed, no kept producer exists.
    unsafe { old.runtime().retire() }.unwrap();
    drop(old);
    assert_eq!(dropped.load(Ordering::Relaxed), count + 16);
}
#[test]
fn prototype_geometry_overflow_and_nonempty_admission_leave_old_queue_untouched() {
    refused::<32>(32, prototype(), false, WorkError::Unavailable);
    refused::<33>(16, prototype(), false, WorkError::Unavailable);
    refused::<33>(33, prototype(), false, WorkError::Unavailable);
    refused::<33>(
        32,
        ReservationPolicy::NativeFirmware16,
        false,
        WorkError::Unavailable,
    );
    refused::<33>(32, prototype(), true, WorkError::Busy);
    // Valid for original16 arithmetic, but not32; refuse before checked addition wraps.
    let huge = GpeQueueBudget::with_pending(usize::MAX - 16).unwrap();
    refused::<33>(
        32,
        ReservationPolicy::NativeFirmware32Protected { gpe: huge },
        false,
        WorkError::Exhausted,
    );
}
struct Saturation {
    runtime: AtomicU64,
    extra: AtomicBool,
    parked: Mutex<Vec<(Arc<Binding>, WakeHandle<64>, TaskContext)>>,
}
impl Saturation {
    fn runtime(&self) -> Pin<&Runtime<64>> {
        // SAFETY: callback owner publishes one pinned executor before admission and keeps it through detach.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>))
        }
    }
}
unsafe extern "C" fn park_actual(context: *mut c_void) {
    // SAFETY: every accepted job keeps the exact Saturation allocation through join.
    let f = unsafe { &*context.cast::<Saturation>() };
    let r = f.runtime();
    let binding = Arc::new(Binding {
        id: AtomicU64::new(0),
        blocked: AtomicBool::new(true),
    });
    let wake = r.bind_current(binding.clone()).unwrap();
    let view = r.current_context().unwrap();
    f.parked.lock().unwrap().push((binding, wake, view));
    assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
}
unsafe extern "C" fn mark_extra(context: *mut c_void) {
    // SAFETY: the queue keeps this exact Saturation allocation until callback completion.
    let f = unsafe { &*context.cast::<Saturation>() };
    f.extra.store(true, Ordering::Release);
}
fn actual_saturation(policy: ReservationPolicy, count: usize) {
    let f = Arc::new(Saturation {
        runtime: AtomicU64::new(0),
        extra: AtomicBool::new(false),
        parked: Mutex::new(Vec::new()),
    });
    let (executor, cpu, dropped) = test_support::executor_with_policy::<64>(f.clone(), policy);
    let r = executor.runtime();
    f.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    let p = Arc::as_ptr(&f) as *mut c_void;
    for _ in 0..count - 8 {
        // SAFETY: each General job keeps f and a distinct mapped stack until explicit wake.
        unsafe { r.queue.execute(Kind::General, park_actual, p) }.unwrap();
    }
    // SAFETY: dedicated service callback keeps f through its explicit wake/join.
    unsafe { r.start_service(park_actual, p) }.unwrap();
    // SAFETY: control callback uses its own reserved frame and the same owner.
    unsafe { r.start_firmware(park_actual, p) }.unwrap();
    // SAFETY: serial GPE's accepted job keeps f through release.
    unsafe { r.queue.execute_gpe(park_actual, p) }.unwrap();
    for _ in 0..2 {
        // SAFETY: accepted Portal permit owns its distinct idle continuation.
        unsafe { r.queue.execute_portal(park_actual, p) }.unwrap();
        // SAFETY: accepted Notify permit owns its distinct idle continuation.
        unsafe { r.queue.execute(Kind::Notify, park_actual, p) }.unwrap();
    }
    assert_eq!(
        // SAFETY: Foreground keeps f even after Pending; no owner is reclaimed early.
        unsafe { r.call_foreground(park_actual, p, cpu.ticks() + 1_000_000_000) },
        Err(WorkError::Pending)
    );
    assert_eq!(f.parked.lock().unwrap().len(), count);
    assert_eq!(r.step(), Ok(false));
    let views: Vec<_> = f
        .parked
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, v)| *v)
        .collect();
    for (index, a) in views.iter().enumerate() {
        for b in &views[..index] {
            assert_ne!(a.context_id, b.context_id);
            assert!(a.stack_end <= b.stack_start || b.stack_end <= a.stack_start);
        }
    }
    // SAFETY: extra ordinary work is held in a queue slot, never a phantom continuation.
    let queued = unsafe { r.queue.execute(Kind::General, mark_extra, p) }.unwrap();
    assert_eq!(r.step(), Ok(false));
    assert_eq!(f.parked.lock().unwrap().len(), count);
    assert_eq!(r.queue.completed(queued), Ok(false));
    assert!(!f.extra.load(Ordering::Acquire));
    r.queue.close().unwrap();
    for (binding, wake, _) in &*f.parked.lock().unwrap() {
        binding.blocked.store(false, Ordering::Release);
        wake.wake().unwrap();
    }
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    assert_eq!(r.queue.completed(queued), Ok(true));
    assert!(f.extra.load(Ordering::Acquire));
    for (_, wake, _) in core::mem::take(&mut *f.parked.lock().unwrap()) {
        // SAFETY: all jobs returned; this fixture stopped every wake source before detach.
        drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
    }
    // SAFETY: queue closed, all real frames joined and bindings detached; no hardware/source exists.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), count);
    assert_eq!(cpu.flags(), 0x202);
}
#[test]
fn thirty_two_saturation_does_not_give_old_sixteen_phantom_workers() {
    actual_saturation(prototype(), 32);
    actual_saturation(
        ReservationPolicy::NativeFirmware16Protected {
            gpe: GpeQueueBudget::QUALIFICATION,
        },
        16,
    );
}
