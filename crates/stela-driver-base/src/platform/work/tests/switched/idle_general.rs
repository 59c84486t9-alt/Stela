//! Real stack admission under permanent, yielding task pressure.
use super::*;
struct Binding;
// SAFETY: this fixture has no foreign state; Runtime supplies the real stack,
// CPU and generation exclusion and keeps this binding through detach.
unsafe impl SwitchBinding for Binding {
    unsafe fn attach(&self, _: &TaskContext) -> Result<(), WorkError> {
        Ok(())
    }
    unsafe fn still_blocked(&self, _: &TaskContext) -> Result<bool, WorkError> {
        Ok(false)
    }
    unsafe fn leave(&self, _: &TaskContext, _: LeaveReason) -> Result<(), WorkError> {
        Ok(())
    }
    unsafe fn arrive(&self, _: &TaskContext, _: bool) -> Result<(), WorkError> {
        Ok(())
    }
    unsafe fn complete(&self, _: &TaskContext) -> Result<(), WorkError> {
        Ok(())
    }
    unsafe fn detach(&self, _: &TaskContext) -> Result<(), WorkError> {
        Ok(())
    }
}
struct Tasks {
    runtime: AtomicU64,
    bindings: Mutex<Vec<(ContextId, Arc<Binding>)>>,
    stop: AtomicBool,
    started: AtomicU64,
}
unsafe extern "C" fn persistent(context: *mut c_void) {
    // SAFETY: queue-kept fixture and pinned runtime outlive all admitted tasks.
    let f = unsafe { &*context.cast::<Tasks>() };
    // SAFETY: the test publishes the pinned runtime before admission.
    let r =
        unsafe { Pin::new_unchecked(&*(f.runtime.load(Ordering::Acquire) as *const Runtime<16>)) };
    let id = r.current_id().unwrap();
    let mut bindings = f.bindings.lock().unwrap();
    if !bindings.iter().any(|(context, _)| *context == id) {
        let binding = Arc::new(Binding);
        r.bind_current(binding.clone()).unwrap();
        bindings.push((id, binding));
    }
    drop(bindings);
    f.started.fetch_add(1, Ordering::Relaxed);
    while !f.stop.load(Ordering::Acquire) {
        r.yield_now().unwrap();
    }
}
#[test]
fn permanent_tasks_refuse_exhaustion_and_reuse_only_their_exact_idle_bindings() {
    let cpu = CpuModel::new();
    let f = Arc::new(Tasks {
        runtime: AtomicU64::new(0),
        bindings: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
        started: AtomicU64::new(0),
    });
    // SAFETY: this fixture retains callback/context/code through retirement.
    let queue = unsafe { Queue::<16>::new(cpu.clone(), f.clone()) }.unwrap();
    let dropped = Arc::new(AtomicU64::new(0));
    let executor = Executor::new_hosted_for_test(queue, stacks(dropped.clone())).unwrap();
    let r = executor.runtime();
    f.runtime
        .store(r.get_ref() as *const Runtime<16> as u64, Ordering::Release);
    let context = Arc::as_ptr(&f).cast_mut().cast();
    let requirement = StackRequirement::exact(128 * 1024, 4096, 4096).unwrap();
    assert_eq!(r.general_capacity(requirement).unwrap(), 2);
    // A declared pool reserve is checked against real compatible idle stacks,
    // independently of spare admission slots and before accepting a callback.
    assert_eq!(
        // SAFETY: fixture/code are kept; failure publishes no callback/context.
        unsafe { r.execute_idle_general_with_headroom(requirement, persistent, context, &[], 2) },
        Err(WorkError::Full)
    );
    for generation in 0..3 {
        f.stop.store(false, Ordering::Release);
        let bindings = f.bindings.lock().unwrap();
        let reusable: Vec<&dyn SwitchBinding> = bindings
            .iter()
            .map(|(_, binding)| binding.as_ref() as &dyn SwitchBinding)
            .collect();
        let mut tickets = Vec::new();
        for _ in 0..2 {
            // SAFETY: retained fixture fits the real stack and reuses only its own bindings.
            tickets.push(
                unsafe { r.execute_idle_general(requirement, persistent, context, &reusable) }
                    .unwrap(),
            );
        }
        // The queue has spare job slots, but no compatible physical task remains.
        // SAFETY: on refusal no callback/context is transferred.
        assert_eq!(
            // SAFETY: retained fixture is valid; refusal transfers no callback or context.
            unsafe { r.execute_idle_general(requirement, persistent, context, &reusable) },
            Err(WorkError::Full)
        );
        drop(reusable);
        drop(bindings);
        assert!(r.step().unwrap());
        assert!(r.step().unwrap());
        assert_eq!(f.started.load(Ordering::Relaxed), (generation + 1) * 2);
        // SAFETY: a yielding persistent task still owns its continuation.
        assert_eq!(
            // SAFETY: retained fixture is valid; refusal transfers no callback or context.
            unsafe { r.execute_idle_general(requirement, persistent, context, &[]) },
            Err(WorkError::Full)
        );
        f.stop.store(true, Ordering::Release);
        while r.step().unwrap() {}
        assert!(
            tickets
                .into_iter()
                .all(|ticket| r.queue().completed(ticket).unwrap())
        );
        // Idle foreign bindings are not an interchangeable unowned stack pool.
        // SAFETY: refusal transfers nothing; no allowed binding is supplied.
        assert_eq!(
            // SAFETY: retained fixture is valid; refusal transfers no callback or context.
            unsafe { r.execute_idle_general(requirement, persistent, context, &[]) },
            Err(WorkError::Full)
        );
    }
    for (id, _) in f.bindings.lock().unwrap().drain(..) {
        // SAFETY: all callbacks returned and this fixture has no producers.
        drop(unsafe { r.detach_binding(id) }.unwrap());
    }
    r.queue().close().unwrap();
    // SAFETY: all jobs and bindings finished, sole producer is stopped.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 4);
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
}
