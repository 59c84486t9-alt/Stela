//! Drain behavior when every eligible continuation is blocked.
use super::*;

/// # Safety
/// p is the queue-kept BoundFixture pointer and index selects one of its
/// two allocated task bindings. The pinned Executor remains live across parking.
unsafe fn sleeper(p: *mut c_void, index: usize) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue keeps that owner across every suspension and callback return.
    let f = unsafe { bound(p) };
    f.bind(index);
    let binding = &f.bindings[index];
    binding.enter(1, 0x200);
    binding.blocked.store(true, Ordering::Release);
    binding.prepared.store(true, Ordering::Release);
    f.event(80 + index as u64);
    assert_eq!(
        // SAFETY: setup published this pinned Runtime pointer before callback admission.
        // The fixture is used while its Executor is live, including all suspended callbacks.
        unsafe { f.runtime() }.park_if_blocked(),
        Ok(ParkOutcome::Resumed)
    );
    f.event(82 + index as u64);
    binding.exit();
}
unsafe extern "C" fn first(p: *mut c_void) {
    // SAFETY: The queue keeps p as a BoundFixture Arc. Indices 0 and 1 name
    // the two bindings created by bound_setup for this pinned executor.
    unsafe { sleeper(p, 0) };
}
unsafe extern "C" fn second(p: *mut c_void) {
    // SAFETY: The queue keeps p as a BoundFixture Arc. Indices 0 and 1 name
    // the two bindings created by bound_setup for this pinned executor.
    unsafe { sleeper(p, 1) };
}
unsafe extern "C" fn queued(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue keeps that owner across every suspension and callback return.
    let f = unsafe { bound(p) };
    // The same-lane callback starts only after a real wake
    // releases a continuation for its next job.
    f.event(84);
    f.data.fetch_add(1, Ordering::Release);
}
unsafe extern "C" fn general_origin(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue keeps that owner across every suspension and callback return.
    let f = unsafe { bound(p) };
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    let runtime = unsafe { f.runtime() };
    let origin = runtime.current_context().unwrap();
    // SAFETY: The callback and context identify this queue's fixture Arc.
    // The owning Executor keeps its pinned runtime/stacks alive while the job is suspended.
    unsafe { runtime.queue().execute(Kind::General, first, p) }.unwrap();
    // SAFETY: The callback and context identify this queue's fixture Arc.
    // The owning Executor keeps its pinned runtime/stacks alive while the job is suspended.
    unsafe { runtime.queue().execute(Kind::General, second, p) }.unwrap();
    // SAFETY: The callback and context identify this queue's fixture Arc.
    // The owning Executor keeps its pinned runtime/stacks alive while the job is suspended.
    unsafe { runtime.queue().execute(Kind::General, queued, p) }.unwrap();
    // Both General stacks park. The third General job
    // remains queued, while the Idle Notify stack is ineligible.
    assert_eq!(runtime.drain(10000), Err(WorkError::Pending));
    assert_eq!(f.data.load(Ordering::Acquire), 0);
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>(),
        [80, 81]
    );
    assert_eq!(
        runtime.current_context().unwrap().context_id,
        origin.context_id
    );
    f.bindings[0].wake();
    // One wake releases one General stack. The queued
    // callback completes; the second sleeper still needs wake.
    assert_eq!(runtime.drain(10000), Err(WorkError::Pending));
    assert_eq!(f.data.load(Ordering::Acquire), 1);
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>(),
        [80, 81, 82, 84]
    );
    f.bindings[1].wake();
    runtime.drain(10000).unwrap();
    assert_eq!(
        runtime.current_context().unwrap().context_id,
        origin.context_id
    );
}
unsafe extern "C" fn notify_origin(p: *mut c_void) {
    // SAFETY: p is the matching fixture Arc pointer submitted to this callback.
    // The queue keeps that owner across every suspension and callback return.
    let f = unsafe { bound(p) };
    // SAFETY: setup published this pinned Runtime pointer before callback admission.
    // The fixture is used while its Executor is live, including all suspended callbacks.
    let runtime = unsafe { f.runtime() };
    let origin = runtime.current_context().unwrap();
    // SAFETY: The callback and context identify this queue's fixture Arc.
    // The owning Executor keeps its pinned runtime/stacks alive while the job is suspended.
    unsafe { runtime.queue().execute(Kind::Notify, first, p) }.unwrap();
    // SAFETY: The callback and context identify this queue's fixture Arc.
    // The owning Executor keeps its pinned runtime/stacks alive while the job is suspended.
    unsafe { runtime.queue().execute(Kind::Notify, queued, p) }.unwrap();
    // The serial Notify continuation parks. Both Idle General
    // stacks are real, but cannot execute the queued Notify job.
    assert_eq!(runtime.drain(10000), Err(WorkError::Pending));
    assert_eq!(f.data.load(Ordering::Acquire), 0);
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>(),
        [80]
    );
    f.bindings[0].wake();
    runtime.drain(10000).unwrap();
    assert_eq!(f.data.load(Ordering::Acquire), 1);
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>(),
        [80, 82, 84]
    );
    assert_eq!(
        runtime.current_context().unwrap().context_id,
        origin.context_id
    );
}
fn run(origin: Callback, expected: &[u64]) {
    let (executor, f, dropped) = bound_setup();
    let runtime = executor.runtime();
    // SAFETY: The context is the queue-kept fixture Arc pointer for this callback.
    // The Executor keeps its pinned runtime and guarded stacks through join or quarantine.
    unsafe { runtime.call_foreground(origin, Arc::as_ptr(&f) as *mut c_void, 10000) }.unwrap();
    assert_eq!(
        f.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(f.cpu.flags.load(Ordering::Acquire), 0x202);
    f.detach_all();
    // SAFETY: This test has no asynchronous producers and calls on the dispatcher.
    // Completed jobs/bindings permit retirement; pending continuations keep their owners.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Acquire), 4);
}
#[test]
fn general_lane_waits_for_wake() {
    run(general_origin, &[80, 81, 82, 84, 83]);
}
#[test]
fn notify_lane_waits_for_wake() {
    run(notify_origin, &[80, 82, 84]);
}
