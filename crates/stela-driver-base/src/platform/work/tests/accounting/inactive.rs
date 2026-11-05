//! These controls execute real hosted guarded native continuations. Hosted CPU,
//! clock and source-free bindings grant no production CPU/Linux readiness.
use super::*;

struct Waiting {
    source: Arc<Scene>,
    phase: AtomicU64,
}

unsafe extern "C" fn target(p: *mut c_void) {
    // SAFETY: test retains exact Arc until both genuine callbacks physically return.
    let s = unsafe { &*p.cast::<Waiting>() };
    let r = s.source.runtime();
    let wake = r.bind_current(s.source.binding.clone()).unwrap();
    s.source.wake.lock().unwrap().replace(wake.clone());
    // An executing real stack cannot claim its own physical departure.
    assert_eq!(r.returned_stack(r.current.get()), Err(WorkError::Busy));
    let index = r.current.get();
    let flags = s.source.cpu.save_disable().unwrap();
    // Negative fault control: reproduce metadata clearing BEFORE a real switch.
    // The actual constructor stack/RSP must independently reject this prefix.
    r.current.set(NONE);
    r.queue.active.clear();
    assert_eq!(r.dispatcher_successor(), Err(WorkError::Busy));
    assert_eq!(r.returned_stack(index), Err(WorkError::Busy));
    r.current.set(index);
    // SAFETY: restore SAME real current task/constructor stack, no callback/wait.
    unsafe {
        let task = &*r.task(index);
        r.queue.active.publish(task.id, &task.stack.bounds);
    }
    // SAFETY: corresponding actual hosted save_disable; no lock/loan remains.
    unsafe { s.source.cpu.restore(flags) };
    let native = wake.retain_inactive().unwrap();
    assert_eq!(
        r.observe_inactive(&native, &wake, false),
        Err(WorkError::Unavailable)
    );
    assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
    s.phase.fetch_or(2, Ordering::Release);
}

unsafe extern "C" fn waiter(p: *mut c_void) {
    // SAFETY: same fixture-owned actual callback allocation as target.
    let s = unsafe { &*p.cast::<Waiting>() };
    let r = s.source.runtime();
    let wake = r.bind_current(s.source.service.clone()).unwrap();
    s.source.service_wake.lock().unwrap().replace(wake.clone());
    s.source
        .domain
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .bind_current(r)
        .unwrap();
    assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
    let target = s.source.wake.lock().unwrap().as_ref().unwrap().clone();
    let native = target.retain_inactive().unwrap();
    // Only an actual prior dispatcher successor can make this observation true.
    assert_eq!(
        r.observe_inactive(&native, &wake, false),
        Ok(InactiveObservation::Inactive)
    );
    r.cancel_inactive(&wake).unwrap();
    // Saved-only/source-queued veto still subscribes, never returns inactive.
    assert_eq!(
        r.observe_inactive(&native, &wake, true),
        Ok(InactiveObservation::Subscribed)
    );
    assert_eq!(
        r.observe_inactive(&native, &wake, false),
        Err(WorkError::Busy)
    );
    // The actual wake occurs after arm and BEFORE park. It must preserve the
    // pending bit and actual scheduling row; no timer/polling rescues a lost wake.
    s.source.binding.blocked.store(false, Ordering::Release);
    target.wake().unwrap();
    assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Skipped));
    r.cancel_inactive(&wake).unwrap();
    assert_eq!(r.activity_for(&target), Ok(scheduling::Activity::Ready));
    // Actual native Ready vetoes success despite its OLD physical departure.
    assert_eq!(
        r.observe_inactive(&native, &wake, false),
        Ok(InactiveObservation::Subscribed)
    );
    s.phase.fetch_or(1, Ordering::Release);
    assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
    r.cancel_inactive(&wake).unwrap();
    // The target really completed; its old retained identity cannot grant a
    // future assignment or an inactivity/death claim. No C fields were adopted.
    assert_eq!(
        r.observe_inactive(&native, &wake, false),
        Err(WorkError::Closed)
    );
    s.phase.fetch_or(4, Ordering::Release);
}

#[test]
fn physical_departure_events_cover_armed_and_prepark_wakes() {
    let (executor, source, dropped) = setup();
    let s = Arc::new(Waiting {
        source: source.clone(),
        phase: AtomicU64::new(0),
    });
    let r = executor.runtime();
    let domain = source.domain.lock().unwrap().as_ref().unwrap().clone();
    // SAFETY: test keeps exact Scene/code/stack owners until physical return.
    let service_ticket =
        unsafe { r.start_service(waiter, Arc::as_ptr(&s) as *mut c_void) }.unwrap();
    assert!(r.step().unwrap());
    // SAFETY: same kept fixture, genuine separate constructor-owned General stack.
    let target_ticket = unsafe {
        r.queue
            .execute(Kind::General, target, Arc::as_ptr(&s) as *mut c_void)
    }
    .unwrap();
    assert!(r.step().unwrap());
    source
        .service_wake
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .wake()
        .unwrap();
    assert!(r.step().unwrap());
    assert_eq!(s.phase.load(Ordering::Acquire), 1);
    assert!(r.step().unwrap());
    assert!(r.queue.completed(target_ticket).unwrap());
    domain.stop_producers().unwrap();
    source.service.blocked.store(false, Ordering::Release);
    assert!(r.step().unwrap());
    assert!(r.queue.completed(service_ticket).unwrap());
    assert_eq!(s.phase.load(Ordering::Acquire), 7);
    assert!(
        r.queue
            .lock()
            .unwrap()
            .state()
            .inactive
            .iter()
            .all(Option::is_none)
    );
    let wake = source.wake.lock().unwrap().as_ref().unwrap().clone();
    let stopped = r.take_stopped_publication(&wake).unwrap();
    // SAFETY: source-free hosted field publisher, both native frames joined.
    unsafe { stopped.finish(&Authority(source.cpu.clone())) }.unwrap();
    // SAFETY: independent hosted binding/data users completed and joined above.
    drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
    // SAFETY: same physical service completion; no source C ref exists in fixture.
    unsafe { domain.retire() }.unwrap();
    let service_wake = source
        .service_wake
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    // SAFETY: actual service frame returned and plain source-free binding joined.
    drop(unsafe { r.detach_binding(service_wake.context_id()) }.unwrap());
    // SAFETY: all real callbacks/registrations/data/bindings physically joined.
    unsafe { r.retire() }.unwrap();
    source.tap.lock().unwrap().take();
    source.domain.lock().unwrap().take();
    drop(domain);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Acquire), 5);
}
