//! Guarded hosted continuations and real RAM publication. Counter/IRQ models
//! grant no native entry/root, original task ref or Linux WQ qualification.
use super::*;
mod support;
use support::*;
unsafe extern "C" fn measured(p: *mut c_void) {
    // SAFETY: queue retains this exact Scene; Runtime pointer published before admission.
    let s = unsafe { &*p.cast::<Scene>() };
    let r = s.runtime();
    let wake = r.bind_current(s.binding.clone()).unwrap();
    s.wake.lock().unwrap().replace(wake.clone());
    let initial = r.execution_current().unwrap();
    assert_eq!(initial.total_ns(), 0);
    s.clock.now.store(130, Ordering::Release);
    let flags = s.cpu.save_disable().unwrap();
    s.cpu.irq.store(true, Ordering::Release);
    // The actual native Board lock is deliberately held. The metric IRQ view
    // must not acquire it, enter C, drop owners or borrow the Runtime task.
    let guard = r.queue.lock().unwrap();
    let entry = Entry {
        cpu: s.cpu.clone(),
        clock: s.clock.clone(),
        rsp: context::stack_pointer(),
    };
    assert_eq!(
        s.tap.lock().unwrap().as_ref().unwrap().publish_irq(&entry),
        Ok(true)
    );
    assert_eq!(s.binding.fields.total.load(Ordering::Acquire), 30);
    drop(guard);
    s.cpu.irq.store(false, Ordering::Release);
    // SAFETY: exact outer hosted flags after modeled entry/Board guard joined.
    unsafe { s.cpu.restore(flags) };
    s.clock.now.store(150, Ordering::Release);
    assert_eq!(r.execution_current().unwrap().total_ns(), 50);
    assert_eq!(
        r.take_stopped_publication(&wake).unwrap_err(),
        WorkError::Pending
    );
    assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
    assert_eq!(r.execution_current().unwrap().total_ns(), 50);
    s.clock.now.store(10_020, Ordering::Release);
    assert_eq!(r.execution_current().unwrap().total_ns(), 70);
}
unsafe extern "C" fn service(p: *mut c_void) {
    // SAFETY: exact queue-kept hosted fixture, no original source task.
    let s = unsafe { &*p.cast::<Scene>() };
    let r = s.runtime();
    let wake = r.bind_current(s.service.clone()).unwrap();
    s.service_wake.lock().unwrap().replace(wake);
    s.domain
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .bind_current(r)
        .unwrap();
    assert_eq!(r.park_if_blocked(), Ok(ParkOutcome::Resumed));
}
#[test]
fn native_intervals_blocked_wake_irq_and_stopped_data_join() {
    let (executor, s, dropped) = setup();
    let r = executor.runtime();
    let domain = s.domain.lock().unwrap().as_ref().unwrap().clone();
    // SAFETY: fixture/code retained by queue; independent owned guarded Service stack.
    let ticket = unsafe { r.start_service(service, Arc::as_ptr(&s) as *mut c_void) }.unwrap();
    assert!(r.step().unwrap());
    assert!(!r.queue.completed(ticket).unwrap());
    let service_ticket = ticket;
    s.clock.now.store(100, Ordering::Release);
    // SAFETY: fixture/code retained through completion, real distinct General stack.
    let ticket = unsafe {
        r.queue
            .execute(Kind::General, measured, Arc::as_ptr(&s) as *mut c_void)
    }
    .unwrap();
    assert!(r.step().unwrap());
    let wake = s.wake.lock().unwrap().as_ref().unwrap().clone();
    assert_eq!(r.activity_for(&wake), Ok(scheduling::Activity::Blocked));
    s.clock.now.store(10_000, Ordering::Release);
    assert_eq!(r.execution_for(&wake).unwrap().total_ns(), 50);
    assert_eq!(s.binding.fields.through.load(Ordering::Acquire), 150);
    assert_eq!(
        r.take_stopped_publication(&wake).unwrap_err(),
        WorkError::Pending
    );
    s.binding.blocked.store(false, Ordering::Release);
    wake.wake().unwrap();
    // Wake changes the actual Board before dispatcher scans Task.state.
    assert_eq!(r.activity_for(&wake), Ok(scheduling::Activity::Ready));
    assert!(r.step().unwrap());
    assert!(r.queue.completed(ticket).unwrap());
    assert_eq!(s.binding.fields.total.load(Ordering::Acquire), 70);
    assert_eq!(s.binding.fields.through.load(Ordering::Acquire), 10_020);
    assert_eq!(r.activity_for(&wake), Err(WorkError::Closed));
    s.service.blocked.store(false, Ordering::Release);
    domain.stop_producers().unwrap();
    assert!(r.step().unwrap());
    assert!(r.queue.completed(service_ticket).unwrap());
    // SAFETY: sole real hosted Service frame physically returned; no source users.
    unsafe { domain.retire() }.unwrap();
    // SAFETY: joined plain hosted Service binding has no data lease.
    drop(
        unsafe {
            r.detach_binding(
                s.service_wake
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .context_id(),
            )
        }
        .unwrap(),
    );
    r.queue.close().unwrap();
    // SAFETY: admission closed/physical child and service joined; only field lease remains.
    assert_eq!(unsafe { r.retire() }, Err(WorkError::Pending));
    // SAFETY: same closed source/physical join; Queue has no binding test.
    assert_eq!(unsafe { r.queue.retire() }, Err(WorkError::Pending));
    // SAFETY: same stopped binding is kept; unresolved source data prevents detach.
    assert!(matches!(
        unsafe { r.detach_binding(wake.context_id()) },
        Err(WorkError::Pending)
    ));
    r.execution.fence.readers.store(1, Ordering::Release);
    assert_eq!(
        r.take_stopped_publication(&wake).unwrap_err(),
        WorkError::Pending
    );
    r.execution.fence.readers.store(0, Ordering::Release);
    let stop = r.take_stopped_publication(&wake).unwrap();
    let target: Arc<dyn ExecutionPublication> = s.binding.fields.clone();
    assert!(stop.matches(&target));
    assert_eq!(stop.identity().sequence(), wake.sequence());
    assert_eq!(
        r.take_stopped_publication(&wake).unwrap_err(),
        WorkError::Unavailable
    );
    // No real Linux task ref exists in this RAM-only hosted mechanism fixture.
    // Its source-reader model is now stopped, matching the explicit unsafe boundary.
    unsafe { stop.finish(&Authority(s.cpu.clone())) }.unwrap();
    // SAFETY: all fixture source users and native physical frame joined.
    drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
    unsafe { r.retire() }.unwrap();
    s.tap.lock().unwrap().take();
    s.domain.lock().unwrap().take();
    drop(domain);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Acquire), 4);
}
