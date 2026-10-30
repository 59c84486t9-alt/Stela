//! Protected GPE admission is independent from General queue pressure.
use super::*;
fn policy(budget: GpeQueueBudget) -> ReservationPolicy {
    ReservationPolicy::NativeFirmware16Protected { gpe: budget }
}
fn failed_construction<const N: usize>(queued: bool, expected: WorkError) {
    let count = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let cpu = test_support::CpuModel::new();
    // SAFETY: this same-thread modeled queue keeps the atomic context.
    let queue = unsafe { Queue::<N>::new(cpu.clone(), count.clone()) }.unwrap();
    let p = Arc::as_ptr(&count) as *mut c_void;
    let ticket = if queued {
        // SAFETY: the queue owns count through the subsequent legacy executor join.
        Some(unsafe { queue.execute(Kind::Notify, count_queued, p) }.unwrap())
    } else {
        None
    };
    let dropped = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let stacks = test_support::stacks(&dropped);
    Runtime::validate_stacks(&queue, &stacks).unwrap();
    // SAFETY: an unprivileged real x87/SSE snapshot, with no native grant.
    let controls = unsafe { context::read_controls() };
    let result = Runtime::with_layout_controls(
        queue.clone(),
        stacks,
        controls,
        policy(GpeQueueBudget::QUALIFICATION).layout(),
    );
    assert!(matches!(result,Err(error) if error==expected));
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert!(!queue.executor_claimed.load(Ordering::Acquire));
    assert_eq!(queue.lock().unwrap().state().layout, Layout::Ordinary);
    if let Some(ticket) = ticket {
        assert_eq!(queue.completed(ticket), Ok(false));
    }
    assert_eq!(count.load(Ordering::Relaxed), 0);
    let runtime =
        Runtime::with_controls(queue.clone(), test_support::stacks(&dropped), controls).unwrap();
    let executor = Executor {
        runtime: ManuallyDrop::new(runtime),
    };
    assert_eq!(executor.runtime().protected_gpe_budget(), Ok(None));
    queue.close().unwrap();
    executor
        .runtime()
        .drain(cpu.ticks() + 1_000_000_000)
        .unwrap();
    assert_eq!(count.load(Ordering::Relaxed), usize::from(queued));
    // SAFETY: no fixture producer exists and every admitted callback joined.
    unsafe { executor.runtime().retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
    assert_eq!(cpu.flags(), 0x202);
}
#[test]
fn protected_budget_and_construction_reject_invalid_geometry_without_taking_jobs() {
    assert_eq!(GpeQueueBudget::with_pending(0), Err(WorkError::Unavailable));
    assert_eq!(
        GpeQueueBudget::with_pending(usize::MAX),
        Err(WorkError::Exhausted)
    );
    assert_eq!(GpeQueueBudget::QUALIFICATION.total_jobs(), 2);
    assert_eq!(GpeQueueBudget::QUALIFICATION.protected_pending(), 1);
    failed_construction::<16>(false, WorkError::Unavailable);
    failed_construction::<17>(true, WorkError::Busy);
}
fn full_admission<const N: usize>(budget: GpeQueueBudget, general_capacity: usize) {
    full_admission_policy::<N>(policy(budget), budget, general_capacity);
}
fn full_admission_policy<const N: usize>(
    reservation: ReservationPolicy,
    budget: GpeQueueBudget,
    general_capacity: usize,
) {
    let count = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let (executor, cpu, dropped) =
        test_support::executor_with_policy::<N>(count.clone(), reservation);
    let r = executor.runtime();
    assert_eq!(r.protected_gpe_budget(), Ok(Some(budget)));
    let p = Arc::as_ptr(&count) as *mut c_void;
    for _ in 0..budget.total_jobs() {
        // SAFETY: all accepted callbacks borrow the queue-kept atomic allocation.
        unsafe { r.queue.execute_gpe(count_queued, p) }.unwrap();
    }
    assert_eq!(
        // SAFETY: Full transfers nothing, even though all ordinary slots are still free.
        unsafe { r.queue.execute_gpe(count_queued, p) },
        Err(WorkError::Full)
    );
    for _ in 0..general_capacity {
        // SAFETY: every General callback keeps this exact atomic context through join.
        unsafe { r.queue.execute(Kind::General, count_queued, p) }.unwrap();
    }
    assert_eq!(
        // SAFETY: ordinary overflow must not borrow a reserved role or GPE slot.
        unsafe { r.queue.execute(Kind::General, count_queued, p) },
        Err(WorkError::Full)
    );
    // SAFETY: queue-owned counter remains valid through each role's real completion.
    unsafe { r.start_service(count_queued, p) }.unwrap();
    // SAFETY: the independent control frame borrows the same counter.
    unsafe { r.start_firmware(count_queued, p) }.unwrap();
    for _ in 0..2 {
        // SAFETY: each accepted Portal owns a distinct continuation permit.
        unsafe { r.queue.execute_portal(count_queued, p) }.unwrap();
        // SAFETY: each accepted Notify owns a distinct continuation permit.
        unsafe { r.queue.execute(Kind::Notify, count_queued, p) }.unwrap();
    }
    assert_eq!(count.load(Ordering::Relaxed), 0);
    // SAFETY: the protected Foreground slot/context survive all peer stack exchanges.
    unsafe { r.call_foreground(count_queued, p, cpu.ticks() + 1_000_000_000) }.unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    assert_eq!(count.load(Ordering::Relaxed), N);
    // SAFETY: no producer remains and every admitted job returned.
    unsafe { r.retire() }.unwrap();
    assert_eq!(r.protected_gpe_budget(), Err(WorkError::Closed));
    assert_eq!(
        r.check_firmware_join(FirmwareQueue::Gpe),
        Err(WorkError::Closed)
    );
    drop(executor);
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        reservation.layout().stack_limit()
    );
    assert_eq!(cpu.flags(), 0x202);
}
#[test]
fn minimum_seventeen_and_sixty_four_slot_queues_keep_all_roles_admissible() {
    full_admission::<17>(GpeQueueBudget::QUALIFICATION, 8);
    full_admission::<64>(GpeQueueBudget::QUALIFICATION, 55);
}
#[test]
fn a_larger_named_gpe_budget_remains_fixed_even_with_spare_general_capacity() {
    let budget = GpeQueueBudget::with_pending(3).unwrap();
    assert_eq!(budget.total_jobs(), 4);
    full_admission::<19>(budget, 8);
}
#[test]
fn a_pending_gpe_keeps_its_own_slot_under_full_general_admission_and_stack_saturation() {
    let f = Scene::new();
    let (executor, cpu, dropped) =
        test_support::executor_with_policy::<32>(f.clone(), policy(GpeQueueBudget::QUALIFICATION));
    let r = executor.runtime();
    f.runtime
        .store(r.get_ref() as *const Runtime<32> as u64, Ordering::Release);
    let p = Arc::as_ptr(&f) as *mut c_void;
    for _ in 0..8 {
        // SAFETY: all blocking General frames keep Scene until explicit release.
        unsafe { r.queue.execute(Kind::General, general, p) }.unwrap();
    }
    for _ in 0..15 {
        // SAFETY: queued General markers borrow the same Scene and do not rebind.
        unsafe { r.queue.execute(Kind::General, ordinary_turn, p) }.unwrap();
    }
    assert_eq!(
        // SAFETY: all23 ordinary admission entries are occupied; rejection transfers nothing.
        unsafe { r.queue.execute(Kind::General, rejected, p) },
        Err(WorkError::Full)
    );
    // SAFETY: all role callbacks are covered by Scene's allocation.
    unsafe { r.start_service(service, p) }.unwrap();
    // SAFETY: the dedicated control context remains live while parked.
    unsafe { r.start_firmware(control, p) }.unwrap();
    for _ in 0..2 {
        // SAFETY: each portal context survives its parked frame.
        unsafe { r.queue.execute_portal(portal, p) }.unwrap();
        // SAFETY: each Notify context survives its parked frame.
        unsafe { r.queue.execute(Kind::Notify, notify, p) }.unwrap();
    }
    // SAFETY: active serial GPE frame keeps the same Scene until release.
    unsafe { r.queue.execute_gpe(gpe, p) }.unwrap();
    assert_eq!(
        // SAFETY: Foreground's reserved context remains held through its pending result.
        unsafe { r.call_foreground(foreground, p, cpu.ticks() + 1_000_000_000) },
        Err(WorkError::Pending)
    );
    assert_eq!(f.blocked.lock().unwrap().len(), 16);
    assert_eq!(r.step(), Ok(false));
    // SAFETY: this second GPE owns the protected pending slot despite full General admission.
    let pending = unsafe { r.queue.execute_gpe(marker, p) }.unwrap();
    assert_eq!(r.queue.completed(pending), Ok(false));
    assert_eq!(
        // SAFETY: the named2entry GPE budget is full; no callback/context is accepted.
        unsafe { r.queue.execute_gpe(rejected, p) },
        Err(WorkError::Full)
    );
    assert_eq!(r.step(), Ok(false));
    r.queue.close().unwrap();
    f.release(None);
    f.finish();
    assert_eq!(r.queue.completed(pending), Ok(true));
    let events = f.events.lock().unwrap();
    assert_eq!(events.iter().filter(|e| e.0 == 90).count(), 15);
    assert_eq!(events.iter().filter(|e| e.0 == 50).count(), 1);
    assert!(!events.iter().any(|e| e.0 == 99));
    assert_eq!(
        events.iter().find(|e| e.0 == 5).unwrap().1,
        events.iter().find(|e| e.0 == 50).unwrap().1
    );
    drop(events);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert_eq!(cpu.flags(), 0x202);
}

mod capacity32;
