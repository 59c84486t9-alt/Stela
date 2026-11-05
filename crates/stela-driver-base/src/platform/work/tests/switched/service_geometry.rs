//! Real guarded constructor mappings/roles, no original Initial/current model.
use super::*;

#[test]
fn reserved_service_observation_uses_actual_shape_and_rejects_irq() {
    let cpu = CpuModel::new();
    let drops = Arc::new(AtomicU64::new(0));
    let mapping_drops = Arc::new(AtomicU64::new(0));
    // SAFETY: exact creating host thread; actual guarded mappings are kept by
    // this hosted Runtime. No native hardware/source-root permission claimed.
    let queue = unsafe { Queue::<16>::new(cpu.clone(), Arc::new(Owner(drops))) }.unwrap();
    let executor = Executor::new_hosted_service_for_test(
        queue.clone(),
        stacks_count(mapping_drops.clone(), 5),
    )
    .unwrap();
    let runtime = executor.runtime();
    let exact = StackRequirement::exact(128 * 1024, 16, 4096).unwrap();
    let linux = StackRequirement::exact(16 * 1024, 16 * 1024, 4096).unwrap();
    assert_eq!(runtime.current_id(), Err(WorkError::Unavailable));
    assert_eq!(runtime.service_supports(exact), Ok(true));
    assert_eq!(runtime.service_supports(linux), Ok(false));
    assert_eq!(runtime.current_id(), Err(WorkError::Unavailable));
    cpu.irq.store(true, Ordering::Release);
    assert_eq!(
        runtime.service_supports(exact),
        Err(WorkError::InterruptContext)
    );
    cpu.irq.store(false, Ordering::Release);
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
    queue.close().unwrap();
    // SAFETY: no callback admitted, all exact constructor frames idle, no
    // binding/timer/IRQ/native or original C producer ever installed.
    unsafe { runtime.retire() }.unwrap();
    assert_eq!(runtime.service_supports(exact), Err(WorkError::Closed));
    drop(executor);
    drop(queue);
    assert_eq!(mapping_drops.load(Ordering::Acquire), 5);
}

#[test]
fn same_shape_on_general_lane_does_not_create_service_role() {
    let cpu = CpuModel::new();
    let drops = Arc::new(AtomicU64::new(0));
    let mapping_drops = Arc::new(AtomicU64::new(0));
    // SAFETY: actual current host thread and owned guarded native stacks only.
    let queue = unsafe { Queue::<16>::new(cpu, Arc::new(Owner(drops))) }.unwrap();
    let executor =
        Executor::new_hosted_for_test(queue.clone(), stacks(mapping_drops.clone())).unwrap();
    let runtime = executor.runtime();
    assert_eq!(
        runtime.service_supports(StackRequirement::exact(128 * 1024, 16, 4096).unwrap()),
        Ok(false)
    );
    queue.close().unwrap();
    // SAFETY: genuinely no submitted job, binding, service or external reader.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
    drop(queue);
    assert_eq!(mapping_drops.load(Ordering::Acquire), 4);
}
