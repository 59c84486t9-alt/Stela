//! Actual stack geometry controls dispatch; descriptors alone grant no native authority.
use super::super::super::StackBacking;
use super::*;
use core::sync::atomic::AtomicUsize;
mod support;
use support::{Fixture, record};
fn kernel() -> StackRequirement {
    StackRequirement::exact(16 * 1024, 16 * 1024, 4096).unwrap()
}
fn ordinary() -> StackRequirement {
    StackRequirement::at_least(128 * 1024, 4096, 4096).unwrap()
}
fn profile() -> StackProfile {
    StackProfile::new(kernel(), ordinary(), 20, 4).unwrap()
}
fn policy() -> ReservationPolicy {
    ReservationPolicy::NativeFirmware32Protected {
        gpe: GpeQueueBudget::QUALIFICATION,
    }
}
#[test]
fn descriptors_reject_invalid_size_alignment_guard_and_counts() {
    for (bytes, alignment, guard) in [
        (0, 4096, 4096),
        (16 * 1024 + 1, 4096, 4096),
        (usize::MAX, 4096, 4096),
        (16 * 1024, 0, 4096),
        (16 * 1024, 3, 4096),
        (16 * 1024, 4096, 0),
        (16 * 1024, 4096, 4097),
    ] {
        assert_eq!(
            StackRequirement::exact(bytes, alignment, guard),
            Err(WorkError::InvalidStack)
        );
    }
    for (kernel_count, ordinary_count) in [(0, 24), (20, 0), (21, 4), (usize::MAX, 1)] {
        assert_eq!(
            StackProfile::new(kernel(), ordinary(), kernel_count, ordinary_count),
            Err(WorkError::Unavailable)
        );
    }
}
#[test]
fn all_mixed_roles_use_their_actual_geometry_with_rust_workers_first() {
    let f = Fixture::new();
    let (executor, cpu, dropped) = support::executor(f.clone());
    let r = executor.runtime();
    // SAFETY: Case and fixture/code remain retained by this queue until actual join.
    unsafe { r.start_service(record, f.context(100, kernel(), false)) }.unwrap();
    // SAFETY: control uses an independent actual ordinary-size reserved continuation.
    unsafe { r.start_firmware(record, f.context(101, ordinary(), false)) }.unwrap();
    // SAFETY: serial GPE context remains retained through completion.
    unsafe {
        r.queue
            .execute_gpe(record, f.context(102, ordinary(), false))
    }
    .unwrap();
    for i in 0..2 {
        // SAFETY: each accepted role owns its actual permit and immutable retained Case.
        unsafe {
            r.queue
                .execute(Kind::Notify, record, f.context(110 + i, ordinary(), false))
        }
        .unwrap();
        // SAFETY: each accepted Portal context/stack remains live through real join.
        unsafe {
            r.queue
                .execute_portal(record, f.context(120 + i, ordinary(), false))
        }
        .unwrap();
    }
    for i in 0..20 {
        // SAFETY: explicit small callback fits exact kernel requirement; this is queued work, not thread creation.
        unsafe {
            r.queue.execute_general_with_requirement(
                kernel(),
                record,
                f.context(i, kernel(), false),
            )
        }
        .unwrap();
    }
    for i in 0..4 {
        // SAFETY: default General requirement is ordinary; retained callback fits that actual extent.
        unsafe {
            r.queue
                .execute(Kind::General, record, f.context(200 + i, ordinary(), false))
        }
        .unwrap();
    }
    // SAFETY: actual Foreground and its immutable Case survive every exchange.
    unsafe {
        r.call_foreground(
            record,
            f.context(199, ordinary(), false),
            cpu.ticks() + 1_000_000_000,
        )
    }
    .unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    let seen = f.seen.lock().unwrap();
    assert_eq!(seen.len(), 32);
    let mut ids: Vec<_> = seen.iter().map(|(_, v)| v.context_id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 32);
    drop(seen);
    f.finish(&cpu);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn ordinary_backlog_cannot_borrow_idle_kernel_workers() {
    let f = Fixture::new();
    let (executor, cpu, dropped) = support::executor(f.clone());
    let r = executor.runtime();
    for i in 0..4 {
        // SAFETY: all four ordinary callbacks retain real blocked frames until explicit release.
        unsafe {
            r.queue
                .execute(Kind::General, record, f.context(i, ordinary(), true))
        }
        .unwrap();
    }
    while r.step().unwrap() {}
    assert_eq!(f.parked.lock().unwrap().len(), 4);
    // SAFETY: retained ordinary callback may wait in the queue; no idle-worker success is implied.
    let waiting = unsafe {
        r.queue
            .execute(Kind::General, record, f.context(10, ordinary(), false))
    }
    .unwrap();
    assert_eq!(r.step(), Ok(false));
    assert_eq!(r.queue.completed(waiting), Ok(false));
    // SAFETY: exact requested geometry admits a real idle kernel-size worker.
    let kernel_job = unsafe {
        r.queue
            .execute_general_with_requirement(kernel(), record, f.context(20, kernel(), false))
    }
    .unwrap();
    assert_eq!(r.step(), Ok(true));
    assert_eq!(r.queue.completed(kernel_job), Ok(true));
    assert_eq!(r.queue.completed(waiting), Ok(false));
    assert_eq!(f.parked.lock().unwrap().len(), 4);
    f.finish(&cpu);
    assert_eq!(r.queue.completed(waiting), Ok(true));
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn queued_requirements_reject_unsupported_geometry_before_transfer_or_sequence() {
    let f = Fixture::new();
    let (executor, cpu, dropped) = support::executor(f.clone());
    let r = executor.runtime();
    let before = r.queue.lock().unwrap().state().next;
    let unavailable = StackRequirement::exact(64 * 1024, 4096, 4096).unwrap();
    assert_eq!(
        // SAFETY: rejection must not accept this retained Case or run its callback.
        unsafe {
            r.queue.execute_general_with_requirement(
                unavailable,
                record,
                f.context(1, unavailable, false),
            )
        },
        Err(WorkError::Unavailable)
    );
    assert_eq!(r.queue.lock().unwrap().state().next, before);
    assert!(f.seen.lock().unwrap().is_empty());
    f.finish(&cpu);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
fn rejected_profile(kind: u8) {
    let f = Fixture::new();
    let cpu = test_support::CpuModel::new();
    // SAFETY: same-thread model retains Fixture, with no hardware/foreign producer.
    let q = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut stacks = support::stacks(&dropped, if kind == 0 { 21 } else { 20 });
    if kind == 1 {
        stacks[2] = support::mapped(kernel(), 4096, &dropped);
    }
    if kind == 2 {
        stacks[2] = support::mapped(ordinary(), 0, &dropped);
    }
    let expected_drop = if kind == 1 || kind == 2 { 33 } else { 32 };
    let selected = if kind == 3 {
        StackProfile::new(
            kernel(),
            StackRequirement::at_least(16 * 1024, 4096, 4096).unwrap(),
            20,
            4,
        )
        .unwrap()
    } else if kind == 4 {
        StackProfile::new(
            StackRequirement::exact(16 * 1024, 16 * 1024, 8192).unwrap(),
            ordinary(),
            20,
            4,
        )
        .unwrap()
    } else {
        profile()
    };
    assert!(matches!(
        Executor::new_hosted_profile_for_test(q.clone(), stacks, policy(), selected),
        Err(WorkError::InvalidStack)
    ));
    assert_eq!(dropped.load(Ordering::Relaxed), expected_drop);
    assert!(!q.executor_claimed.load(Ordering::Acquire));
    assert_eq!(q.lock().unwrap().state().stack_profile, None);
    let executor =
        Executor::new_hosted_for_test(q.clone(), test_support::stacks(&dropped)).unwrap();
    f.publish(executor.runtime());
    assert_eq!(
        // SAFETY: typed request must refuse before any profile was genuinely constructed.
        unsafe {
            q.execute_general_with_requirement(kernel(), record, f.context(1, kernel(), false))
        },
        Err(WorkError::Unavailable)
    );
    f.finish(&cpu);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), expected_drop + 16);
}
#[test]
fn wrong_counts_size_alignment_overlap_and_guard_leave_real_queue_unclaimed() {
    for kind in 0..5 {
        rejected_profile(kind);
    }
}

#[test]
fn oldest_compatible_jobs_preserve_order_within_each_actual_pool() {
    let f = Fixture::new();
    let (executor, cpu, dropped) = support::executor(f.clone());
    let r = executor.runtime();
    for tag in 0..6 {
        let required = if tag % 2 == 0 { kernel() } else { ordinary() };
        // SAFETY: each explicit immutable Case fits its requested actual geometry and remains retained through join.
        unsafe {
            r.queue.execute_general_with_requirement(
                required,
                record,
                f.context(tag, required, false),
            )
        }
        .unwrap();
    }
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    let seen = f.seen.lock().unwrap();
    for parity in 0..2 {
        assert_eq!(
            seen.iter()
                .map(|(tag, _)| *tag)
                .filter(|tag| tag % 2 == parity)
                .collect::<Vec<_>>(),
            (0..6).filter(|tag| tag % 2 == parity).collect::<Vec<_>>()
        );
    }
    drop(seen);
    f.finish(&cpu);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn nonempty_queue_refuses_profile_without_reinterpreting_its_original_callback() {
    let f = Fixture::new();
    let cpu = test_support::CpuModel::new();
    // SAFETY: exact fixture allocation survives the later unprofiled fallback executor and real join.
    let q = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    // SAFETY: original ordinary callback is valid for the retained128KiB fallback stacks.
    let ticket =
        unsafe { q.execute(Kind::General, record, f.context(7, ordinary(), false)) }.unwrap();
    let next = q.lock().unwrap().state().next;
    let dropped = Arc::new(AtomicUsize::new(0));
    assert!(matches!(
        Executor::new_hosted_profile_for_test(
            q.clone(),
            support::stacks(&dropped, 20),
            policy(),
            profile()
        ),
        Err(WorkError::Busy)
    ));
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
    assert!(!q.executor_claimed.load(Ordering::Acquire));
    assert_eq!(q.lock().unwrap().state().stack_profile, None);
    assert_eq!(q.lock().unwrap().state().next, next);
    assert_eq!(q.completed(ticket), Ok(false));
    assert!(f.seen.lock().unwrap().is_empty());
    let executor =
        Executor::new_hosted_for_test(q.clone(), test_support::stacks(&dropped)).unwrap();
    f.publish(executor.runtime());
    f.finish(&cpu);
    assert_eq!(q.completed(ticket), Ok(true));
    assert_eq!(f.seen.lock().unwrap()[0].0, 7);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 48);
}

mod general_reservation;

mod owned_escrow;
