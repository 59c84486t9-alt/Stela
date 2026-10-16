use super::*;

fn reserve(
    thread: &mut MemoryThread<Policy>,
) -> monitor::Access<MemoryBacking, MemoryView, MappingAttributes> {
    let access = reservation_access(&thread.domain, 0);
    thread
        .domain
        .system
        .reservations
        .load(&mut thread.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    access
}

fn fixture() -> (Arc<MemoryBacking>, Arc<MemoryDomain>, MemoryThread<Policy>) {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let thread = domain.thread(Policy::default());
    (backing, domain, thread)
}

#[test]
fn checked_entry_returns_healthy_body_result() {
    let (_, _, mut thread) = fixture();
    let entry = thread.prepare(MemoryRequirements::default()).unwrap();
    // SAFETY: no native pointer is retained or accessed by this body.
    assert_eq!(unsafe { entry.with_checked_view(|_| 37) }, Ok(37));
}

#[test]
fn callback_fault_clears_actual_reservation_and_preserves_fault() {
    let (backing, domain, mut thread) = fixture();
    let access = reserve(&mut thread);
    thread.policy.reject = Some(GUEST_BASE);
    let mut data = [0x7c];
    let request = MemoryRequest {
        address: GUEST_BASE,
        data: data.as_mut_ptr(),
        bytes: 1,
        flags: 0,
        pc: TEST_PC,
    };
    // SAFETY: valid synchronous ABI request and disjoint private staging.
    let result = unsafe {
        thread.with_checked_view(|context| {
            let status = (context.callback)(context, &request);
            (
                status,
                context.fault_address,
                context.fault_pc,
                context.completed_bytes,
            )
        })
    };
    assert_eq!(
        result,
        Ok((MemoryStatus::TagCheck as u32, GUEST_BASE, TEST_PC, 0))
    );
    assert_eq!(data, [0x7c]);
    assert_eq!(snapshot(&backing, 1), [0]);
    assert_eq!(
        domain.system.reservations.store(
            &mut thread.reservation,
            &access,
            || -> Result<(), MemoryStatus> { panic!("cleared reservation invoked store") }
        ),
        Ok(monitor::ConditionalWrite::<()>::Failed)
    );
}

#[test]
fn local_alignment_fault_clears_actual_reservation() {
    let (_, domain, mut thread) = fixture();
    let access = reserve(&mut thread);
    // SAFETY: this body records a local fault without exposing ABI pointers.
    let result = unsafe {
        thread.with_checked_view(|context| {
            context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 3);
            (
                context.fault_kind,
                context.fault_address,
                context.fault_pc,
                context.completed_bytes,
            )
        })
    };
    assert_eq!(
        result,
        Ok((MemoryStatus::Alignment as u32, GUEST_BASE + 1, TEST_PC, 3))
    );
    assert_eq!(
        domain.system.reservations.store(
            &mut thread.reservation,
            &access,
            || -> Result<(), MemoryStatus> { panic!("local fault did not clear") }
        ),
        Ok(monitor::ConditionalWrite::<()>::Failed)
    );
}

#[test]
fn post_body_health_failure_discards_result_without_rolling_back_write() {
    let (backing, domain, mut thread) = fixture();
    let mut data = [0x6b];
    let request = MemoryRequest {
        address: GUEST_BASE,
        data: data.as_mut_ptr(),
        bytes: 1,
        flags: flags::WRITE,
        pc: TEST_PC,
    };
    let mut prefix = None;
    // SAFETY: valid synchronous ABI request and disjoint private staging.
    let result = unsafe {
        thread.with_checked_view(|context| {
            let status = (context.callback)(context, &request);
            prefix = Some((status, context.completed_bytes));
            domain.system.failed.store(true, Ordering::Release);
            91
        })
    };
    assert_eq!(result, Err(MemoryStatus::Domain));
    assert_eq!(prefix, Some((MemoryStatus::Success as u32, 1)));
    assert_eq!(snapshot(&backing, 1), [0x6b]);
    assert_eq!(
        thread.prepare(MemoryRequirements::default()).err(),
        Some(MemoryStatus::Domain)
    );
}

#[test]
fn local_alignment_late_failure_preserves_external_provenance() {
    let (_, domain, mut thread) = fixture();
    let mut fault = None;
    // SAFETY: this body records a local fault; it retains only copied scalars.
    let result = unsafe {
        thread.with_checked_view(|context| {
            context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 5);
            fault = Some((
                context.fault_kind,
                context.fault_address,
                context.fault_pc,
                context.completed_bytes,
            ));
            domain.system.failed.store(true, Ordering::Release);
            72
        })
    };
    assert_eq!(result, Err(MemoryStatus::Domain));
    assert_eq!(
        fault,
        Some((MemoryStatus::Alignment as u32, GUEST_BASE + 1, TEST_PC, 5))
    );
}

#[test]
fn actual_monitor_failure_during_body_is_reported_by_post_body_health() {
    let (backing, domain, mut thread) = fixture();
    reserve(&mut thread);
    let range = monitor::WriteRange::new(backing, 0, 1).unwrap();
    // SAFETY: the body uses the real writer gate, catches its deliberate panic,
    // and records a local fault; no pointers or owner borrows escape.
    let result = unsafe {
        thread.with_checked_view(|context| {
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = domain.system.reservations.with_writer(
                    &range,
                    monitor::Invalidation::OnCommit,
                    || -> Result<(), MemoryStatus> { panic!("deliberate real monitor failure") },
                );
            }));
            assert!(failure.is_err());
            context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 0);
            84
        })
    };
    assert_eq!(result, Err(MemoryStatus::Domain));
    assert_eq!(domain.check_execution(), Err(MemoryStatus::Domain));
}

#[test]
fn malformed_fault_status_fails_finalization() {
    let (_, _, mut thread) = fixture();
    // SAFETY: deliberate invalid fault-sidecar input tests defensive handling;
    // header, callback and owner fields remain intact and no pointers escape.
    assert_eq!(
        unsafe {
            thread.with_checked_view(|context| {
                context.fault_kind = u32::MAX;
                19
            })
        },
        Err(MemoryStatus::Domain)
    );
}

#[test]
fn legacy_result_does_not_assert_successful_finalization() {
    let (_, domain, mut thread) = fixture();
    // SAFETY: no pointer access or escape; this tests the documented legacy API.
    assert_eq!(
        unsafe {
            thread.with_view(|_| {
                domain.system.failed.store(true, Ordering::Release);
                26
            })
        },
        26
    );
    assert_eq!(domain.check_execution(), Err(MemoryStatus::Domain));
}
