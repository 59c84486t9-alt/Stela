use super::*;

#[test]
fn controlled_tag_fault_clears_other_reservation_and_releases_writer_gate() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut observer = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    domain
        .system
        .reservations
        .load(&mut observer.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    let mut writer = domain.thread(Policy {
        reject: Some(GUEST_BASE),
        ..Policy::default()
    });
    let mut bytes = [0x6b];
    let fault = invoke(
        &mut writer,
        GUEST_BASE,
        &mut bytes,
        flags::WRITE | flags::TAG_CHECKED,
    );
    assert_eq!(fault.status, MemoryStatus::TagCheck as u32);
    assert_eq!(fault.completed, 0);
    assert_eq!(snapshot(&backing, 1), [0]);
    let conditional = domain
        .system
        .reservations
        .store(&mut observer.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    assert_eq!(conditional, monitor::ConditionalWrite::Failed);
    writer.policy_mut().reject = None;
    assert_eq!(
        invoke(&mut writer, GUEST_BASE, &mut bytes, flags::WRITE).status,
        MemoryStatus::Success as u32
    );
    assert_eq!(snapshot(&backing, 1), bytes);
    assert!(domain.check_execution().is_ok());
}

#[test]
fn retirement_rejects_access_and_invalidates_reserved_mapping() {
    let backing = backing();
    let mapping = view(&backing, 0, STORAGE_BYTES, RIGHTS);
    let domain = domain(vec![Arc::clone(&mapping)]);
    let mut thread = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    domain
        .system
        .reservations
        .load(&mut thread.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    domain.retire(&mapping).unwrap();
    assert!(!mapping.is_current());
    assert!(matches!(
        domain.system.reservations.store(
            &mut thread.reservation,
            &access,
            || Ok::<_, MemoryStatus>(())
        ),
        Err(monitor::AccessError::Monitor(
            monitor::MonitorError::DeadMapping
        ))
    ));
    let mut bytes = [0];
    assert_eq!(
        invoke(&mut thread, GUEST_BASE, &mut bytes, 0).status,
        MemoryStatus::Translation as u32
    );
}

#[test]
fn discontiguous_physical_views_and_overlapping_guest_views_decline() {
    let backing = backing();
    let first = view(&backing, 0, 4, RIGHTS);
    let discontiguous =
        MemoryView::new(Arc::clone(&backing), GUEST_BASE + 4, 16, 12, RIGHTS).unwrap();
    let domain = domain(vec![Arc::clone(&first), discontiguous]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [0x3d; 8];
    assert_eq!(
        invoke(&mut thread, GUEST_BASE, &mut bytes, flags::WRITE).status,
        MemoryStatus::Unsupported as u32
    );
    assert_eq!(snapshot(&backing, 8), [0; 8]);
    assert!(
        MemoryDomain::new(
            MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
            vec![
                (first, ATTRIBUTES),
                (view(&backing, 2, 4, RIGHTS), ATTRIBUTES)
            ],
            TargetCpu::Baseline,
        )
        .is_err()
    );
}

fn in_system(system: &Arc<MemorySystem>, views: Vec<Arc<MemoryView>>) -> Arc<MemoryDomain> {
    MemoryDomain::new(
        Arc::clone(system),
        views.into_iter().map(|view| (view, ATTRIBUTES)).collect(),
        TargetCpu::detect(),
    )
    .unwrap()
}

#[test]
fn shared_backing_writer_invalidates_reservations_across_address_spaces() {
    let physical = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let first = in_system(&system, vec![view(&physical, 0, STORAGE_BYTES, RIGHTS)]);
    let alias_base = GUEST_BASE * 2;
    let alias =
        MemoryView::new(Arc::clone(&physical), alias_base, 0, STORAGE_BYTES, RIGHTS).unwrap();
    let second = in_system(&system, vec![alias]);
    let mut observer = first.thread(Policy::default());
    let access = reservation_access(&first, 0);
    system
        .reservations
        .load(&mut observer.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    let mut writer = second.thread(Policy::default());
    let mut bytes = [0x43];
    assert_eq!(
        invoke(&mut writer, alias_base, &mut bytes, flags::WRITE).status,
        MemoryStatus::Success as u32
    );
    assert_eq!(
        system
            .reservations
            .store(
                &mut observer.reservation,
                &access,
                || Ok::<_, MemoryStatus>(())
            )
            .unwrap(),
        monitor::ConditionalWrite::Failed
    );
    assert_eq!(snapshot(&physical, 1), bytes);
}

#[test]
fn conflicting_system_cannot_register_a_live_physical_backing() {
    let physical = backing();
    let first_system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let second_system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    let first = in_system(&first_system, vec![Arc::clone(&mapping)]);
    let same_system_snapshot = in_system(&first_system, vec![Arc::clone(&mapping)]);
    assert!(matches!(
        MemoryDomain::new(
            Arc::clone(&second_system),
            vec![(Arc::clone(&mapping), ATTRIBUTES)],
            TargetCpu::Baseline
        ),
        Err(MemoryStatus::Domain)
    ));
    drop(first_system);
    drop(first);
    assert!(matches!(
        MemoryDomain::new(
            Arc::clone(&second_system),
            vec![(Arc::clone(&mapping), ATTRIBUTES)],
            TargetCpu::Baseline
        ),
        Err(MemoryStatus::Domain)
    ));
    drop(same_system_snapshot);
    assert!(
        MemoryDomain::new(
            second_system,
            vec![(mapping, ATTRIBUTES)],
            TargetCpu::Baseline
        )
        .is_ok()
    );
}

#[test]
fn retirement_reaches_reservations_from_every_snapshot_of_the_same_view() {
    let physical = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    let first = in_system(&system, vec![Arc::clone(&mapping)]);
    let second = in_system(&system, vec![Arc::clone(&mapping)]);
    let alias = in_system(&system, vec![view(&physical, 0, STORAGE_BYTES, RIGHTS)]);
    let mut observer = second.thread(Policy::default());
    let original = reservation_access(&second, 0);
    system
        .reservations
        .load(&mut observer.reservation, &original, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    first.retire(&mapping).unwrap();
    let alias_access = reservation_access(&alias, 0);
    let result = system
        .reservations
        .store(&mut observer.reservation, &alias_access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    assert_eq!(result, monitor::ConditionalWrite::Failed);
}

#[test]
fn one_view_generation_cannot_change_attributes_between_live_snapshots() {
    let physical = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    let original = in_system(&system, vec![Arc::clone(&mapping)]);
    let changed = MappingAttributes {
        tagged: !ATTRIBUTES.tagged,
        ..ATTRIBUTES
    };
    assert!(matches!(
        MemoryDomain::new(
            Arc::clone(&system),
            vec![(Arc::clone(&mapping), changed)],
            TargetCpu::Baseline
        ),
        Err(MemoryStatus::InvalidRequest)
    ));
    let unchanged = in_system(&system, vec![mapping]);
    assert!(Arc::ptr_eq(
        &original.registered_views()[0].monitor,
        &unchanged.registered_views()[0].monitor
    ));
}

#[test]
fn retiring_an_unregistered_view_declines_without_mutation() {
    let physical = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    let original = in_system(&system, vec![mapping]);
    let unregistered = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    assert_eq!(
        original.retire(&unregistered),
        Err(MemoryStatus::InvalidRequest)
    );
    assert!(unregistered.is_current());
    assert!(original.registered_views()[0].view.is_current());
}

#[test]
fn platform_and_abi_declines_preserve_existing_local_reservation() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut thread = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    for unavailable in [true, false] {
        domain
            .system
            .reservations
            .load(&mut thread.reservation, &access, || {
                Ok::<_, MemoryStatus>(())
            })
            .unwrap();
        thread.policy_mut().unavailable = unavailable;
        let mut staging = [0x7b; 3];
        let result = invoke(&mut thread, GUEST_BASE, &mut staging, flags::WRITE);
        assert_eq!(
            result.status,
            if unavailable {
                MemoryStatus::Unsupported
            } else {
                MemoryStatus::InvalidRequest
            } as u32
        );
        assert_eq!(result.completed, 0);
        assert_eq!(snapshot(&backing, 3), [0; 3]);
        thread.policy_mut().unavailable = false;
        assert_eq!(
            domain
                .system
                .reservations
                .store(&mut thread.reservation, &access, || Ok::<_, MemoryStatus>(
                    ()
                )),
            Ok(monitor::ConditionalWrite::Stored(()))
        );
    }
}

#[test]
fn local_native_fault_record_clears_reservation_at_invocation_return() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut thread = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    domain
        .system
        .reservations
        .load(&mut thread.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    // SAFETY: the callback only records a local fault, retaining no pointers.
    unsafe {
        thread.with_view(|context| {
            context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 0)
        });
    }
    assert_eq!(
        domain.system.reservations.store(
            &mut thread.reservation,
            &access,
            || Ok::<_, MemoryStatus>(())
        ),
        Ok(monitor::ConditionalWrite::Failed)
    );
    assert_eq!(snapshot(&backing, 1), [0]);
}
