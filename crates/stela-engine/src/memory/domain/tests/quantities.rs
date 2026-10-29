use super::*;

#[test]
fn crossing_quadword_split_requires_explicit_predicated_sve_or_asimd() {
    for descriptor in [
        0,
        flags::SME,
        flags::SME | flags::SVE_PREDICATED,
        flags::SVE_PREDICATED,
        flags::ASIMD,
    ] {
        let backing = backing();
        let readonly = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let domain = domain(vec![
            view(&backing, 0, 11, RIGHTS),
            view(&backing, 11, 21, readonly),
        ]);
        let mut thread = domain.thread(Policy::default());
        let mut bytes = [0x63; 16];
        let result = invoke(
            &mut thread,
            GUEST_BASE + 8,
            &mut bytes,
            flags::WRITE | descriptor,
        );
        let special = descriptor & flags::SME == 0
            && descriptor & (flags::SVE_PREDICATED | flags::ASIMD) != 0;
        assert_eq!(result.status, MemoryStatus::Permission as u32);
        assert_eq!(result.completed, if special { 0 } else { 3 });
        assert_eq!(
            result.fault_address,
            GUEST_BASE + if special { 8 } else { 11 }
        );
        assert_eq!(
            &snapshot(&backing, 16)[8..11],
            if special { &[0; 3] } else { &[0x63; 3] }
        );
    }
}

#[test]
fn raw_reached_part_translation_precedes_permissions_and_retains_prefix() {
    use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
    for tbi in [false, true] {
        let backing = backing();
        let denied = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let views = vec![
            MemoryView::new(backing.clone(), 0xfff0, 0, 16, RIGHTS).unwrap(),
            MemoryView::new(backing.clone(), 0x10000, 16, 16, denied).unwrap(),
        ];
        let domain = domain(views);
        let controls = MemoryControls::new(
            LowerAddressProfile::new(16, tbi).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        );
        let mut thread = domain.thread(controls);
        let mut staging = [0x7c; 2];
        let raw = 0xffff | if tbi { 0xa500_0000_0000_0000 } else { 0 };
        let request = MemoryRequest {
            address: raw,
            data: staging.as_mut_ptr(),
            bytes: 2,
            flags: flags::WRITE,
            pc: TEST_PC,
        };
        // SAFETY: staging is a live, disjoint two-byte array for the callback. The fixture
        // keeps the domain; no view or staging pointer escapes this closure.
        unsafe {
            thread.with_view(|context| {
                assert_eq!(
                    (context.callback)(context, &request),
                    MemoryStatus::Translation as u32
                );
                assert_eq!(context.completed_bytes, 1);
                assert_eq!(context.fault_address, raw + 1);
                assert_eq!(context.fault_pc, TEST_PC);
            });
        }
        assert_eq!(snapshot(&backing, 17)[15..17], [0x7c, 0]);
    }
}

#[test]
fn fault_settlement_preserves_declines_and_clears_selected_architectural_faults() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut thread = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    for status in [
        MemoryStatus::Translation,
        MemoryStatus::Permission,
        MemoryStatus::Alignment,
        MemoryStatus::StackAlignment,
        MemoryStatus::TagCheck,
        MemoryStatus::Unsupported,
        MemoryStatus::InvalidRequest,
    ] {
        domain
            .system
            .reservations
            .load(&mut thread.reservation, &access, || {
                Ok::<_, MemoryStatus>(())
            })
            .unwrap();
        thread.settle_fault(status).unwrap();
        let outcome = domain
            .system
            .reservations
            .store(&mut thread.reservation, &access, || {
                Ok::<_, MemoryStatus>(())
            })
            .unwrap();
        assert_eq!(
            outcome,
            if is_guest_fault(status as u32) {
                monitor::ConditionalWrite::Failed
            } else {
                monitor::ConditionalWrite::Stored(())
            }
        );
    }
}

#[test]
fn sme_crossing_prefix_invalidates_only_bytes_actually_written() {
    let backing = backing();
    let readonly = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let domain = MemoryDomain::new(
        system.clone(),
        vec![
            (view(&backing, 0, 11, RIGHTS), ATTRIBUTES),
            (view(&backing, 11, 21, readonly), ATTRIBUTES),
        ],
        TargetCpu::detect(),
    )
    .unwrap();
    let mut writer = domain.thread(Policy::default());
    let mut touched = domain.thread(Policy::default());
    let mut untouched = domain.thread(Policy::default());
    let touched_access = reservation_access(&domain, 10);
    let untouched_access = monitor::Access::new(
        backing.clone(),
        domain.registered_views()[1].monitor.clone(),
        16,
        1,
        monitor::Shape::Scalar,
    )
    .unwrap();
    system
        .reservations
        .load(&mut touched.reservation, &touched_access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    system
        .reservations
        .load(&mut untouched.reservation, &untouched_access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    let mut bytes = [0x5e; 16];
    let result = invoke(
        &mut writer,
        GUEST_BASE + 8,
        &mut bytes,
        flags::WRITE | flags::SME,
    );
    assert_eq!(result.completed, 3);
    assert_eq!(
        system
            .reservations
            .store(&mut touched.reservation, &touched_access, || Ok::<
                _,
                MemoryStatus,
            >(
                ()
            ))
            .unwrap(),
        monitor::ConditionalWrite::Failed
    );
    assert_eq!(
        system
            .reservations
            .store(&mut untouched.reservation, &untouched_access, || Ok::<
                _,
                MemoryStatus,
            >(
                ()
            ))
            .unwrap(),
        monitor::ConditionalWrite::Stored(())
    );
}

#[test]
fn each_wrapping_raw_part_is_translated_in_its_own_regime() {
    struct WrappingPolicy;
    impl DataPolicy for WrappingPolicy {
        fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn translate(&self, address: u64) -> Result<u64, MemoryStatus> {
            Ok(address & 0xffff)
        }
        fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
            Ok(())
        }
    }
    let backing = backing();
    let domain = domain(vec![
        MemoryView::new(backing.clone(), 0xfff0, 0, 16, RIGHTS).unwrap(),
        MemoryView::new(backing.clone(), 0, 16, 16, RIGHTS).unwrap(),
    ]);
    let mut thread = domain.thread(WrappingPolicy);
    let mut staging = [0x2d, 0x7b];
    let request = MemoryRequest {
        address: u64::MAX,
        data: staging.as_mut_ptr(),
        bytes: 2,
        flags: flags::WRITE,
        pc: TEST_PC,
    };
    // SAFETY: The two-byte staging array is live and disjoint from backing RAM.
    // The kept domain checks the guest address; pointers do not escape.
    unsafe {
        thread.with_view(|context| {
            assert_eq!(
                (context.callback)(context, &request),
                MemoryStatus::Success as u32
            );
            assert_eq!(context.completed_bytes, 2);
        });
    }
    assert_eq!(snapshot(&backing, 17)[15..17], staging);
}

#[test]
fn local_stack_fault_keeps_named_provenance_and_clears_selected_reservation() {
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
    // SAFETY: The kept fixture owns this thread and its callback. The closure
    // updates only fault metadata and keeps no pointer to the view.
    unsafe {
        thread.with_view(|context| {
            context.record(MemoryStatus::StackAlignment, GUEST_BASE + 1, TEST_PC, 0);
            assert_eq!(context.fault_kind, 8);
            assert_eq!(context.fault_address, GUEST_BASE + 1);
            assert_eq!(context.fault_pc, TEST_PC);
            assert_eq!(context.completed_bytes, 0);
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

#[test]
fn exact_pair_and_asimd_quantity_table_preserves_mem_branch_order() {
    let cases: &[(usize, usize, u32, &[usize], bool)] = &[
        (0, 16, flags::ASIMD, &[8, 8], false),
        (8, 16, flags::ASIMD, &[8, 8], false),
        (0, 16, flags::ASIMD | flags::PAIR, &[8, 8], true),
        (8, 16, flags::ASIMD | flags::PAIR, &[8, 8], true),
        (0, 32, flags::ASIMD | flags::PAIR, &[8, 8, 8, 8], false),
        (8, 32, flags::ASIMD | flags::PAIR, &[8, 8, 8, 8], false),
        (4, 8, flags::PAIR, &[8], true),
        (12, 8, flags::PAIR, &[4, 4], false),
        (0, 16, flags::PAIR, &[16], true),
        (8, 16, flags::PAIR, &[8, 8], false),
        (0, 16, flags::SVE_PREDICATED, &[16], false),
        (8, 16, flags::SVE_PREDICATED, &[8, 8], false),
        (8, 16, flags::SME, &[1; 16], false),
    ];
    for (residue, bytes, descriptor, widths, retains_pair) in cases {
        let parts =
            AccessParts::new(GUEST_BASE + *residue as u64, *bytes, *descriptor).collect::<Vec<_>>();
        assert_eq!(parts.iter().map(|p| p.bytes).collect::<Vec<_>>(), *widths);
        assert!(
            parts
                .iter()
                .all(|p| (p.flags & flags::PAIR != 0) == *retains_pair)
        );
        assert!(
            parts
                .iter()
                .all(|p| (p.address as usize & 15) + p.bytes <= 16)
        );
    }
    for (bytes, descriptor) in [
        (16, flags::ASIMD),
        (16, flags::ASIMD | flags::PAIR),
        (32, flags::ASIMD | flags::PAIR),
        (16, flags::PAIR),
    ] {
        for residue in [1, 3, 5, 7, 9, 11, 13, 15] {
            let parts =
                AccessParts::new(GUEST_BASE + residue, bytes, descriptor).collect::<Vec<_>>();
            assert_eq!(parts.len(), bytes);
            assert!(parts.iter().all(|p| p.bytes == 1 && p.flags == descriptor));
        }
    }
}

#[test]
fn aligned_asimd_first_split_preserves_store_prefix_while_sve_lse2_combines() {
    for descriptor in [
        flags::ASIMD,
        flags::ASIMD | flags::PAIR,
        flags::SVE_PREDICATED,
        flags::PAIR,
    ] {
        let physical = backing();
        let readonly = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let domain = domain(vec![
            view(&physical, 0, 8, RIGHTS),
            view(&physical, 8, 24, readonly),
        ]);
        let mut thread = domain.thread(Policy::default());
        let mut data = [0x57; 16];
        let outcome = invoke(
            &mut thread,
            GUEST_BASE,
            &mut data,
            flags::WRITE | descriptor,
        );
        let prefix = if descriptor & flags::ASIMD != 0 { 8 } else { 0 };
        assert_eq!(outcome.status, MemoryStatus::Permission as u32);
        assert_eq!(outcome.completed, prefix);
        assert_eq!(outcome.fault_address, GUEST_BASE + prefix);
        assert_eq!(outcome.fault_pc, TEST_PC);
        assert_eq!(
            &snapshot(&physical, 16)[..8],
            if prefix == 8 { &[0x57; 8] } else { &[0; 8] }
        );
        if prefix == 8 {
            assert_eq!(thread.policy.checked_flags, [flags::WRITE | descriptor]);
        }
    }
}

#[test]
fn pair_half_quantity_is_checked_before_any_byte_and_not_family_split() {
    for (address, width, prefix_boundary) in [(GUEST_BASE + 8, 16, 11), (GUEST_BASE + 12, 8, 14)] {
        let physical = backing();
        let readonly = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let domain = domain(vec![
            view(&physical, 0, prefix_boundary, RIGHTS),
            view(&physical, prefix_boundary, 32 - prefix_boundary, readonly),
        ]);
        let mut thread = domain.thread(Policy::default());
        let mut data = vec![0x38; width];
        let result = invoke(&mut thread, address, &mut data, flags::WRITE | flags::PAIR);
        assert_eq!(result.status, MemoryStatus::Permission as u32);
        assert_eq!(result.completed, 0);
        assert_eq!(result.fault_address, address);
        assert!(snapshot(&physical, 32).iter().all(|b| *b == 0));
    }
}

#[test]
fn every_wide_asimd_residue_executes_on_declared_baseline_without_wide_host_caps() {
    for bytes in [16, 32] {
        for residue in 0..16 {
            let physical = backing();
            let domain = MemoryDomain::new(
                MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
                vec![(view(&physical, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
                TargetCpu::Baseline,
            )
            .unwrap();
            let mut thread = domain.thread(Policy::default());
            let descriptor = flags::ASIMD | if bytes == 32 { flags::PAIR } else { 0 };
            let address = GUEST_BASE + 16 + residue as u64;
            let mut expected = (0..bytes).map(|i| (i + 1) as u8).collect::<Vec<_>>();
            let written = invoke(
                &mut thread,
                address,
                &mut expected,
                descriptor | flags::WRITE,
            );
            assert_eq!(written.status, MemoryStatus::Success as u32);
            assert_eq!(written.completed, bytes as u64);
            let mut actual = vec![0xa5; bytes];
            assert_eq!(
                invoke(&mut thread, address, &mut actual, descriptor).status,
                MemoryStatus::Success as u32
            );
            assert_eq!(actual, expected);
            let mut full = vec![0; STORAGE_BYTES];
            full[16 + residue..16 + residue + bytes].copy_from_slice(&expected);
            assert_eq!(snapshot(&physical, STORAGE_BYTES), full);
        }
    }
}

#[test]
fn asimd32_prefix_and_descriptor_clear_do_not_touch_later_reservation_granules() {
    let physical = backing();
    let readonly = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let domain = MemoryDomain::new(
        system.clone(),
        vec![
            (view(&physical, 0, 8, RIGHTS), ATTRIBUTES),
            (view(&physical, 8, STORAGE_BYTES - 8, readonly), ATTRIBUTES),
        ],
        TargetCpu::Baseline,
    )
    .unwrap();
    let mut writer = domain.thread(Policy::default());
    let mut touched = domain.thread(Policy::default());
    let mut later = domain.thread(Policy::default());
    let first = reservation_access(&domain, 0);
    let future = monitor::Access::new(
        physical.clone(),
        domain.registered_views()[1].monitor.clone(),
        16,
        1,
        monitor::Shape::Scalar,
    )
    .unwrap();
    system
        .reservations
        .load(&mut touched.reservation, &first, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    system
        .reservations
        .load(
            &mut later.reservation,
            &future,
            || Ok::<_, MemoryStatus>(()),
        )
        .unwrap();
    let mut data = [0x75; 32];
    let result = invoke(
        &mut writer,
        GUEST_BASE,
        &mut data,
        flags::ASIMD | flags::PAIR | flags::WRITE,
    );
    assert_eq!(result.status, MemoryStatus::Permission as u32);
    assert_eq!(result.completed, 8);
    assert_eq!(result.fault_address, GUEST_BASE + 8);
    assert_eq!(writer.policy.checked_flags, [flags::ASIMD | flags::WRITE]);
    assert_eq!(
        system
            .reservations
            .store(&mut touched.reservation, &first, || Ok::<_, MemoryStatus>(
                ()
            ))
            .unwrap(),
        monitor::ConditionalWrite::Failed
    );
    assert_eq!(
        system
            .reservations
            .store(
                &mut later.reservation,
                &future,
                || Ok::<_, MemoryStatus>(())
            )
            .unwrap(),
        monitor::ConditionalWrite::Stored(())
    );
    assert!(
        snapshot(&physical, STORAGE_BYTES)[8..]
            .iter()
            .all(|b| *b == 0)
    );
}

#[test]
fn small_combined_pair_read_still_requires_atomic16_when_it_crosses_host8() {
    let physical = backing();
    let domain = MemoryDomain::new(
        MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
        vec![(view(&physical, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
        TargetCpu::Baseline,
    )
    .unwrap();
    let mut thread = domain.thread(Policy::default());
    let mut data = [0xa5; 8];
    let result = invoke(&mut thread, GUEST_BASE + 4, &mut data, flags::PAIR);
    assert_eq!(result.status, MemoryStatus::Unsupported as u32);
    assert_eq!(result.completed, 0);
    assert_eq!(data, [0xa5; 8]);
}
