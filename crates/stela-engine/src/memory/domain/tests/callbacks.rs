use super::*;

#[test]
fn unqualified_policy_refuses_both_checked_and_disabled_cpa_specializations_before_entry() {
    use stela_compiler::context::memory::address::{
        AccessEl, AddressAddChecks, AddressCheckRequirements, IncrementChoice,
    };
    let domain = domain(Vec::new());
    let mut thread = domain.thread(Policy::default());
    assert!(thread.prepare(MemoryRequirements::default()).is_ok());
    for access_el in [AccessEl::El0, AccessEl::El1] {
        for checks in [AddressAddChecks::Disabled, AddressAddChecks::Enabled] {
            let required = MemoryRequirements {
                required_address_checks: AddressCheckRequirements::for_access(access_el, checks)
                    .with_increment_choice(IncrementChoice::Unchecked),
                ..Default::default()
            };
            assert_eq!(
                thread.prepare(required).err(),
                Some(MemoryStatus::Unsupported)
            );
            assert!(thread.policy.checked.is_empty());
        }
    }
}

#[test]
fn access_parts_match_all_sca_residues_and_architectural_widths() {
    for residue in 0..SCA_BYTES {
        for bytes in [1, 2, 4, 8, SCA_BYTES] {
            let actual: Vec<_> =
                AccessParts::new(GUEST_BASE + residue as u64, bytes, flags::SVE_PREDICATED)
                    .collect();
            let expected_widths = if residue + bytes <= SCA_BYTES {
                vec![bytes]
            } else if bytes == SCA_BYTES && residue == HALF_SCA_BYTES {
                vec![HALF_SCA_BYTES; 2]
            } else {
                vec![1; bytes]
            };
            assert_eq!(
                actual.iter().map(|part| part.bytes).collect::<Vec<_>>(),
                expected_widths,
                "residue={residue} width={bytes}"
            );
            let mut offset = 0;
            for part in actual {
                assert_eq!(part.offset, offset);
                assert_eq!(part.address, GUEST_BASE + residue as u64 + offset as u64);
                assert!((part.address as usize & (SCA_BYTES - 1)) + part.bytes <= SCA_BYTES);
                offset += part.bytes;
            }
            assert_eq!(offset, bytes);
        }
    }
}

#[test]
fn synchronous_callbacks_write_read_and_preserve_neighbors() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut thread = domain.thread(Policy::default());
    for bytes in [1, 2, 4, 8, SCA_BYTES] {
        if bytes == SCA_BYTES && !TargetCpu::detect().supports(TargetCpu::Cx16) {
            continue;
        }
        let mut expected = (1..=bytes).map(|byte| byte as u8).collect::<Vec<_>>();
        let written = invoke(
            &mut thread,
            GUEST_BASE + SCA_BYTES as u64,
            &mut expected,
            flags::WRITE,
        );
        assert_eq!(written.status, MemoryStatus::Success as u32);
        assert_eq!(written.completed, bytes as u64);
        let mut actual = vec![0xa5; bytes];
        let read = invoke(&mut thread, GUEST_BASE + SCA_BYTES as u64, &mut actual, 0);
        if bytes == SCA_BYTES && !TargetCpu::detect().supports(TargetCpu::AtomicLoad16) {
            assert_eq!(read.status, MemoryStatus::Unsupported as u32);
            assert_eq!(actual, vec![0xa5; bytes]);
            continue;
        }
        assert_eq!(read.status, MemoryStatus::Success as u32);
        assert_eq!(actual, expected);
        assert!(snapshot(&backing, SCA_BYTES).iter().all(|byte| *byte == 0));
    }
}

#[test]
fn actual_native_callbacks_cover_every_admitted_residue_and_width() {
    let target = TargetCpu::detect();
    let mut admitted = 0;
    let mut capability_declined = 0;
    for residue in 0..SCA_BYTES {
        for bytes in [1, 2, 4, 8, SCA_BYTES] {
            let address = GUEST_BASE + SCA_BYTES as u64 + residue as u64;
            let physical = backing();
            let pointer = physical
                .host_pointer(SCA_BYTES + residue, bytes, AccessKind::Read)
                .unwrap();
            let supported = AccessParts::new(address, bytes, 0).all(|part| {
                (part.bytes != SCA_BYTES || target.supports(TargetCpu::Cx16))
                    && access::read_footprint(
                        pointer.as_ptr() as usize + part.offset,
                        part.bytes,
                        target,
                    )
                    .is_ok()
            });
            if !supported {
                capability_declined += 1;
                continue;
            }
            admitted += 1;
            let domain = domain(vec![view(&physical, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Policy::default());
            let mut expected = (1..=bytes).map(|byte| byte as u8).collect::<Vec<_>>();
            let written = invoke(&mut thread, address, &mut expected, flags::WRITE);
            assert_eq!(
                written.status,
                MemoryStatus::Success as u32,
                "residue={residue} width={bytes}"
            );
            assert_eq!(written.completed, bytes as u64);
            let mut actual = vec![0xa5; bytes];
            assert_eq!(
                invoke(&mut thread, address, &mut actual, 0).status,
                MemoryStatus::Success as u32
            );
            assert_eq!(actual, expected);
            let mut full_expected = vec![0; STORAGE_BYTES];
            full_expected[SCA_BYTES + residue..SCA_BYTES + residue + bytes]
                .copy_from_slice(&expected);
            assert_eq!(snapshot(&physical, STORAGE_BYTES), full_expected);
        }
    }
    assert_eq!(admitted + capability_declined, SCA_BYTES * 5);
    eprintln!(
        "native callback matrix: {admitted} admitted, {capability_declined} capability-declined"
    );
}

#[test]
fn wide_read_and_write_host_capabilities_are_independent() {
    for target in [
        TargetCpu::Baseline,
        TargetCpu::Cx16,
        TargetCpu::AtomicLoad16,
    ] {
        if !target.supported() {
            continue;
        }
        let physical = backing();
        let domain = MemoryDomain::new(
            MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
            vec![(view(&physical, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
            target,
        )
        .unwrap();
        let mut thread = domain.thread(Policy::default());
        let mut expected = [0x5a; SCA_BYTES];
        let written = invoke(&mut thread, GUEST_BASE, &mut expected, flags::WRITE);
        let expected_write = if target.supports(TargetCpu::Cx16) {
            MemoryStatus::Success
        } else {
            MemoryStatus::Unsupported
        };
        assert_eq!(written.status, expected_write as u32);
        let mut actual = [0xa5; SCA_BYTES];
        let read = invoke(&mut thread, GUEST_BASE, &mut actual, 0);
        if target.supports(TargetCpu::AtomicLoad16) {
            assert_eq!(read.status, MemoryStatus::Success as u32);
            assert_eq!(actual, [0; SCA_BYTES]);
        } else {
            assert_eq!(read.status, MemoryStatus::Unsupported as u32);
            assert_eq!(actual, [0xa5; SCA_BYTES]);
        }
    }
}

#[test]
fn adjacent_views_resolve_one_atomic_quantity_before_writing() {
    let backing = backing();
    let readonly = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let domain = domain(vec![
        view(&backing, 0, 4, RIGHTS),
        view(&backing, 4, 12, readonly),
    ]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [0x5a; 8];
    let denied = invoke(&mut thread, GUEST_BASE, &mut bytes, flags::WRITE);
    assert_eq!(denied.status, MemoryStatus::Permission as u32);
    assert_eq!(denied.completed, 0);
    assert_eq!(snapshot(&backing, 8), [0; 8]);
    assert!(thread.policy.checked.is_empty());
    let mut read = [0xff; 8];
    assert_eq!(
        invoke(&mut thread, GUEST_BASE, &mut read, 0).status,
        MemoryStatus::Success as u32
    );
    assert_eq!(read, [0; 8]);
}

#[test]
fn contiguous_alias_views_share_one_native_atomic_quantity() {
    let backing = backing();
    let domain = domain(vec![
        view(&backing, 0, 4, RIGHTS),
        view(&backing, 4, 12, RIGHTS),
    ]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(
        invoke(&mut thread, GUEST_BASE, &mut bytes, flags::WRITE).status,
        MemoryStatus::Success as u32
    );
    assert_eq!(thread.policy.checked, [(GUEST_BASE, 8)]);
    assert_eq!(snapshot(&backing, 8), bytes);
}

#[test]
fn later_byte_permission_failure_preserves_completed_store_prefix() {
    let backing = backing();
    let readonly = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let domain = domain(vec![
        view(&backing, 0, SCA_BYTES, RIGHTS),
        view(&backing, SCA_BYTES, SCA_BYTES, readonly),
    ]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [0x36, 0x79];
    let result = invoke(
        &mut thread,
        GUEST_BASE + (SCA_BYTES - 1) as u64,
        &mut bytes,
        flags::WRITE,
    );
    assert_eq!(result.status, MemoryStatus::Permission as u32);
    assert_eq!(result.fault_kind, result.status);
    assert_eq!(result.fault_address, GUEST_BASE + SCA_BYTES as u64);
    assert_eq!(result.fault_pc, TEST_PC);
    assert_eq!(result.completed, 1);
    let actual = snapshot(&backing, SCA_BYTES + 1);
    assert_eq!(actual[SCA_BYTES - 1], 0x36);
    assert_eq!(actual[SCA_BYTES], 0);
    assert_eq!(
        thread.policy.checked,
        [(GUEST_BASE + (SCA_BYTES - 1) as u64, 1)]
    );
}

#[test]
fn denied_later_read_only_changes_private_staging_prefix() {
    let backing = backing();
    let noaccess = AccessPermissions {
        readable: false,
        writable: false,
        executable: false,
    };
    let domain = domain(vec![
        view(&backing, 0, SCA_BYTES, RIGHTS),
        view(&backing, SCA_BYTES, SCA_BYTES, noaccess),
    ]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [0xa5; 2];
    let result = invoke(
        &mut thread,
        GUEST_BASE + (SCA_BYTES - 1) as u64,
        &mut bytes,
        0,
    );
    assert_eq!(result.status, MemoryStatus::Permission as u32);
    assert_eq!(result.completed, 1);
    assert_eq!(bytes, [0, 0xa5]);
}

#[test]
fn data_and_tag_entries_refuse_unknown_profile_bits() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let controls = crate::memory::policy::MemoryControls::new(
        crate::memory::policy::LowerAddressProfile::new(48, false).unwrap(),
        false,
        false,
        false,
        crate::memory::policy::TagCheckFaultMode::Ignore,
        false,
    );
    let mut thread = domain.thread(controls);
    let ordinary = MemoryRequirements {
        required_profile: profile_requirements::NATIVE_ACCESS,
        ..Default::default()
    };
    assert!(thread.prepare(ordinary).is_ok());
    assert!(thread.prepare_tag(ordinary, false).is_ok());
    let before = snapshot(&backing, STORAGE_BYTES);
    for unknown in (3..8).map(|bit| 1 << bit) {
        assert_eq!(unknown & profile_requirements::KNOWN, 0);
        for generic in [0, profile_requirements::NATIVE_ACCESS] {
            let requirements = MemoryRequirements {
                required_profile: unknown | generic,
                ..Default::default()
            };
            assert_eq!(
                thread.prepare(requirements).err(),
                Some(MemoryStatus::InvalidRequest)
            );
            assert_eq!(
                thread.prepare_tag(requirements, false).err(),
                Some(MemoryStatus::InvalidRequest)
            );
        }
    }
    assert_eq!(snapshot(&backing, STORAGE_BYTES), before);
    assert!(thread.prepare(ordinary).is_ok());
    assert!(thread.prepare_tag(ordinary, false).is_ok());
}
