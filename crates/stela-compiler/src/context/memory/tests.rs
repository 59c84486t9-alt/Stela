use super::*;
use core::mem::offset_of;

#[test]
fn named_stack_fault_preserves_old_codes_and_merge_rejects_opposite_sp_profiles() {
    for (code, status) in [
        MemoryStatus::Success,
        MemoryStatus::Translation,
        MemoryStatus::Permission,
        MemoryStatus::Alignment,
        MemoryStatus::TagCheck,
        MemoryStatus::Unsupported,
        MemoryStatus::InvalidRequest,
        MemoryStatus::Domain,
        MemoryStatus::StackAlignment,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(status as u32, code as u32);
        assert_eq!(MemoryStatus::from_code(code as u32), Some(status));
    }
    assert_eq!(MemoryStatus::from_code(9), None);
    for first in [
        SpAlignmentRequirement::Any,
        SpAlignmentRequirement::Enabled,
        SpAlignmentRequirement::Disabled,
    ] {
        for second in [
            SpAlignmentRequirement::Any,
            SpAlignmentRequirement::Enabled,
            SpAlignmentRequirement::Disabled,
        ] {
            let a = MemoryRequirements {
                required_flags: flags::WRITE,
                required_sp_alignment: first,
                ..Default::default()
            };
            let b = MemoryRequirements {
                required_host_caps: host_caps::CX16,
                required_profile: profile_requirements::NATIVE_ACCESS,
                required_sp_alignment: second,
                ..Default::default()
            };
            let merged = a.merge(b);
            let conflict = first != SpAlignmentRequirement::Any
                && second != SpAlignmentRequirement::Any
                && first != second;
            assert_eq!(merged.is_none(), conflict);
            if let Some(merged) = merged {
                assert_eq!(merged.required_flags, flags::WRITE);
                assert_eq!(merged.required_host_caps, host_caps::CX16);
                assert_eq!(merged.required_profile, profile_requirements::NATIVE_ACCESS);
                assert_eq!(
                    merged.required_sp_alignment,
                    if first == SpAlignmentRequirement::Any {
                        second
                    } else {
                        first
                    }
                );
            }
        }
    }
}

#[test]
fn ordinary_shape_matrix_never_admits_atomic_ordered_or_invalid_pair_widths() {
    let scalar: &[u32] = &[1, 2, 4, 8, 16];
    let pair: &[u32] = &[8, 16];
    let asimd_pair: &[u32] = &[8, 16, 32];
    let cases: &[(u32, &[u32])] = &[
        (0, scalar),
        (flags::SME, scalar),
        (flags::SVE_PREDICATED, scalar),
        (flags::SME | flags::SVE_PREDICATED, scalar),
        (flags::ASIMD, scalar),
        (flags::PAIR, pair),
        (flags::ASIMD | flags::PAIR, asimd_pair),
        (flags::PAIR | flags::SME, &[]),
        (flags::PAIR | flags::SVE_PREDICATED, &[]),
        (flags::ASIMD | flags::SME, &[]),
        (flags::ASIMD | flags::SVE_PREDICATED, &[]),
        (flags::ATOMIC, &[]),
        (flags::ORDERED, &[]),
        (flags::PAIR | flags::ATOMIC, &[]),
        (flags::ASIMD | flags::PAIR | flags::ORDERED, &[]),
        (1 << 31, &[]),
    ];
    for (descriptor, widths) in cases {
        for qualifiers in 0..8 {
            let flags = descriptor
                | if qualifiers & 1 != 0 { flags::WRITE } else { 0 }
                | if qualifiers & 2 != 0 {
                    flags::TAG_CHECKED
                } else {
                    0
                }
                | if qualifiers & 4 != 0 {
                    flags::NON_TEMPORAL
                } else {
                    0
                };
            for bytes in [0, 1, 2, 4, 8, 16, 32, 64] {
                let request = MemoryRequest {
                    address: 0,
                    data: core::ptr::null_mut(),
                    bytes,
                    flags,
                    pc: 0,
                };
                assert_eq!(
                    request.has_supported_ordinary_shape(),
                    widths.contains(&bytes),
                    "flags={flags:#x} bytes={bytes}"
                );
            }
        }
    }
    assert_eq!(flags::PAIR, 1 << 6);
    assert_eq!(flags::ATOMIC, 1 << 7);
    assert_eq!(flags::ORDERED, 1 << 8);
    assert_eq!(flags::ORDINARY_KNOWN & (flags::ATOMIC | flags::ORDERED), 0);
}

#[test]
fn request_and_callback_offsets_match_native_contract() {
    assert_eq!(size_of::<MemoryRequest>(), MEMORY_REQUEST_BYTES);
    assert_eq!(
        offset_of!(MemoryRequest, address),
        MEMORY_REQUEST_ADDRESS_OFFSET as usize
    );
    assert_eq!(
        offset_of!(MemoryRequest, data),
        MEMORY_REQUEST_DATA_OFFSET as usize
    );
    assert_eq!(
        offset_of!(MemoryRequest, bytes),
        MEMORY_REQUEST_LENGTH_OFFSET as usize
    );
    assert_eq!(
        offset_of!(MemoryRequest, flags),
        MEMORY_REQUEST_FLAGS_OFFSET as usize
    );
    assert_eq!(
        offset_of!(MemoryRequest, pc),
        MEMORY_REQUEST_PC_OFFSET as usize
    );
    assert_eq!(
        size_of::<MemoryContextView>(),
        MEMORY_CONTEXT_BYTES as usize
    );
    assert_eq!(
        offset_of!(MemoryContextView, callback),
        MEMORY_CALLBACK_OFFSET as usize
    );
}
