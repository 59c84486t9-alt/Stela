use super::*;

#[test]
fn ordinary_payload_and_maps_preserve_original_bytes() {
    let source = words(&[NOP, 0xd280_00e0, RET_X30]);
    let old = crate::compile(&source, GuestAddress(0x1000)).unwrap();
    let new = compile_for_profile(
        &source,
        GuestAddress(0x1000),
        profile(32, true),
        TargetCpu::Baseline,
    )
    .unwrap();
    assert_eq!(&new.x86_64_code[CONTEXT_WRAPPER_BYTES..], old.x86_64_code);
    assert_eq!(
        new.source_map,
        old.source_map
            .iter()
            .map(|(pc, offset)| (*pc, offset + CONTEXT_WRAPPER_BYTES))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        context_wrapper(),
        [
            0x41, 0x57, 0x49, 0x89, 0xf7, 0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3
        ]
    );
}

#[test]
fn variable_length_modes_and_prefix_boundary_are_explicit() {
    for bytes in [16, 32, 64, 128, 256] {
        let source = words(&[AND_Z0_Z1_Z2, RDSVL_X0_ONE, RET_X30]);
        assert!(
            compile_for_profile(
                &source,
                GuestAddress(0),
                profile(bytes, true),
                TargetCpu::Baseline
            )
            .is_ok()
        );
        assert!(
            compile_for_profile(
                &source,
                GuestAddress(0),
                profile(bytes, false),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("streaming mode required")
        );
        assert!(
            compile_for_profile(
                &words(&[RDSVL_X0_ONE, RET_X30]),
                GuestAddress(0),
                profile(bytes, false),
                TargetCpu::Baseline
            )
            .is_ok()
        );
    }
    assert!(
        compile_for_profile(
            &words(&[MOVPRFX_Z0_Z1, AND_Z0_Z1_Z2, RET_X30]),
            GuestAddress(0),
            profile(32, true),
            TargetCpu::Baseline
        )
        .unwrap_err()
        .0
        .contains("MOVPRFX pair validation")
    );
    for word in [0xf940_0020, 0x4e22_8420, 0x1e22_2820] {
        assert!(
            compile_for_profile(
                &words(&[word, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline
            )
            .is_err()
        );
    }
}
#[test]
fn branches_resolve_across_scalable_instruction_bodies() {
    const BRANCH_PLUS_EIGHT: u32 = 0x1400_0002;
    let native = compile_for_profile(
        &words(&[BRANCH_PLUS_EIGHT, AND_Z0_Z1_Z2, RET_X30]),
        GuestAddress(0),
        profile(32, true),
        TargetCpu::Baseline,
    )
    .unwrap();
    let branch = native.source_map[0].1;
    assert_eq!(native.x86_64_code[branch], 0xe9);
    let displacement = i32::from_le_bytes(
        native.x86_64_code[branch + 1..branch + 5]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        (branch + 5) as i64 + i64::from(displacement),
        native.source_map[2].1 as i64
    );
}
