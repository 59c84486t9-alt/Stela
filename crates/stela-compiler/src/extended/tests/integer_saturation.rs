use super::*;
use crate::aarch64::sve::integer_saturation;

#[test]
fn integer_saturation_maps_all_forms_with_exact_body_boundaries() {
    const CANONICAL_WORDS: [u32; 39] = [
        0x4500_f800, // saba_z_zzz_
        0x4540_c000, // sabalb_z_zzz_
        0x4540_c400, // sabalt_z_zzz_
        0x040c_0000, // sabd_z_p_zz_
        0x4540_3000, // sabdlb_z_zz_
        0x4540_3400, // sabdlt_z_zz_
        0x4410_8000, // shadd_z_p_zz_
        0x4412_8000, // shsub_z_p_zz_
        0x4416_8000, // shsubr_z_p_zz_
        0x4408_a000, // sqabs_z_p_z_m
        0x4418_8000, // sqadd_z_p_zz_
        0x2524_c000, // sqadd_z_zi_
        0x0420_1000, // sqadd_z_zz_
        0x4501_d800, // sqcadd_z_zz_
        0x4409_a000, // sqneg_z_p_z_m
        0x441a_8000, // sqsub_z_p_zz_
        0x2526_c000, // sqsub_z_zi_
        0x0420_1800, // sqsub_z_zz_
        0x441e_8000, // sqsubr_z_p_zz_
        0x4414_8000, // srhadd_z_p_zz_
        0x441c_8000, // suqadd_z_p_zz_
        0x4500_fc00, // uaba_z_zzz_
        0x4540_c800, // uabalb_z_zzz_
        0x4540_cc00, // uabalt_z_zzz_
        0x040d_0000, // uabd_z_p_zz_
        0x4540_3800, // uabdlb_z_zz_
        0x4540_3c00, // uabdlt_z_zz_
        0x4411_8000, // uhadd_z_p_zz_
        0x4413_8000, // uhsub_z_p_zz_
        0x4417_8000, // uhsubr_z_p_zz_
        0x4419_8000, // uqadd_z_p_zz_
        0x2525_c000, // uqadd_z_zi_
        0x0420_1400, // uqadd_z_zz_
        0x441b_8000, // uqsub_z_p_zz_
        0x2527_c000, // uqsub_z_zi_
        0x0420_1c00, // uqsub_z_zz_
        0x441f_8000, // uqsubr_z_p_zz_
        0x4415_8000, // urhadd_z_p_zz_
        0x441d_8000, // usqadd_z_p_zz_
    ];
    const REGISTER_MASK: u32 = 31;
    const SOURCE_SHIFT: u32 = 5;
    const SOURCE_REGISTER: u32 = 5;
    for canonical in CANONICAL_WORDS {
        for register in [0, SOURCE_REGISTER, REGISTER_MASK] {
            let word = (canonical & !(REGISTER_MASK | (REGISTER_MASK << SOURCE_SHIFT)))
                | register
                | (SOURCE_REGISTER << SOURCE_SHIFT);
            let operand = integer_saturation::decode(word).unwrap().unwrap();
            assert_eq!(
                crate::aarch64::sve::decode(word),
                Some(Ok(crate::aarch64::sve::Operand::IntegerSaturation(operand)))
            );
            for bytes in [16, 32, 64, 128, 256] {
                for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                    let native = compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, true),
                        target,
                    )
                    .unwrap();
                    let mut expected = Vec::new();
                    x86_64::sve::integer_saturation::emit(
                        &mut expected,
                        operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );
                    assert_eq!(
                        native.source_map[0],
                        (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES)
                    );
                    assert_eq!(
                        native.source_map[1],
                        (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                        expected
                    );
                    assert_eq!(native.x86_64_code[native.source_map[1].1..], [RET]);
                }
            }
        }
    }
}

#[test]
fn integer_saturation_preflight_rejects_reserved_mode_and_prefix_inputs() {
    const SQADD_Z0_Z1_Z2: u32 = 0x0422_1020;
    const SQADD_RESERVED_BYTE_SHIFT8: u32 = 0x2524_e000;
    const SABDLB_RESERVED_BYTE: u32 = 0x4500_3000;
    const MOVPRFX_PREDICATED_Z0_Z1: u32 = 0x0410_2020;
    for word in [SQADD_RESERVED_BYTE_SHIFT8, SABDLB_RESERVED_BYTE] {
        assert!(
            compile_for_profile(
                &words(&[NOP, word, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("reserved streaming integer saturation")
        );
    }
    for bytes in [16, 32, 64, 128, 256] {
        assert!(
            compile_for_profile(
                &words(&[SQADD_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(bytes, false),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("streaming mode required")
        );
    }
    for prefix in [MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1] {
        assert!(
            compile_for_profile(
                &words(&[prefix, SQADD_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
    }
    assert!(crate::compile(&words(&[SQADD_Z0_Z1_Z2, RET_X30]), GuestAddress(0)).is_err());
}
