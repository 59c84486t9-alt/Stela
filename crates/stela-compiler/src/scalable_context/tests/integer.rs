use super::*;
use crate::aarch64::sve::integer_arithmetic;
use crate::aarch64::sve::integer_saturation;

#[test]
fn integer_comparison_preflight_rejects_non_streaming_reserved_and_prefix_inputs() {
    const CMPEQ_BYTE: u32 = 0x2400_2020;
    const CMPEQ_WIDE_RESERVED_DOUBLEWORD: u32 = 0x24c0_2020;
    const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
    for (input, streaming, reason) in [
        (vec![CMPEQ_BYTE, RET_X30], false, "streaming mode required"),
        (
            vec![CMPEQ_WIDE_RESERVED_DOUBLEWORD, RET_X30],
            true,
            "reserved streaming integer comparison",
        ),
        (vec![MOVPRFX_Z0_Z1, CMPEQ_BYTE, RET_X30], true, "MOVPRFX"),
    ] {
        let error = crate::testing::context_leaf(
            &words(&input),
            GuestAddress(0),
            profile(32, streaming),
            TargetCpu::Baseline,
        )
        .unwrap_err();
        assert!(error.to_string().contains(reason), "{error:?}");
    }
}

#[test]
fn integer_comparison_accepts_declared_sme_without_sme2() {
    const CMPEQ_BYTE: u32 = 0x2400_2020;
    let length = VectorLength::from_bytes(32).unwrap();
    let mode = ScalableMode::new(true, true);
    let declared = ScalableProfile::new_with_features(
        length,
        mode,
        ScalableFeatures::of(ScalableFeature::Sme),
        ScalableControls::new(length, false),
    )
    .unwrap();
    let source = words(&[CMPEQ_BYTE, RET_X30]);
    let fixed = crate::testing::context_leaf(
        &source,
        GuestAddress(0),
        ScalableProfile::new(length, mode),
        TargetCpu::Baseline,
    )
    .unwrap();
    let explicit =
        crate::testing::context_leaf(&source, GuestAddress(0), declared, TargetCpu::Baseline)
            .unwrap();
    assert_eq!(fixed.x86_64_code, explicit.x86_64_code);
    assert_eq!(fixed.source_map, explicit.source_map);
}

#[test]
fn integer_arithmetic_maps_all_families_with_exact_body_boundaries() {
    const CANONICAL_WORDS: [u32; 48] = [
        0x0416_a000, // abs_z_p_z_m
        0x4500_d000, // adclb_z_zzz_
        0x4500_d400, // adclt_z_zzz_
        0x0400_0000, // add_z_p_zz_
        0x2520_c000, // add_z_zi_
        0x0420_0000, // add_z_zz_
        0x4500_d800, // cadd_z_zz_
        0x0417_a000, // neg_z_p_z_m
        0x4540_0000, // saddlb_z_zz_
        0x4540_8000, // saddlbt_z_zz_
        0x4540_0400, // saddlt_z_zz_
        0x4540_4000, // saddwb_z_zz_
        0x4540_4400, // saddwt_z_zz_
        0x4580_d000, // sbclb_z_zzz_
        0x4580_d400, // sbclt_z_zzz_
        0x4400_c000, // sclamp_z_zz_
        0x0494_0000, // sdiv_z_p_zz_
        0x0496_0000, // sdivr_z_p_zz_
        0x0408_0000, // smax_z_p_zz_
        0x2528_c000, // smax_z_zi_
        0x040a_0000, // smin_z_p_zz_
        0x252a_c000, // smin_z_zi_
        0x4540_1000, // ssublb_z_zz_
        0x4540_8800, // ssublbt_z_zz_
        0x4540_1400, // ssublt_z_zz_
        0x4540_8c00, // ssubltb_z_zz_
        0x4540_5000, // ssubwb_z_zz_
        0x4540_5400, // ssubwt_z_zz_
        0x0401_0000, // sub_z_p_zz_
        0x2521_c000, // sub_z_zi_
        0x0420_0400, // sub_z_zz_
        0x0403_0000, // subr_z_p_zz_
        0x2523_c000, // subr_z_zi_
        0x4540_0800, // uaddlb_z_zz_
        0x4540_0c00, // uaddlt_z_zz_
        0x4540_4800, // uaddwb_z_zz_
        0x4540_4c00, // uaddwt_z_zz_
        0x4400_c400, // uclamp_z_zz_
        0x0495_0000, // udiv_z_p_zz_
        0x0497_0000, // udivr_z_p_zz_
        0x0409_0000, // umax_z_p_zz_
        0x2529_c000, // umax_z_zi_
        0x040b_0000, // umin_z_p_zz_
        0x252b_c000, // umin_z_zi_
        0x4540_1800, // usublb_z_zz_
        0x4540_1c00, // usublt_z_zz_
        0x4540_5800, // usubwb_z_zz_
        0x4540_5c00, // usubwt_z_zz_
    ];
    const DESTINATION_MASK: u32 = 31;
    const SOURCE_MASK: u32 = 31 << 5;
    const SOURCE_REGISTER: u32 = 5;
    for canonical in CANONICAL_WORDS {
        // Distinct operands, destination/source alias, and ordinary Z31.
        for register in [0, SOURCE_REGISTER, 31] {
            let word =
                (canonical & !(DESTINATION_MASK | SOURCE_MASK)) | register | (SOURCE_REGISTER << 5);
            let operand = integer_arithmetic::decode(word).unwrap().unwrap();
            assert_eq!(
                crate::aarch64::sve::decode(word),
                Some(Ok(crate::aarch64::sve::Operand::IntegerArithmetic(operand)))
            );
            for bytes in [16, 32, 64, 128, 256] {
                for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                    let native = crate::testing::context_leaf(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, true),
                        target,
                    )
                    .unwrap();
                    let mut expected = Code::new();
                    x86_64::sve::integer_arithmetic::emit(
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
fn integer_arithmetic_preflight_rejects_mode_reserved_and_prefix_inputs() {
    const ADD_Z0_Z1_Z2: u32 = 0x0422_0020;
    const SDIV_RESERVED_BYTE: u32 = 0x0414_0000;
    const UDIV_RESERVED_HALFWORD: u32 = 0x0455_0000;
    const SADDLB_RESERVED_BYTE: u32 = 0x4500_0000;
    const ADD_RESERVED_BYTE_SHIFT8: u32 = 0x2520_e000;
    for word in [
        SDIV_RESERVED_BYTE,
        UDIV_RESERVED_HALFWORD,
        SADDLB_RESERVED_BYTE,
        ADD_RESERVED_BYTE_SHIFT8,
    ] {
        assert!(
            crate::testing::context_leaf(
                &words(&[NOP, word, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .to_string()
            .contains("reserved streaming integer arithmetic")
        );
    }
    for bytes in [16, 32, 64, 128, 256] {
        assert!(
            crate::testing::context_leaf(
                &words(&[ADD_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(bytes, false),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .to_string()
            .contains("streaming mode required")
        );
    }
    assert!(
        crate::testing::context_leaf(
            &words(&[MOVPRFX_Z0_Z1, ADD_Z0_Z1_Z2, RET_X30]),
            GuestAddress(0),
            profile(32, true),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .to_string()
        .contains("MOVPRFX pair validation")
    );
    assert!(crate::testing::leaf(&words(&[ADD_Z0_Z1_Z2, RET_X30]), GuestAddress(0)).is_err());
}

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
                    let native = crate::testing::context_leaf(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, true),
                        target,
                    )
                    .unwrap();
                    let mut expected = Code::new();
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
            crate::testing::context_leaf(
                &words(&[NOP, word, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .to_string()
            .contains("reserved streaming integer saturation")
        );
    }
    for bytes in [16, 32, 64, 128, 256] {
        assert!(
            crate::testing::context_leaf(
                &words(&[SQADD_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(bytes, false),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .to_string()
            .contains("streaming mode required")
        );
    }
    for prefix in [MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1] {
        assert!(
            crate::testing::context_leaf(
                &words(&[prefix, SQADD_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .to_string()
            .contains("MOVPRFX pair validation")
        );
    }
    assert!(crate::testing::leaf(&words(&[SQADD_Z0_Z1_Z2, RET_X30]), GuestAddress(0)).is_err());
}

#[test]
fn sign_operations_require_streaming_without_za() {
    const FABS_HALF: u32 = 0x045c_a020;
    const FNEG_DOUBLE: u32 = 0x04dd_bfff;
    const RESERVED_SIGN_SIZE: u32 = 0x041c_a020;
    for bytes in [16, 32, 64, 128, 256] {
        for svcr in 0..=3 {
            let profile = ScalableProfile::new(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::from_svcr(svcr).unwrap(),
            );
            let source = words(&[FABS_HALF, FNEG_DOUBLE, RET_X30]);
            let result = crate::testing::context_leaf(
                &source,
                GuestAddress(0),
                profile,
                TargetCpu::Baseline,
            );
            if profile.mode().streaming() {
                let native = result.unwrap();
                assert_eq!(
                    native.source_map[0],
                    (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                );
                assert_eq!(native.source_map[1].0, GuestAddress(4));
                assert!(native.source_map[1].1 > native.source_map[0].1);
            } else {
                assert!(matches!(
                    result.unwrap_err().kind,
                    crate::CompileErrorKind::StreamingModeRequired
                ));
            }
        }
    }
    assert!(crate::testing::leaf(&words(&[FABS_HALF, RET_X30]), GuestAddress(0)).is_err());
    assert!(
        crate::testing::context_leaf(
            &words(&[RESERVED_SIGN_SIZE, RET_X30]),
            GuestAddress(0),
            profile(16, true),
            TargetCpu::Baseline
        )
        .unwrap_err()
        .to_string()
        .contains("reserved streaming sign")
    );
}
