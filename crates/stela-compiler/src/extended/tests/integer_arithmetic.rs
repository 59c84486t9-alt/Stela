use super::*;
use crate::aarch64::sve::integer_arithmetic;

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
                    let native = compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, true),
                        target,
                    )
                    .unwrap();
                    let mut expected = Vec::new();
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
            compile_for_profile(
                &words(&[NOP, word, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("reserved streaming integer arithmetic")
        );
    }
    for bytes in [16, 32, 64, 128, 256] {
        assert!(
            compile_for_profile(
                &words(&[ADD_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(bytes, false),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("streaming mode required")
        );
    }
    assert!(
        compile_for_profile(
            &words(&[MOVPRFX_Z0_Z1, ADD_Z0_Z1_Z2, RET_X30]),
            GuestAddress(0),
            profile(32, true),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .0
        .contains("MOVPRFX pair validation")
    );
    assert!(crate::compile(&words(&[ADD_Z0_Z1_Z2, RET_X30]), GuestAddress(0)).is_err());
}
