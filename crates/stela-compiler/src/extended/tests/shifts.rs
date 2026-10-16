use super::*;
use crate::aarch64::sve::shifts;
use crate::aarch64::sve::shifts_narrow;

fn declared_dit_zero_profile(bytes: usize) -> ScalableProfile {
    let length = VectorLength::from_bytes(bytes).unwrap();
    ScalableProfile::new_with_features(
        length,
        ScalableMode::new(true, false),
        ScalableFeatures::of(ScalableFeature::Sme),
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
    )
    .unwrap()
}

#[test]
fn integer_shifts_register_exact_bodies_and_source_maps() {
    const CANONICAL_WORDS: [u32; 43] = [
        0x040081e0, // ASR
        0x04188040, // ASR
        0x04108040, // ASR
        0x042f9020, // ASR
        0x04228020, // ASR
        0x040481e0, // ASRD
        0x04148040, // ASRR
        0x04038100, // LSL
        0x041b8040, // LSL
        0x04138040, // LSL
        0x04289c20, // LSL
        0x04228c20, // LSL
        0x04178040, // LSLR
        0x040181e0, // LSR
        0x04198040, // LSR
        0x04118040, // LSR
        0x042f9420, // LSR
        0x04228420, // LSR
        0x04158040, // LSRR
        0x4508f420, // SLI
        0x440a8040, // SQRSHL
        0x440e8040, // SQRSHLR
        0x04068100, // SQSHL
        0x44088040, // SQSHL
        0x440c8040, // SQSHLR
        0x040f8100, // SQSHLU
        0x450ff020, // SRI
        0x44028040, // SRSHL
        0x44068040, // SRSHLR
        0x040c81e0, // SRSHR
        0x450fe820, // SRSRA
        0x450fe020, // SSRA
        0x440b8040, // UQRSHL
        0x440f8040, // UQRSHLR
        0x04078100, // UQSHL
        0x44098040, // UQSHL
        0x440d8040, // UQSHLR
        0x44038040, // URSHL
        0x44078040, // URSHLR
        0x040d81e0, // URSHR
        0x450fec20, // URSRA
        0x450fe420, // USRA
        0x042f3440, // XAR
    ];
    for word in CANONICAL_WORDS {
        let operand = shifts::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::Shifts(operand)))
        );
        for bytes in [16, 32, 64, 128, 256] {
            for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                let native = compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0x1000),
                    declared_dit_zero_profile(bytes),
                    target,
                )
                .unwrap();
                let mut body = Vec::new();
                x86_64::sve::shifts::emit(
                    &mut body,
                    operand,
                    VectorLength::from_bytes(bytes).unwrap(),
                    target,
                );
                let return_offset = CONTEXT_WRAPPER_BYTES + body.len();
                assert_eq!(
                    native.source_map,
                    [
                        (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                        (GuestAddress(0x1004), return_offset)
                    ]
                );
                assert_eq!(
                    &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                    context_wrapper()
                );
                assert_eq!(
                    &native.x86_64_code[CONTEXT_WRAPPER_BYTES..return_offset],
                    body
                );
                assert_eq!(&native.x86_64_code[return_offset..], &[RET]);
            }
        }
        let length = VectorLength::from_bytes(16).unwrap();
        let base_sme = ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, false),
            ScalableFeatures::of(ScalableFeature::Sme),
            ScalableControls::new(length, false),
        )
        .unwrap();
        assert!(
            compile_for_profile(
                &words(&[word, RET_X30]),
                GuestAddress(0),
                base_sme,
                TargetCpu::Baseline
            )
            .is_ok()
        );
        for streaming in [false, true] {
            for za in [false, true] {
                let selected = ScalableProfile::new(
                    VectorLength::from_bytes(16).unwrap(),
                    ScalableMode::new(streaming, za),
                );
                let result = compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0),
                    selected,
                    TargetCpu::Baseline,
                );
                if streaming && x86_64::sve::shifts::requires_declared_dit_zero(operand, length) {
                    assert!(result.unwrap_err().0.contains("requires declared DIT=0"));
                } else if streaming {
                    assert!(result.is_ok());
                } else {
                    assert!(result.unwrap_err().0.contains("streaming mode required"));
                }
            }
        }
    }
}

#[test]
fn integer_shift_dit_policy_preserves_canonical_width_boundaries() {
    // Expected decisions come from the source-bound June per-form audit,
    // including forward/reverse rounding identity and byte packed exceptions.
    const AUDITED_WORDS: &[(u32, bool, bool)] = &[
        (0x0400_81e0, true, false),  // asr_z_p_zi_
        (0x0400_83e0, true, false),  // asr_z_p_zi_
        (0x0440_83e0, true, false),  // asr_z_p_zi_
        (0x04c0_83e0, true, false),  // asr_z_p_zi_
        (0x0418_8040, true, true),   // asr_z_p_zw_
        (0x0458_8040, true, true),   // asr_z_p_zw_
        (0x0498_8040, true, true),   // asr_z_p_zw_
        (0x0410_8040, true, true),   // asr_z_p_zz_
        (0x0450_8040, true, true),   // asr_z_p_zz_
        (0x0490_8040, true, true),   // asr_z_p_zz_
        (0x04d0_8040, true, true),   // asr_z_p_zz_
        (0x042f_9020, true, false),  // asr_z_zi_
        (0x043f_9020, true, false),  // asr_z_zi_
        (0x047f_9020, true, false),  // asr_z_zi_
        (0x04ff_9020, true, false),  // asr_z_zi_
        (0x0422_8020, true, true),   // asr_z_zw_
        (0x0462_8020, true, true),   // asr_z_zw_
        (0x04a2_8020, true, true),   // asr_z_zw_
        (0x0404_81e0, true, false),  // asrd_z_p_zi_
        (0x0404_83e0, true, false),  // asrd_z_p_zi_
        (0x0444_83e0, true, false),  // asrd_z_p_zi_
        (0x04c4_83e0, true, false),  // asrd_z_p_zi_
        (0x0414_8040, true, true),   // asrr_z_p_zz_
        (0x0454_8040, true, true),   // asrr_z_p_zz_
        (0x0494_8040, true, true),   // asrr_z_p_zz_
        (0x04d4_8040, true, true),   // asrr_z_p_zz_
        (0x0403_8100, true, false),  // lsl_z_p_zi_
        (0x0403_8200, true, false),  // lsl_z_p_zi_
        (0x0443_8000, true, false),  // lsl_z_p_zi_
        (0x0483_8000, true, false),  // lsl_z_p_zi_
        (0x041b_8040, true, true),   // lsl_z_p_zw_
        (0x045b_8040, true, true),   // lsl_z_p_zw_
        (0x049b_8040, true, true),   // lsl_z_p_zw_
        (0x0413_8040, true, false),  // lsl_z_p_zz_
        (0x0453_8040, true, true),   // lsl_z_p_zz_
        (0x0493_8040, true, true),   // lsl_z_p_zz_
        (0x04d3_8040, true, true),   // lsl_z_p_zz_
        (0x0428_9c20, true, false),  // lsl_z_zi_
        (0x0430_9c20, true, false),  // lsl_z_zi_
        (0x0460_9c20, true, false),  // lsl_z_zi_
        (0x04a0_9c20, true, false),  // lsl_z_zi_
        (0x0422_8c20, true, true),   // lsl_z_zw_
        (0x0462_8c20, true, true),   // lsl_z_zw_
        (0x04a2_8c20, true, true),   // lsl_z_zw_
        (0x0417_8040, true, false),  // lslr_z_p_zz_
        (0x0457_8040, true, true),   // lslr_z_p_zz_
        (0x0497_8040, true, true),   // lslr_z_p_zz_
        (0x04d7_8040, true, true),   // lslr_z_p_zz_
        (0x0401_81e0, true, false),  // lsr_z_p_zi_
        (0x0401_83e0, true, false),  // lsr_z_p_zi_
        (0x0441_83e0, true, false),  // lsr_z_p_zi_
        (0x04c1_83e0, true, false),  // lsr_z_p_zi_
        (0x0419_8040, true, true),   // lsr_z_p_zw_
        (0x0459_8040, true, true),   // lsr_z_p_zw_
        (0x0499_8040, true, true),   // lsr_z_p_zw_
        (0x0411_8040, true, false),  // lsr_z_p_zz_
        (0x0451_8040, true, true),   // lsr_z_p_zz_
        (0x0491_8040, true, true),   // lsr_z_p_zz_
        (0x04d1_8040, true, true),   // lsr_z_p_zz_
        (0x042f_9420, true, false),  // lsr_z_zi_
        (0x043f_9420, true, false),  // lsr_z_zi_
        (0x047f_9420, true, false),  // lsr_z_zi_
        (0x04ff_9420, true, false),  // lsr_z_zi_
        (0x0422_8420, true, true),   // lsr_z_zw_
        (0x0462_8420, true, true),   // lsr_z_zw_
        (0x04a2_8420, true, true),   // lsr_z_zw_
        (0x0415_8040, true, false),  // lsrr_z_p_zz_
        (0x0455_8040, true, true),   // lsrr_z_p_zz_
        (0x0495_8040, true, true),   // lsrr_z_p_zz_
        (0x04d5_8040, true, true),   // lsrr_z_p_zz_
        (0x4508_f420, true, false),  // sli_z_zzi_
        (0x4510_f420, true, false),  // sli_z_zzi_
        (0x4540_f420, true, false),  // sli_z_zzi_
        (0x4580_f420, true, false),  // sli_z_zzi_
        (0x440a_8040, false, false), // sqrshl_z_p_zz_
        (0x444a_8040, false, false), // sqrshl_z_p_zz_
        (0x448a_8040, false, false), // sqrshl_z_p_zz_
        (0x44ca_8040, false, false), // sqrshl_z_p_zz_
        (0x440e_8040, false, false), // sqrshlr_z_p_zz_
        (0x444e_8040, false, false), // sqrshlr_z_p_zz_
        (0x448e_8040, false, false), // sqrshlr_z_p_zz_
        (0x44ce_8040, false, false), // sqrshlr_z_p_zz_
        (0x0406_8100, false, false), // sqshl_z_p_zi_
        (0x0406_8200, false, false), // sqshl_z_p_zi_
        (0x0446_8000, false, false), // sqshl_z_p_zi_
        (0x0486_8000, false, false), // sqshl_z_p_zi_
        (0x4408_8040, false, false), // sqshl_z_p_zz_
        (0x4448_8040, false, false), // sqshl_z_p_zz_
        (0x4488_8040, false, false), // sqshl_z_p_zz_
        (0x44c8_8040, false, false), // sqshl_z_p_zz_
        (0x440c_8040, false, false), // sqshlr_z_p_zz_
        (0x444c_8040, false, false), // sqshlr_z_p_zz_
        (0x448c_8040, false, false), // sqshlr_z_p_zz_
        (0x44cc_8040, false, false), // sqshlr_z_p_zz_
        (0x040f_8100, false, false), // sqshlu_z_p_zi_
        (0x040f_8200, false, false), // sqshlu_z_p_zi_
        (0x044f_8000, false, false), // sqshlu_z_p_zi_
        (0x048f_8000, false, false), // sqshlu_z_p_zi_
        (0x450f_f020, true, false),  // sri_z_zzi_
        (0x451f_f020, true, false),  // sri_z_zzi_
        (0x455f_f020, true, false),  // sri_z_zzi_
        (0x45df_f020, true, false),  // sri_z_zzi_
        (0x4402_8040, true, true),   // srshl_z_p_zz_
        (0x4442_8040, true, true),   // srshl_z_p_zz_
        (0x4482_8040, true, true),   // srshl_z_p_zz_
        (0x44c2_8040, true, true),   // srshl_z_p_zz_
        (0x4406_8040, false, false), // srshlr_z_p_zz_
        (0x4446_8040, false, false), // srshlr_z_p_zz_
        (0x4486_8040, false, false), // srshlr_z_p_zz_
        (0x44c6_8040, false, false), // srshlr_z_p_zz_
        (0x040c_81e0, true, false),  // srshr_z_p_zi_
        (0x040c_83e0, true, false),  // srshr_z_p_zi_
        (0x044c_83e0, true, false),  // srshr_z_p_zi_
        (0x04cc_83e0, true, false),  // srshr_z_p_zi_
        (0x450f_e820, true, false),  // srsra_z_zi_
        (0x451f_e820, true, false),  // srsra_z_zi_
        (0x455f_e820, true, false),  // srsra_z_zi_
        (0x45df_e820, true, false),  // srsra_z_zi_
        (0x450f_e020, true, false),  // ssra_z_zi_
        (0x451f_e020, true, false),  // ssra_z_zi_
        (0x455f_e020, true, false),  // ssra_z_zi_
        (0x45df_e020, true, false),  // ssra_z_zi_
        (0x440b_8040, false, false), // uqrshl_z_p_zz_
        (0x444b_8040, false, false), // uqrshl_z_p_zz_
        (0x448b_8040, false, false), // uqrshl_z_p_zz_
        (0x44cb_8040, false, false), // uqrshl_z_p_zz_
        (0x440f_8040, false, false), // uqrshlr_z_p_zz_
        (0x444f_8040, false, false), // uqrshlr_z_p_zz_
        (0x448f_8040, false, false), // uqrshlr_z_p_zz_
        (0x44cf_8040, false, false), // uqrshlr_z_p_zz_
        (0x0407_8100, false, false), // uqshl_z_p_zi_
        (0x0407_8200, false, false), // uqshl_z_p_zi_
        (0x0447_8000, false, false), // uqshl_z_p_zi_
        (0x0487_8000, false, false), // uqshl_z_p_zi_
        (0x4409_8040, false, false), // uqshl_z_p_zz_
        (0x4449_8040, false, false), // uqshl_z_p_zz_
        (0x4489_8040, false, false), // uqshl_z_p_zz_
        (0x44c9_8040, false, false), // uqshl_z_p_zz_
        (0x440d_8040, false, false), // uqshlr_z_p_zz_
        (0x444d_8040, false, false), // uqshlr_z_p_zz_
        (0x448d_8040, false, false), // uqshlr_z_p_zz_
        (0x44cd_8040, false, false), // uqshlr_z_p_zz_
        (0x4403_8040, true, true),   // urshl_z_p_zz_
        (0x4443_8040, true, true),   // urshl_z_p_zz_
        (0x4483_8040, true, true),   // urshl_z_p_zz_
        (0x44c3_8040, true, true),   // urshl_z_p_zz_
        (0x4407_8040, false, false), // urshlr_z_p_zz_
        (0x4447_8040, false, false), // urshlr_z_p_zz_
        (0x4487_8040, false, false), // urshlr_z_p_zz_
        (0x44c7_8040, false, false), // urshlr_z_p_zz_
        (0x040d_81e0, true, false),  // urshr_z_p_zi_
        (0x040d_83e0, true, false),  // urshr_z_p_zi_
        (0x044d_83e0, true, false),  // urshr_z_p_zi_
        (0x04cd_83e0, true, false),  // urshr_z_p_zi_
        (0x450f_ec20, true, false),  // ursra_z_zi_
        (0x451f_ec20, true, false),  // ursra_z_zi_
        (0x455f_ec20, true, false),  // ursra_z_zi_
        (0x45df_ec20, true, false),  // ursra_z_zi_
        (0x450f_e420, true, false),  // usra_z_zi_
        (0x451f_e420, true, false),  // usra_z_zi_
        (0x455f_e420, true, false),  // usra_z_zi_
        (0x45df_e420, true, false),  // usra_z_zi_
        (0x042f_3440, true, false),  // xar_z_zzi_
        (0x043f_3440, true, false),  // xar_z_zzi_
        (0x047f_3440, true, false),  // xar_z_zzi_
        (0x04ff_3440, true, false),  // xar_z_zzi_
    ];
    for &(word, noted, requires_dit_zero) in AUDITED_WORDS {
        let operand = shifts::decode(word).unwrap().unwrap();
        assert_eq!(operand.has_dit_guarantee, noted, "{word:#x}");
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            assert_eq!(
                x86_64::sve::shifts::requires_declared_dit_zero(operand, length),
                requires_dit_zero,
                "{word:#x} at {bytes} bytes",
            );
            let source = words(&[NOP, word, RET_X30]);
            let legacy = compile_for_profile(
                &source,
                GuestAddress(0),
                profile(bytes, true),
                TargetCpu::Baseline,
            );
            if requires_dit_zero {
                assert!(legacy.unwrap_err().0.contains("requires declared DIT=0"));
            } else {
                assert!(legacy.is_ok());
            }
            assert!(
                compile_for_profile(
                    &source,
                    GuestAddress(0),
                    declared_dit_zero_profile(bytes),
                    TargetCpu::Baseline,
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn integer_shifts_reserved_and_prefix_inputs_remain_explicit() {
    const LSL_RESERVED_SIZE: u32 = 0x0403_8000;
    const ASR_RESERVED_DOUBLEWORDS: u32 = 0x04d8_8000;
    const LSL_Z0_B_P0_Z0_B_ZERO: u32 = 0x0403_8100;
    for word in [LSL_RESERVED_SIZE, ASR_RESERVED_DOUBLEWORDS] {
        assert!(
            compile_for_profile(
                &words(&[NOP, word, RET_X30]),
                GuestAddress(0),
                profile(16, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("reserved streaming integer shift")
        );
    }
    assert!(
        compile_for_profile(
            &words(&[MOVPRFX_Z0_Z1, LSL_Z0_B_P0_Z0_B_ZERO, RET_X30]),
            GuestAddress(0),
            profile(16, true),
            TargetCpu::Baseline
        )
        .unwrap_err()
        .0
        .contains("MOVPRFX pair validation")
    );
    assert!(crate::compile(&words(&[LSL_Z0_B_P0_Z0_B_ZERO, RET_X30]), GuestAddress(0)).is_err());
}

#[test]
fn width_conversions_register_exact_bodies_and_source_maps() {
    const CANONICAL_WORDS: [u32; 26] = [
        0x452f1820, // RSHRNB
        0x452f1c20, // RSHRNT
        0x452f1020, // SHRNB
        0x452f1420, // SHRNT
        0x452f2820, // SQRSHRNB
        0x452f2c20, // SQRSHRNT
        0x452f0820, // SQRSHRUNB
        0x452f0c20, // SQRSHRUNT
        0x452f2020, // SQSHRNB
        0x452f2420, // SQSHRNT
        0x452f0020, // SQSHRUNB
        0x452f0420, // SQSHRUNT
        0x45284020, // SQXTNB
        0x45284420, // SQXTNT
        0x45285020, // SQXTUNB
        0x45285420, // SQXTUNT
        0x4508a020, // SSHLLB
        0x4508a420, // SSHLLT
        0x452f3820, // UQRSHRNB
        0x452f3c20, // UQRSHRNT
        0x452f3020, // UQSHRNB
        0x452f3420, // UQSHRNT
        0x45284820, // UQXTNB
        0x45284c20, // UQXTNT
        0x4508a820, // USHLLB
        0x4508ac20, // USHLLT
    ];
    for word in CANONICAL_WORDS {
        let operand = shifts_narrow::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::ShiftsNarrow(operand)))
        );
        for bytes in [16, 32, 64, 128, 256] {
            for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                let native = compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0x1000),
                    profile(bytes, true),
                    target,
                )
                .unwrap();
                let mut body = Vec::new();
                x86_64::sve::shifts_narrow::emit(
                    &mut body,
                    operand,
                    VectorLength::from_bytes(bytes).unwrap(),
                    target,
                );
                let return_offset = CONTEXT_WRAPPER_BYTES + body.len();
                assert_eq!(
                    native.source_map,
                    [
                        (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                        (GuestAddress(0x1004), return_offset)
                    ]
                );
                assert_eq!(
                    &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                    context_wrapper()
                );
                assert_eq!(
                    &native.x86_64_code[CONTEXT_WRAPPER_BYTES..return_offset],
                    body
                );
                assert_eq!(&native.x86_64_code[return_offset..], &[RET]);
            }
        }
        for streaming in [false, true] {
            for za in [false, true] {
                let selected = ScalableProfile::new(
                    VectorLength::from_bytes(16).unwrap(),
                    ScalableMode::new(streaming, za),
                );
                let result = compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0),
                    selected,
                    TargetCpu::Baseline,
                );
                if streaming {
                    assert!(result.is_ok());
                } else {
                    assert!(result.unwrap_err().0.contains("streaming mode required"));
                }
            }
        }
    }
}

#[test]
fn width_conversion_reserved_and_prefix_inputs_remain_explicit() {
    const SSHLLB_RESERVED_SIZE: u32 = 0x4500_a000;
    const SQXTNB_RESERVED_SIZE: u32 = 0x4520_4000;
    const SSHLLB_Z0_H_Z1_B: u32 = 0x4508_a020;
    for word in [SSHLLB_RESERVED_SIZE, SQXTNB_RESERVED_SIZE] {
        assert!(
            compile_for_profile(
                &words(&[NOP, word, RET_X30]),
                GuestAddress(0),
                profile(16, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("reserved streaming width-conversion")
        );
    }
    assert!(
        compile_for_profile(
            &words(&[MOVPRFX_Z0_Z1, SSHLLB_Z0_H_Z1_B, RET_X30]),
            GuestAddress(0),
            profile(16, true),
            TargetCpu::Baseline
        )
        .unwrap_err()
        .0
        .contains("MOVPRFX pair validation")
    );
    assert!(crate::compile(&words(&[SSHLLB_Z0_H_Z1_B, RET_X30]), GuestAddress(0)).is_err());
}
