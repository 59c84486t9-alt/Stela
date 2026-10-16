//! SVE permute dispatch, bodies and source maps.
use super::*;
use crate::aarch64::sve::rearrange;
use alloc::vec::Vec;

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
const RESERVED_LOGICAL_MASK: u32 = 0x05c0_07e0;
const NONZERO_REVD_SIZE: u32 = 0x056e_8000;
const MOVPRFX_PREDICATED_Z0_Z1: u32 = 0x0410_2020;
const REARRANGEMENT_WORDS: [u32; 20] = [
    0x05c00003, // dupm_z_i_
    0x05600023, // ext_z_zi_con
    0x05200023, // ext_z_zi_des
    0x04224023, // index_z_ii_
    0x04224823, // index_z_ir_
    0x04224423, // index_z_ri_
    0x04224c23, // index_z_rr_
    0x05383823, // rev_z_z_
    0x052e8023, // revd_z_p_z_m
    0x052d8023, // splice_z_p_zz_con
    0x052c8023, // splice_z_p_zz_des
    0x05223023, // tbl_z_zz_1
    0x05222823, // tbl_z_zz_2
    0x05222c23, // tbx_z_zz_
    0x05227023, // trn1_z_zz_
    0x05227423, // trn2_z_zz_
    0x05226823, // uzp1_z_zz_
    0x05226c23, // uzp2_z_zz_
    0x05226023, // zip1_z_zz_
    0x05226423, // zip2_z_zz_
];

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn profile(bytes: usize, svcr: u64) -> ScalableProfile {
    ScalableProfile::new(
        VectorLength::from_bytes(bytes).unwrap(),
        ScalableMode::from_svcr(svcr).unwrap(),
    )
}

fn dit_zero_profile(bytes: usize, svcr: u64) -> ScalableProfile {
    let length = VectorLength::from_bytes(bytes).unwrap();
    ScalableProfile::new_with_features(
        length,
        ScalableMode::from_svcr(svcr).unwrap(),
        ScalableFeatures::of(ScalableFeature::Sme),
        ScalableControls::new(length, false),
    )
    .unwrap()
}

#[test]
fn rearrangement_production_dispatch_has_exact_body_maps_and_target_encoding() {
    for word in REARRANGEMENT_WORDS {
        let operand = rearrange::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::Rearrange(operand)))
        );
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in [1, 3] {
                for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                    let length = VectorLength::from_bytes(bytes).unwrap();
                    let execution = if x86_64::sve::rearrange::requires_explicit_dit_zero(
                        operand, length, target,
                    ) {
                        dit_zero_profile(bytes, svcr)
                    } else {
                        profile(bytes, svcr)
                    };
                    let native = compile_for_profile(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0x1000),
                        execution,
                        target,
                    )
                    .unwrap();
                    let mut expected = Vec::new();
                    x86_64::sve::rearrange::emit(
                        &mut expected,
                        operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        native.source_map,
                        [
                            (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                            (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + 1),
                            (
                                GuestAddress(0x1008),
                                CONTEXT_WRAPPER_BYTES + 1 + expected.len()
                            ),
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES + 1..native.source_map[2].1],
                        expected
                    );
                    assert_eq!(&native.x86_64_code[native.source_map[2].1..], [RET]);
                }
            }
        }
    }
}

#[test]
fn rearrangement_preflight_preserves_mode_reserved_legacy_and_prefix_boundaries() {
    for word in REARRANGEMENT_WORDS {
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in [0, 2] {
                assert!(
                    compile_for_profile(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, svcr),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .0
                    .contains("streaming mode required")
                );
            }
        }
        assert!(crate::compile(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
        assert!(
            compile_for_profile(
                &source(&[MOVPRFX_Z0_Z1, word, RET_X30]),
                GuestAddress(0),
                profile(32, 3),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
    }
    assert!(
        compile_for_profile(
            &source(&[NOP, RESERVED_LOGICAL_MASK, RET_X30]),
            GuestAddress(0),
            profile(32, 3),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .0
        .contains("reserved streaming rearrangement")
    );
}

#[test]
fn rearrangement_declines_nonzero_revd_size_and_both_prefix_forms() {
    assert!(
        compile_for_profile(
            &source(&[NONZERO_REVD_SIZE, RET_X30]),
            GuestAddress(0),
            profile(32, 3),
            TargetCpu::Baseline,
        )
        .is_err()
    );
    for prefix in [MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1] {
        assert!(
            compile_for_profile(
                &source(&[prefix, REARRANGEMENT_WORDS[0], RET_X30]),
                GuestAddress(0),
                profile(32, 3),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
    }
}

#[test]
fn rearrangement_scalar_tables_require_explicit_dit_zero_while_byte_shuffle_stays_v1() {
    const TBL_B_Z3_Z1_Z2: u32 = 0x0522_3023;
    const TBL_H_Z3_Z1_Z2: u32 = 0x0562_3023;
    for bytes in [16, 32, 64, 128, 256] {
        for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
            for svcr in [1, 3] {
                for word in [TBL_B_Z3_Z1_Z2, TBL_H_Z3_Z1_Z2] {
                    let operand = rearrange::decode(word).unwrap().unwrap();
                    let requires = x86_64::sve::rearrange::requires_explicit_dit_zero(
                        operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );
                    let legacy = compile_for_profile(
                        &source(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, svcr),
                        target,
                    );
                    if requires {
                        assert!(legacy.unwrap_err().0.contains(
                            "scalar table lookup requires explicitly declared DIT=0 at 0x1000"
                        ));
                        assert_eq!(profile(bytes, svcr).required_dit(), None);
                    } else {
                        assert!(legacy.is_ok());
                    }
                    let declared = dit_zero_profile(bytes, svcr);
                    assert_eq!(declared.required_dit(), Some(false));
                    assert!(
                        compile_for_profile(
                            &source(&[word, RET_X30]),
                            GuestAddress(0x1000),
                            declared,
                            target,
                        )
                        .is_ok()
                    );
                }
            }
        }
    }
    // These observations distinguish fixed-work PSHUFB from scalar gather;
    // the frontend itself consumes the shared selector rather than a cutoff copy.
    let byte = rearrange::decode(TBL_B_Z3_Z1_Z2).unwrap().unwrap();
    let half = rearrange::decode(TBL_H_Z3_Z1_Z2).unwrap().unwrap();
    let small = VectorLength::from_bytes(16).unwrap();
    let wide = VectorLength::from_bytes(256).unwrap();
    assert!(x86_64::sve::rearrange::requires_explicit_dit_zero(
        byte,
        small,
        TargetCpu::Baseline
    ));
    assert!(!x86_64::sve::rearrange::requires_explicit_dit_zero(
        byte,
        small,
        TargetCpu::Ssse3
    ));
    assert!(x86_64::sve::rearrange::requires_explicit_dit_zero(
        byte,
        wide,
        TargetCpu::Ssse3
    ));
    assert!(x86_64::sve::rearrange::requires_explicit_dit_zero(
        half,
        small,
        TargetCpu::Ssse3
    ));
}
