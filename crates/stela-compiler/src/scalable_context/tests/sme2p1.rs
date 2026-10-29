//! SME2.1 dispatch, features, modes and source maps.
use super::*;
use crate::aarch64::sve::{rearrange, reductions};
use alloc::vec::Vec;
const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const PARENT_Q_WORDS: [u32; 105] = [
    0x052037ff, // tbxq_z_zz_
    0x05212421, // dupq_z_zi_
    0x05212423, // dupq_z_zi_
    0x052127ff, // dupq_z_zi_
    0x05222421, // dupq_z_zi_
    0x05222423, // dupq_z_zi_
    0x052227ff, // dupq_z_zi_
    0x05223421, // tbxq_z_zz_
    0x05223423, // tbxq_z_zz_
    0x05232421, // dupq_z_zi_
    0x05232423, // dupq_z_zi_
    0x052327ff, // dupq_z_zi_
    0x05242421, // dupq_z_zi_
    0x05242423, // dupq_z_zi_
    0x052427ff, // dupq_z_zi_
    0x05262421, // dupq_z_zi_
    0x05262423, // dupq_z_zi_
    0x052627ff, // dupq_z_zi_
    0x05282421, // dupq_z_zi_
    0x05282423, // dupq_z_zi_
    0x052827ff, // dupq_z_zi_
    0x052c2421, // dupq_z_zi_
    0x052c2423, // dupq_z_zi_
    0x052c27ff, // dupq_z_zi_
    0x05382421, // dupq_z_zi_
    0x05382423, // dupq_z_zi_
    0x053827ff, // dupq_z_zi_
    0x05602421, // extq_z_zi_des
    0x05602423, // extq_z_zi_des
    0x056027ff, // extq_z_zi_des
    0x056037ff, // tbxq_z_zz_
    0x05612421, // extq_z_zi_des
    0x05612423, // extq_z_zi_des
    0x056127ff, // extq_z_zi_des
    0x05623421, // tbxq_z_zz_
    0x05623423, // tbxq_z_zz_
    0x056f2421, // extq_z_zi_des
    0x056f2423, // extq_z_zi_des
    0x056f27ff, // extq_z_zi_des
    0x05a037ff, // tbxq_z_zz_
    0x05a23421, // tbxq_z_zz_
    0x05a23423, // tbxq_z_zz_
    0x05e037ff, // tbxq_z_zz_
    0x05e23421, // tbxq_z_zz_
    0x05e23423, // tbxq_z_zz_
    0x4400e3ff, // zipq1_z_zz_
    0x4400e7ff, // zipq2_z_zz_
    0x4400ebff, // uzpq1_z_zz_
    0x4400efff, // uzpq2_z_zz_
    0x4400fbff, // tblq_z_zz_
    0x4402e021, // zipq1_z_zz_
    0x4402e023, // zipq1_z_zz_
    0x4402e421, // zipq2_z_zz_
    0x4402e423, // zipq2_z_zz_
    0x4402e821, // uzpq1_z_zz_
    0x4402e823, // uzpq1_z_zz_
    0x4402ec21, // uzpq2_z_zz_
    0x4402ec23, // uzpq2_z_zz_
    0x4402f821, // tblq_z_zz_
    0x4402f823, // tblq_z_zz_
    0x4440e3ff, // zipq1_z_zz_
    0x4440e7ff, // zipq2_z_zz_
    0x4440ebff, // uzpq1_z_zz_
    0x4440efff, // uzpq2_z_zz_
    0x4440fbff, // tblq_z_zz_
    0x4442e021, // zipq1_z_zz_
    0x4442e023, // zipq1_z_zz_
    0x4442e421, // zipq2_z_zz_
    0x4442e423, // zipq2_z_zz_
    0x4442e821, // uzpq1_z_zz_
    0x4442e823, // uzpq1_z_zz_
    0x4442ec21, // uzpq2_z_zz_
    0x4442ec23, // uzpq2_z_zz_
    0x4442f821, // tblq_z_zz_
    0x4442f823, // tblq_z_zz_
    0x4480e3ff, // zipq1_z_zz_
    0x4480e7ff, // zipq2_z_zz_
    0x4480ebff, // uzpq1_z_zz_
    0x4480efff, // uzpq2_z_zz_
    0x4480fbff, // tblq_z_zz_
    0x4482e021, // zipq1_z_zz_
    0x4482e023, // zipq1_z_zz_
    0x4482e421, // zipq2_z_zz_
    0x4482e423, // zipq2_z_zz_
    0x4482e821, // uzpq1_z_zz_
    0x4482e823, // uzpq1_z_zz_
    0x4482ec21, // uzpq2_z_zz_
    0x4482ec23, // uzpq2_z_zz_
    0x4482f821, // tblq_z_zz_
    0x4482f823, // tblq_z_zz_
    0x44c0e3ff, // zipq1_z_zz_
    0x44c0e7ff, // zipq2_z_zz_
    0x44c0ebff, // uzpq1_z_zz_
    0x44c0efff, // uzpq2_z_zz_
    0x44c0fbff, // tblq_z_zz_
    0x44c2e021, // zipq1_z_zz_
    0x44c2e023, // zipq1_z_zz_
    0x44c2e421, // zipq2_z_zz_
    0x44c2e423, // zipq2_z_zz_
    0x44c2e821, // uzpq1_z_zz_
    0x44c2e823, // uzpq1_z_zz_
    0x44c2ec21, // uzpq2_z_zz_
    0x44c2ec23, // uzpq2_z_zz_
    0x44c2f821, // tblq_z_zz_
    0x44c2f823, // tblq_z_zz_
];
const REDUCTION_Q_CLASSES: [u32; 8] = [
    0x0405_2000,
    0x041e_2000,
    0x041d_2000,
    0x041c_2000,
    0x040c_2000,
    0x040e_2000,
    0x040d_2000,
    0x040f_2000,
];
const SIZE_SHIFT: u32 = 22;
const SOURCE_ONE_DESTINATION_ZERO: u32 = 0x20;
fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
fn features(q: bool) -> ScalableFeatures {
    let base = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
    if q {
        base.with(ScalableFeature::Sme2p1)
    } else {
        base
    }
}
fn declared(bytes: usize, svcr: u64, q: bool) -> ScalableProfile {
    let length = VectorLength::from_bytes(bytes).unwrap();
    ScalableProfile::new_with_features(
        length,
        ScalableMode::from_svcr(svcr).unwrap(),
        features(q),
        ScalableControls::new(length, false),
    )
    .unwrap()
}
fn reduction_words() -> impl Iterator<Item = u32> {
    REDUCTION_Q_CLASSES.into_iter().flat_map(|class| {
        (0..4).map(move |size| class | size << SIZE_SHIFT | SOURCE_ONE_DESTINATION_ZERO)
    })
}
#[test]
fn sme2p1_q_dispatch_has_exact_body_and_maps_for_all_declared_lengths_modes_targets() {
    assert_eq!(reduction_words().count(), 32);
    for word in PARENT_Q_WORDS.into_iter().chain(reduction_words()) {
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in [1, 3] {
                for target in [
                    TargetCpu::Baseline,
                    TargetCpu::Ssse3,
                    TargetCpu::Sse41,
                    TargetCpu::Sse42,
                ] {
                    let length = VectorLength::from_bytes(bytes).unwrap();
                    let native = crate::testing::context_leaf(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0x1000),
                        declared(bytes, svcr, true),
                        target,
                    )
                    .unwrap();
                    let mut expected = Code::new();
                    if let Some(Ok(operand)) = reductions::decode(word) {
                        assert_eq!(operand.output, reductions::Output::Quadword);
                        x86_64::sve::reductions::emit(&mut expected, operand, length, target);
                    } else {
                        let operand = rearrange::decode(word).unwrap().unwrap();
                        assert!(matches!(
                            operand,
                            rearrange::Operand::Interleave { segment: true, .. }
                                | rearrange::Operand::Extract { segment: true, .. }
                                | rearrange::Operand::Table { segment: true, .. }
                                | rearrange::Operand::DuplicateSegment { .. }
                        ));
                        x86_64::sve::rearrange::emit(&mut expected, operand, length, target);
                    }
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
fn sme2p1_q_requires_explicit_guest_feature_and_streaming_mode_independent_of_za() {
    for word in PARENT_Q_WORDS.into_iter().chain(reduction_words()) {
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for svcr in [1, 3] {
                for profile in [
                    ScalableProfile::new(length, ScalableMode::from_svcr(svcr).unwrap()),
                    declared(bytes, svcr, false),
                ] {
                    let error = crate::testing::context_leaf(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0x1000),
                        profile,
                        TargetCpu::Baseline,
                    )
                    .unwrap_err();
                    assert_eq!(error.instruction.unwrap().address, GuestAddress(0x1004));
                    let crate::CompileErrorKind::GuestFeaturesUnavailable { required, .. } =
                        error.kind
                    else {
                        panic!("{error}")
                    };
                    let sme2p1 = crate::aarch64::scalable::features::ScalableFeature::Sme2p1;
                    assert!(
                        required.all_features().contains(sme2p1)
                            || required.any_features().contains(sme2p1)
                    );
                }
            }
            for svcr in [0, 2] {
                assert!(
                    crate::testing::context_leaf(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0x1000),
                        declared(bytes, svcr, true),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("streaming mode required at 0x1004")
                );
            }
        }
        assert!(crate::testing::leaf(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
        for prefix in [0x0420_bc20, 0x0410_2020] {
            assert!(
                crate::testing::context_leaf(
                    &source(&[prefix, word, RET_X30]),
                    GuestAddress(0),
                    declared(32, 3, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .to_string()
                .contains("MOVPRFX pair validation")
            );
        }
    }
}

#[test]
fn sme2p1_q_table_dit_scope_follows_selected_recipe_and_other_q_forms_stay_unrestricted() {
    for word in PARENT_Q_WORDS {
        let operand = rearrange::decode(word).unwrap().unwrap();
        for bytes in [16, 32, 64, 128, 256] {
            for target in [
                TargetCpu::Baseline,
                TargetCpu::Ssse3,
                TargetCpu::Sse41,
                TargetCpu::Sse42,
            ] {
                let required = x86_64::sve::rearrange::requires_explicit_dit_zero(
                    operand,
                    VectorLength::from_bytes(bytes).unwrap(),
                    target,
                );
                let table = matches!(operand, rearrange::Operand::Table { segment: true, .. });
                if !table {
                    assert!(!required);
                }
                if let rearrange::Operand::Table { element_size, .. } = operand {
                    let byte = element_size == crate::aarch64::scalable::ElementSize::Byte;
                    assert_eq!(required, !(byte && target.supports(TargetCpu::Ssse3)));
                }
                for svcr in [1, 3] {
                    assert!(
                        crate::testing::context_leaf(
                            &source(&[word, RET_X30]),
                            GuestAddress(0),
                            declared(bytes, svcr, true),
                            target
                        )
                        .is_ok()
                    );
                }
            }
        }
    }
}
