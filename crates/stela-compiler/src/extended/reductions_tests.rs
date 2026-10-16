//! Scalar reduction dispatch, allocated widths, exact body maps and admission limits.
use super::*;
use crate::aarch64::sve::reductions::{self, Output};
use alloc::vec::Vec;

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
const MOVPRFX_PREDICATED_Z0_Z1: u32 = 0x0410_2020;
const SIGNED_ADD: u32 = 0x0400_2000;
const RESERVED_SIGNED_DOUBLEWORD: u32 = 0x04c0_2020;
const SIZE_SHIFT: u32 = 22;
const SOURCE_ONE_DESTINATION_ZERO: u32 = 0x20;
const BASE_CLASSES: [u32; 9] = [
    0x041a_2000,
    0x0418_2000,
    0x0419_2000,
    0x0400_2000,
    0x0401_2000,
    0x0408_2000,
    0x0409_2000,
    0x040a_2000,
    0x040b_2000,
];

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn profile(bytes: usize, svcr: u64) -> ScalableProfile {
    let length = VectorLength::from_bytes(bytes).unwrap();
    ScalableProfile::new_with_features(
        length,
        ScalableMode::from_svcr(svcr).unwrap(),
        ScalableFeatures::of(ScalableFeature::Sme),
        ScalableControls::new(length, false),
    )
    .unwrap()
}

fn base_words() -> impl Iterator<Item = u32> {
    BASE_CLASSES.into_iter().flat_map(|class| {
        (0..4).filter_map(move |size| {
            (class != SIGNED_ADD || size != 3)
                .then_some(class | size << SIZE_SHIFT | SOURCE_ONE_DESTINATION_ZERO)
        })
    })
}

#[test]
fn scalar_reductions_all_35_widths_have_exact_dispatch_body_maps_and_targets() {
    assert_eq!(base_words().count(), 35);
    for word in base_words() {
        let operand = reductions::decode(word).unwrap().unwrap();
        assert_eq!(operand.output, Output::Scalar);
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::Reductions(operand)))
        );
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in [1, 3] {
                for target in [TargetCpu::Baseline, TargetCpu::Sse41, TargetCpu::Sse42] {
                    let native = compile_for_profile(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, svcr),
                        target,
                    )
                    .unwrap();
                    let mut expected = Vec::new();
                    x86_64::sve::reductions::emit(
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
fn scalar_reductions_preserve_mode_reserved_legacy_and_prefix_boundaries() {
    for word in base_words() {
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
        for prefix in [MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1] {
            assert!(
                compile_for_profile(
                    &source(&[prefix, word, RET_X30]),
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
    assert_eq!(
        reductions::decode(RESERVED_SIGNED_DOUBLEWORD),
        Some(Err(()))
    );
    assert!(
        compile_for_profile(
            &source(&[NOP, RESERVED_SIGNED_DOUBLEWORD, RET_X30]),
            GuestAddress(0),
            profile(32, 3),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .0
        .contains("reserved streaming integer reduction")
    );
}
