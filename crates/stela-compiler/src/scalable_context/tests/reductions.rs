//! SVE reduction dispatch, element sizes, source maps and limits.
use super::*;
use crate::aarch64::sve::reductions::{self, Output};
use alloc::vec::Vec;

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
                    let native = crate::testing::context_leaf(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, svcr),
                        target,
                    )
                    .unwrap();
                    let mut expected = Code::new();
                    x86_64::sve::reductions::emit(
                        &mut expected,
                        operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );

                    assert_bodies(&native, GuestAddress(0x1000), &[NOP_BODY, &expected]);
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
                    crate::testing::context_leaf(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, svcr),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("streaming mode required")
                );
            }
        }
        assert!(crate::testing::leaf(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
        for prefix in [MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1] {
            assert!(
                crate::testing::context_leaf(
                    &source(&[prefix, word, RET_X30]),
                    GuestAddress(0),
                    profile(32, 3),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .to_string()
                .contains("MOVPRFX pair validation")
            );
        }
    }
    assert_eq!(
        reductions::decode(RESERVED_SIGNED_DOUBLEWORD),
        Some(Err(crate::aarch64::Unsupported))
    );
    assert!(
        crate::testing::context_leaf(
            &source(&[NOP, RESERVED_SIGNED_DOUBLEWORD, RET_X30]),
            GuestAddress(0),
            profile(32, 3),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .to_string()
        .contains("reserved streaming integer reduction")
    );
}
