//! PMOV dispatch, source maps and feature/mode limits.
use super::*;
use crate::aarch64::sve::integer_predicate_move;
use alloc::vec::Vec;

const RET_X30: u32 = 0xd65f_03c0;
const BASES: [u32; 4] = [0x052b_3800, 0x052d_3800, 0x0569_3800, 0x05a9_3800];
const PORTION_LOW_SHIFT: u32 = 17;
const PORTION_HIGH_SHIFT: u32 = 22;
const PREDICATE_SHIFT: u32 = 5;

fn source(word: u32) -> Vec<u8> {
    [word, RET_X30]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}
fn profile(bytes: usize, streaming: bool, za: bool, p1: bool) -> ScalableProfile {
    let mut features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
    if p1 {
        features = features.with(ScalableFeature::Sme2p1);
    }
    ScalableProfile::new_with_features(
        VectorLength::from_bytes(bytes).unwrap(),
        ScalableMode::new(streaming, za),
        features,
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
    )
    .unwrap()
}

#[test]
fn predicate_move_dispatch_preserves_complete_bodies_and_maps() {
    for (size, base) in BASES.into_iter().enumerate() {
        for portion in 0..(1u32 << size) {
            let word = base
                | ((portion & 3) << PORTION_LOW_SHIFT)
                | ((portion >> 2) << PORTION_HIGH_SHIFT)
                | (15 << PREDICATE_SHIFT)
                | 31;
            let operand = integer_predicate_move::decode(word).unwrap().unwrap();
            assert_eq!(
                crate::aarch64::sve::decode(word),
                Some(Ok(crate::aarch64::sve::Operand::IntegerPredicateMove(
                    operand
                )))
            );
            for bytes in [16, 32, 64, 128, 256] {
                for za in [false, true] {
                    for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                        let native = compile_for_profile(
                            &source(word),
                            GuestAddress(0x1000),
                            profile(bytes, true, za, true),
                            target,
                        )
                        .unwrap();
                        let mut expected = Vec::new();
                        x86_64::sve::integer_predicate_move::emit(
                            &mut expected,
                            operand,
                            VectorLength::from_bytes(bytes).unwrap(),
                            target,
                        );
                        assert_eq!(
                            native.source_map,
                            [
                                (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                            ]
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                            expected
                        );
                        assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                    }
                }
            }
        }
    }
}

#[test]
fn predicate_move_requires_sme2p1_streaming_without_requiring_za() {
    for word in BASES {
        let error = compile_for_profile(
            &source(word),
            GuestAddress(0),
            profile(16, true, false, false),
            TargetCpu::Baseline,
        )
        .unwrap_err();
        assert!(error.0.contains("FEAT_SME2p1"));
        for za in [false, true] {
            let error = compile_for_profile(
                &source(word),
                GuestAddress(0),
                profile(16, false, za, true),
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(error.0.contains("streaming mode required"));
            assert!(
                compile_for_profile(
                    &source(word),
                    GuestAddress(0),
                    profile(16, true, za, true),
                    TargetCpu::Baseline
                )
                .is_ok()
            );
        }
        assert!(
            compile_for_profile(
                &source(word),
                GuestAddress(0),
                ScalableProfile::new(
                    VectorLength::from_bytes(16).unwrap(),
                    ScalableMode::new(true, false)
                ),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("FEAT_SME2p1")
        );
    }
}
