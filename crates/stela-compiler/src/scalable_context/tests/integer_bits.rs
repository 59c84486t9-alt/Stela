use super::*;
use crate::aarch64::sve::integer_bits;

#[test]
fn integer_bits_register_exact_bodies_and_source_maps() {
    const CANONICAL_WORDS: [u32; 7] = [
        0x0418_a020, // CLS
        0x0419_a020, // CLZ
        0x041a_a020, // CNT
        0x0527_8020, // RBIT
        0x0564_8020, // REVB
        0x05a5_8020, // REVH
        0x05e6_8020, // REVW
    ];
    for word in CANONICAL_WORDS {
        let operand = integer_bits::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::IntegerBits(operand)))
        );
        for bytes in [16, 32, 64, 128, 256] {
            for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Sse41] {
                let native = crate::testing::context_leaf(
                    &words(&[word, RET_X30]),
                    GuestAddress(0x1000),
                    profile(bytes, true),
                    target,
                )
                .unwrap();
                let mut body = Code::new();
                x86_64::sve::integer_bits::emit(
                    &mut body,
                    operand,
                    VectorLength::from_bytes(bytes).unwrap(),
                    target,
                );

                assert_single_body(&native, GuestAddress(0x1000), &body);
            }
        }
        let length = VectorLength::from_bytes(16).unwrap();
        for streaming in [false, true] {
            for za in [false, true] {
                // Base SME is sufficient; no accidental SME2 requirement.
                let selected = ScalableProfile::new_with_features(
                    length,
                    ScalableMode::new(streaming, za),
                    ScalableFeatures::of(ScalableFeature::Sme),
                    ScalableControls::new(length, false),
                )
                .unwrap();
                let result = crate::testing::context_leaf(
                    &words(&[word, RET_X30]),
                    GuestAddress(0),
                    selected,
                    TargetCpu::Baseline,
                );
                if streaming {
                    assert!(result.is_ok());
                } else {
                    assert!(matches!(
                        result.unwrap_err().kind,
                        crate::CompileErrorKind::StreamingModeRequired
                    ));
                }
            }
        }
    }
}

#[test]
fn integer_bits_zeroing_forms_remain_explicit() {
    const ZEROING_WORDS: [u32; 7] = [
        0x0408_a020,
        0x0409_a020,
        0x040a_a020,
        0x0527_a020,
        0x0564_a020,
        0x05a5_a020,
        0x05e6_a020,
    ];
    for word in ZEROING_WORDS {
        assert!(
            crate::testing::context_leaf(
                &words(&[word, RET_X30]),
                GuestAddress(0),
                profile(16, true),
                TargetCpu::Baseline
            )
            .is_err()
        );
    }
}
#[test]
fn integer_bits_bsr_recipes_require_declared_dit_zero() {
    const SIZE_SHIFT: u32 = 22;
    const LEADING_COUNT_WORDS: [u32; 2] = [0x0418_a020, 0x0419_a020];
    const VECTOR_BYTES: [usize; 5] = [16, 32, 64, 128, 256];
    // Independent audited B/H/S/D decisions by ascending supported SVL.
    const EXPECTED_DIT_REQUIREMENTS: [[bool; 5]; 4] = [
        [false; 5],
        [false; 5],
        [false, false, false, false, true],
        [true; 5],
    ];
    for canonical in LEADING_COUNT_WORDS {
        for (size, expected_by_length) in EXPECTED_DIT_REQUIREMENTS.into_iter().enumerate() {
            let word = canonical | ((size as u32) << SIZE_SHIFT);
            let operand = integer_bits::decode(word).unwrap().unwrap();
            for (length_index, bytes) in VECTOR_BYTES.into_iter().enumerate() {
                let length = VectorLength::from_bytes(bytes).unwrap();
                let requires_declared_dit_zero = expected_by_length[length_index];
                assert_eq!(
                    x86_64::sve::integer_bits::requires_declared_dit_zero(operand, length),
                    requires_declared_dit_zero
                );
                let declared = ScalableProfile::new_with_features(
                    length,
                    ScalableMode::new(true, false),
                    ScalableFeatures::of(ScalableFeature::Sme),
                    ScalableControls::new(length, false),
                )
                .unwrap();
                assert_eq!(declared.required_dit(), Some(false));
                for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Sse41] {
                    let positive = crate::testing::context_leaf(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        declared,
                        target,
                    )
                    .unwrap();
                    let mut body = Code::new();
                    x86_64::sve::integer_bits::emit(&mut body, operand, length, target);
                    assert_eq!(
                        &positive.x86_64_code[CONTEXT_WRAPPER_BYTES..][..body.len()],
                        body
                    );
                    let legacy = crate::testing::context_leaf(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, true),
                        target,
                    );
                    if requires_declared_dit_zero {
                        assert!(legacy.unwrap_err().to_string().contains("declared DIT=0"));
                    } else {
                        assert_eq!(legacy.unwrap().x86_64_code, positive.x86_64_code);
                    }
                }
            }
        }
    }
}
