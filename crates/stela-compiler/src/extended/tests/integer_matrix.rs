use super::*;
use crate::aarch64::sme::integer_matrix;

#[test]
fn integer_matrix_admission_checks_features_mode_and_source_maps() {
    const MATRIX_WORDS: [u32; 6] = [
        0xc1a0_1c10, // ADD ZA.S pair.
        0xc100_0000, // SMLALL ZA.S indexed byte products.
        0xc180_0000, // SMLALL ZA.D indexed halfword products.
        0xa080_0000, // SMOPA ZA.S byte outer products.
        0xa0c0_0000, // SMOPA ZA.D halfword outer products.
        0x8080_0008, // BMOPA ZA.S XNOR outer products.
    ];
    for word in MATRIX_WORDS {
        let operand = integer_matrix::decode(word).unwrap();
        let source = words(&[word, RET_X30]);
        assert!(crate::compile(&source, GuestAddress(0)).is_err());
        let legacy = ScalableProfile::new(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::new(true, true),
        );
        let legacy_result =
            compile_for_profile(&source, GuestAddress(0), legacy, TargetCpu::Baseline);
        assert_eq!(legacy_result.is_ok(), !operand.requires_i16i64());
        if operand.requires_i16i64() {
            assert!(legacy_result.unwrap_err().0.contains("FEAT_SME_I16I64"));
        }
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for sme2 in [false, true] {
                for i16i64 in [false, true] {
                    let mut features = ScalableFeatures::of(ScalableFeature::Sme);
                    if sme2 {
                        features = features.with(ScalableFeature::Sme2);
                    }
                    if i16i64 {
                        features = features.with(ScalableFeature::SmeI16I64);
                    }
                    for streaming in [false, true] {
                        for za in [false, true] {
                            let profile = ScalableProfile::new_with_features(
                                length,
                                ScalableMode::new(streaming, za),
                                features,
                                ScalableControls::new(length, false),
                            )
                            .unwrap();
                            let result = compile_for_profile(
                                &source,
                                GuestAddress(0),
                                profile,
                                TargetCpu::Baseline,
                            );
                            let permitted = streaming
                                && za
                                && (!operand.requires_sme2() || sme2)
                                && (!operand.requires_i16i64() || i16i64);
                            assert_eq!(
                                result.is_ok(),
                                permitted,
                                "word={word:#x} bytes={bytes} sme2={sme2} i16i64={i16i64} sm={streaming} za={za}"
                            );
                            if let Ok(native) = result {
                                let mut body = Vec::new();
                                x86_64::sme::integer_matrix::emit(
                                    &mut body,
                                    &operand,
                                    length,
                                    TargetCpu::Baseline,
                                );
                                let map = &native.source_map;
                                assert_eq!(map.len(), 2);
                                assert_eq!(map[0], (GuestAddress(0), CONTEXT_WRAPPER_BYTES));
                                assert_eq!(
                                    map[1],
                                    (GuestAddress(4), CONTEXT_WRAPPER_BYTES + body.len())
                                );
                                assert_eq!(&native.x86_64_code[map[0].1..map[1].1], body);
                                assert_eq!(&native.x86_64_code[map[1].1..], &[RET]);
                            }
                        }
                    }
                }
            }
        }
    }
}
