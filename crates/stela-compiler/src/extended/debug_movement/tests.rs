use super::*;
use crate::aarch64::scalable::{ScalableMode, VectorLength};
use alloc::vec;
const FROM_ZT0: u32 = 0xc04c03e0;
const TO_ZT0: u32 = 0xc04e03e0;
fn profile(streaming: bool) -> ScalableProfile {
    let length = VectorLength::from_bytes(16).unwrap();
    ScalableProfile::new_with_features(
        length,
        ScalableMode::new(streaming, true),
        ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
        crate::aarch64::scalable::profile::ScalableControls::new(length, true),
    )
    .unwrap()
}
#[test]
fn both_modes_keep_literal_access_obligations_even_for_discarded_read() {
    for streaming in [false, true] {
        for word in [FROM_ZT0 | 31, TO_ZT0 | 31] {
            let output = prepare(word, profile(streaming), Recipe::Scalar).unwrap();
            let instruction = &output.execution_requirements().instructions()[0];
            assert_eq!(
                instruction.access(),
                &ScalableAccessRequirements::Known(
                    vec![
                        ScalableAccessCheck::SmeEnabled,
                        ScalableAccessCheck::SmeZt0Enabled
                    ]
                    .into_boxed_slice()
                )
            );
            assert_eq!(
                instruction.guest_memory_quantity(),
                GuestMemoryQuantity::None
            );
            assert_eq!(output.word(), word);
            assert_eq!(output.word_to_native()[0].0, EXTERNAL_WORD_ORDINAL);
        }
    }
}
#[test]
fn discarded_read_emits_only_transport_return_after_runtime_checks() {
    for recipe in [Recipe::Scalar, Recipe::Sse2Comparison] {
        let output = prepare(FROM_ZT0 | 31, profile(false), recipe).unwrap();
        assert_eq!(output.code(), &[RET]);
    }
}
#[test]
fn all_lane_endpoints_preserve_shared_decoder_identity() {
    for base in [FROM_ZT0, TO_ZT0] {
        for lane in 0..8 {
            for register in [0, 30, 31] {
                let word = base | (lane << 12) | register;
                let output = prepare(word, profile(true), Recipe::Scalar).unwrap();
                assert_eq!(output.operand(), movement::decode(word).unwrap());
            }
        }
    }
}
#[test]
fn non_debug_forms_and_inactive_za_decline() {
    assert!(prepare(0xd503201f, profile(true), Recipe::Scalar).is_err());
    let length = VectorLength::from_bytes(16).unwrap();
    let no_za = ScalableProfile::new_with_features(
        length,
        ScalableMode::new(true, false),
        ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
        crate::aarch64::scalable::profile::ScalableControls::new(length, true),
    )
    .unwrap();
    assert!(prepare(FROM_ZT0, no_za, Recipe::Scalar).is_err());
}
