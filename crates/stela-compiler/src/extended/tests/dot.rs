use super::*;
use crate::aarch64::sve::dot;

#[test]
fn integer_dot_admission_requires_streaming_without_requiring_za() {
    const SDOT_Z0_S_Z1_B_Z2_B: u32 = 0x4482_0020;
    const CDOT_RESERVED_BYTE: u32 = 0x4400_1000;
    let source = words(&[SDOT_Z0_S_Z1_B_Z2_B, RET_X30]);
    assert!(crate::compile(&source, GuestAddress(0)).is_err());
    assert!(matches!(
        crate::aarch64::sve::decode(SDOT_Z0_S_Z1_B_Z2_B),
        Some(Ok(crate::aarch64::sve::Operand::Dot(_)))
    ));
    for bytes in [16, 32, 64, 128, 256] {
        for streaming in [false, true] {
            for za in [false, true] {
                let profile = ScalableProfile::new(
                    VectorLength::from_bytes(bytes).unwrap(),
                    ScalableMode::new(streaming, za),
                );
                let result =
                    compile_for_profile(&source, GuestAddress(0), profile, TargetCpu::Baseline);
                if streaming {
                    assert!(result.is_ok());
                } else {
                    assert!(result.unwrap_err().0.contains("streaming mode required"));
                }
            }
        }
        assert!(
            compile_for_profile(
                &words(&[CDOT_RESERVED_BYTE, RET_X30]),
                GuestAddress(0),
                profile(bytes, true),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("reserved streaming integer dot")
        );
    }
}

#[test]
fn integer_dot_registration_keeps_half_numerical_and_prefix_inputs_explicit() {
    const HALF_NUMERICAL_WORDS: [u32; 10] = [
        0x6420_8000,
        0x6420_4000,
        0x64a0_8000,
        0x64a0_8400,
        0x64a0_a000,
        0x64a0_a400,
        0x64a0_4000,
        0x64a0_4400,
        0x64a0_6000,
        0x64a0_6400,
    ];
    const SDOT_Z0_S_Z1_B_Z2_B: u32 = 0x4482_0020;
    for word in HALF_NUMERICAL_WORDS {
        assert!(dot::decode(word).unwrap().is_ok());
        assert_eq!(crate::aarch64::sve::decode(word), None);
        assert!(
            compile_for_profile(
                &words(&[word, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline,
            )
            .is_err()
        );
    }
    assert!(
        compile_for_profile(
            &words(&[MOVPRFX_Z0_Z1, SDOT_Z0_S_Z1_B_Z2_B, RET_X30]),
            GuestAddress(0),
            profile(32, true),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .0
        .contains("MOVPRFX pair validation")
    );
}

#[test]
fn mixed_signedness_dot_requires_an_explicit_guest_i8mm_profile() {
    const MIXED_SIGNEDNESS_WORDS: [u32; 3] = [0x44a0_1c00, 0x4480_7800, 0x44a0_1800];
    for word in MIXED_SIGNEDNESS_WORDS {
        assert!(dot::decode_integer(word).unwrap().unwrap().requires_i8mm());
        for bytes in [16, 32, 64, 128, 256] {
            for za in [false, true] {
                for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                    let profile = ScalableProfile::new(
                        VectorLength::from_bytes(bytes).unwrap(),
                        ScalableMode::new(true, za),
                    );
                    assert!(
                        compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0),
                            profile,
                            target,
                        )
                        .unwrap_err()
                        .0
                        .contains("guest I8MM is outside the streaming profile")
                    );
                }
            }
        }
    }
}
