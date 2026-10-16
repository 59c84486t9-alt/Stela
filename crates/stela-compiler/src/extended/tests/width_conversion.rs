use super::*;
use crate::aarch64::sve::shifts_narrow;

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
