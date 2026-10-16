use super::*;
use alloc::vec::Vec;

#[test]
fn avx2_shift_encodings_keep_data_count_and_destination_fields_distinct() {
    for (opcode, operation, width) in [
        (VexShiftOpcode::LeftDword, 0x47, 0),
        (VexShiftOpcode::RightDword, 0x45, 0),
        (VexShiftOpcode::ArithmeticDword, 0x46, 0),
        (VexShiftOpcode::LeftQword, 0x47, 0x80),
        (VexShiftOpcode::RightQword, 0x45, 0x80),
    ] {
        let mut code = Vec::new();
        opcode.register(&mut code, 3, 6, 7, TargetCpu::Avx2);
        assert_eq!(code, [0xc4, 0xe2, width | 0x49, operation, 0xdf]);
        for target in [TargetCpu::Baseline, TargetCpu::Sse42, TargetCpu::Fma] {
            code.clear();
            let declined = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                opcode.register(&mut code, 0, 0, 1, target);
            }));
            assert!(declined.is_err());
            assert!(code.is_empty());
        }
    }
}

#[test]
fn word_to_qword_widening_requires_checked_sse41() {
    for (opcode, mnemonic, encoding) in [
        (
            SimdOpcode::SignExtendWordToQword,
            "pmovsxwq",
            [0x66, 0x0f, 0x38, 0x24],
        ),
        (
            SimdOpcode::ZeroExtendWordToQword,
            "pmovzxwq",
            [0x66, 0x0f, 0x38, 0x34],
        ),
    ] {
        assert_eq!(opcode.mnemonic(), mnemonic);
        assert_eq!(opcode.encoding(), encoding);
        assert_eq!(opcode.requires(), TargetCpu::Sse41);
        for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
            let mut code = Vec::new();
            let declined = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                opcode.append(&mut code, target)
            }));
            assert!(declined.is_err());
            assert!(code.is_empty());
        }
        for target in [TargetCpu::Sse41, TargetCpu::Sse42] {
            let mut code = Vec::new();
            opcode.append(&mut code, target);
            assert_eq!(code, encoding);
        }
    }
}

#[test]
fn signed_byte_widening_requires_checked_sse41() {
    let opcode = SimdOpcode::SignExtendByteToWord;
    let encoding = [0x66, 0x0f, 0x38, 0x20];
    assert_eq!(opcode.mnemonic(), "pmovsxbw");
    assert_eq!(opcode.encoding(), encoding);
    assert_eq!(opcode.requires(), TargetCpu::Sse41);
    for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
        let mut code = Vec::new();
        let declined = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            opcode.append(&mut code, target);
        }));
        assert!(declined.is_err());
        assert!(code.is_empty());
    }
    for target in [TargetCpu::Sse41, TargetCpu::Sse42] {
        let mut code = Vec::new();
        opcode.append(&mut code, target);
        assert_eq!(code, encoding);
    }
}
