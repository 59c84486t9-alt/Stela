use super::*;
use alloc::vec::Vec;

#[test]
fn schedule_gathers_require_ssse3_independently_of_sha() {
    for target in [
        TargetCpu::Baseline,
        TargetCpu::Ssse3,
        TargetCpu::Sha,
        TargetCpu::Ssse3.with_sha(),
    ] {
        for kind in [Kind::Schedule0, Kind::Schedule1] {
            let operand = Operand {
                kind,
                destination: 31,
                left: 31,
                right: 31,
            };
            let mut code = Vec::new();
            emit(&mut code, &operand, target);
            let alignment = Host::AlignBytes.encoding();
            let used = code
                .windows(alignment.len())
                .any(|bytes| bytes == alignment);
            let expected = target.supports(TargetCpu::Ssse3)
                && (kind == Kind::Schedule1 || !target.supports(TargetCpu::Sha));
            assert_eq!(used, expected);
        }
    }
}

#[test]
fn checked_hash_uses_two_round_pairs_with_explicit_implicit_input_staging() {
    for kind in [Kind::Hash, Kind::Hash2] {
        let operand = Operand {
            kind,
            destination: 31,
            left: 31,
            right: 31,
        };
        let mut code = Vec::new();
        emit(&mut code, &operand, TargetCpu::Sha);
        assert_eq!(
            code.windows(3).filter(|w| *w == [0x0f, 0x38, 0xcb]).count(),
            2
        );
        let mut baseline = Vec::new();
        emit(&mut baseline, &operand, TargetCpu::Baseline);
        assert!(!baseline.windows(3).any(|w| w == [0x0f, 0x38, 0xcb]));
        // Full-width saves/restores cover every callee-saved GPR used.
        for (xmm, register) in [(SAVED_RBX, EBX), (SAVED_RBP, EBP), (SAVED_R12, R12D)] {
            for opcode in [MOVQ_XMM_RM64, MOVQ_RM64_XMM] {
                let expected = [
                    PACKED_PREFIX,
                    REX_W | (register >> EXTENDED_REGISTER_SHIFT),
                    opcode[0],
                    opcode[1],
                    MODRM_REGISTER | (xmm << MODRM_REGISTER_SHIFT) | (register & LOW_REGISTER_MASK),
                ];
                assert!(baseline.windows(expected.len()).any(|w| w == expected));
            }
        }
    }
}
