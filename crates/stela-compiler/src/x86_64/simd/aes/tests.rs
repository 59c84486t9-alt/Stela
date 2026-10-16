use super::*;
use alloc::vec;
use alloc::vec::Vec;

fn occurrences(code: &[u8], opcode: Host) -> usize {
    code.windows(opcode.encoding().len())
        .filter(|window| *window == opcode.encoding())
        .count()
}

#[test]
fn independent_aes_target_uses_only_the_reviewed_legacy_recipes() {
    for (kind, expected, bytes) in [
        (Kind::Encrypt, vec![Host::AesEncryptLast], 37),
        (Kind::Decrypt, vec![Host::AesDecryptLast], 37),
        (
            Kind::MixColumns,
            vec![Host::AesDecryptLast, Host::AesEncryptRound],
            30,
        ),
        (
            Kind::InverseMixColumns,
            vec![Host::AesInverseMixColumns],
            21,
        ),
    ] {
        let operand = Operand {
            kind,
            destination: 31,
            source: 31,
        };
        let mut code = Vec::new();
        emit(&mut code, &operand, TargetCpu::Aes);
        assert_eq!(code.len(), bytes); // Complete body, excludes harness RET.
        for opcode in [
            Host::AesEncryptLast,
            Host::AesDecryptLast,
            Host::AesEncryptRound,
            Host::AesDecryptRound,
            Host::AesInverseMixColumns,
        ] {
            assert_eq!(
                occurrences(&code, opcode),
                usize::from(expected.contains(&opcode))
            );
        }
        assert_eq!(occurrences(&code, Host::ByteShuffle), 0);
    }
}

#[test]
fn baseline_excludes_aes_and_ssse3_even_for_aliases() {
    for kind in [
        Kind::Encrypt,
        Kind::Decrypt,
        Kind::MixColumns,
        Kind::InverseMixColumns,
    ] {
        let mut code = Vec::new();
        emit(
            &mut code,
            &Operand {
                kind,
                destination: 31,
                source: 31,
            },
            TargetCpu::Baseline,
        );
        for opcode in [
            Host::AesEncryptLast,
            Host::AesDecryptLast,
            Host::AesEncryptRound,
            Host::AesDecryptRound,
            Host::AesInverseMixColumns,
            Host::ByteShuffle,
        ] {
            assert_eq!(occurrences(&code, opcode), 0);
        }
    }
}
