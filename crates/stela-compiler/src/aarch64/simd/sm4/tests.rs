use super::*;
#[test]
fn two_operand_encryption_and_three_operand_keys_preserve_all_register_roles() {
    for destination in 0..32 {
        for left in 0..32 {
            assert_eq!(
                decode(0xcec08400 | destination | (left << 5)),
                Some(Ok(Operand {
                    kind: Kind::Encrypt,
                    destination: destination as u8,
                    input: destination as u8,
                    keys: left as u8
                }))
            );
            for right in 0..32 {
                assert_eq!(
                    decode(0xce60c800 | destination | (left << 5) | (right << 16)),
                    Some(Ok(Operand {
                        kind: Kind::ExpandKey,
                        destination: destination as u8,
                        input: left as u8,
                        keys: right as u8
                    }))
                );
            }
        }
    }
    for word in [0xce60c000, 0xce60c400, 0xcec08000, 0xce60cc00, 0x4520e000] {
        assert!(decode(word).is_none());
    }
}
