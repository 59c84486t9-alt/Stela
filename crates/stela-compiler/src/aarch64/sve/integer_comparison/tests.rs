use super::*;

#[test]
fn canonical_fields_and_reserved_wide_doubleword() {
    for encoding in ENCODINGS {
        for size in 0..=SIZE_MASK {
            for left in 0..=Z_REGISTER_MASK {
                for right in 0..=Z_REGISTER_MASK {
                    for governing in [0, GOVERNING_REGISTER_MASK] {
                        for destination in [0, P_REGISTER_MASK] {
                            let word = encoding.value
                                | size << SIZE_SHIFT
                                | left << SOURCE_SHIFT
                                | right << RIGHT_SHIFT
                                | governing << GOVERNING_SHIFT
                                | destination;
                            let operand = decode(word);
                            if encoding.source == SourceKind::WideVector && size == SIZE_MASK {
                                assert_eq!(operand, Some(Err(())));
                            } else {
                                let operand = operand.unwrap().unwrap();
                                assert_eq!(operand.relation, encoding.relation);
                                assert_eq!(operand.unsigned, encoding.unsigned);
                                assert_eq!(operand.element_size.bytes(), 1 << size);
                                assert_eq!(operand.left, left as u8);
                                assert_eq!(operand.governing, governing as u8);
                                assert_eq!(operand.destination, destination as u8);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn immediate_widths_and_sign_extension() {
    for encoding in ENCODINGS
        .iter()
        .filter(|entry| entry.source == SourceKind::Immediate)
    {
        let maximum = if encoding.unsigned {
            UNSIGNED_IMMEDIATE_MASK
        } else {
            SIGNED_IMMEDIATE_MASK
        };
        for bits in 0..=maximum {
            let shift = if encoding.unsigned {
                UNSIGNED_IMMEDIATE_SHIFT
            } else {
                RIGHT_SHIFT
            };
            let operand = decode(encoding.value | bits << shift).unwrap().unwrap();
            let value = if !encoding.unsigned && bits >= SIGNED_IMMEDIATE_SIGN as u32 {
                bits as i16 - SIGNED_IMMEDIATE_MODULUS
            } else {
                bits as i16
            };
            assert_eq!(operand.right, Right::Immediate(value));
        }
    }
}

#[test]
fn non_family_words_decline() {
    for word in [0, u32::MAX, 0x2400_8000 ^ 1 << 29] {
        assert_eq!(decode(word), None);
    }
}
