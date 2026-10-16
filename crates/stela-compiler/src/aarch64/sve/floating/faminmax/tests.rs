use super::*;

#[test]
fn all_widths_predicates_aliases_and_fixed_bits() {
    for (opcode, operation) in [
        (FAMAX, AbsoluteMinMaxOperation::Maximum),
        (FAMIN, AbsoluteMinMaxOperation::Minimum),
    ] {
        assert_eq!(decode(opcode), Some(Err(())));
        for (size, format) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
            for governing in 0..=GOVERNING_MASK {
                for destination in 0..=REGISTER_MASK {
                    for right in [0, destination, REGISTER_MASK] {
                        let word = opcode
                            | (size << SIZE_SHIFT)
                            | (governing << GOVERNING_SHIFT)
                            | (right << RIGHT_SHIFT)
                            | destination;
                        assert_eq!(
                            decode(word),
                            Some(Ok(Operand {
                                operation,
                                format,
                                destination: destination as u8,
                                governing: governing as u8,
                                right: right as u8,
                            }))
                        );
                    }
                }
            }
        }
        for bit in 0..32 {
            if FORM_MASK & (1 << bit) != 0 && bit != 16 {
                assert_eq!(decode(opcode ^ (1 << bit)), None);
            }
        }
    }
}
