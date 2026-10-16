use super::*;

#[test]
fn all_operations_widths_predicates_and_vector_aliases() {
    for opcode in [FRINTN, FRINTP, FRINTM, FRINTZ, FRINTA, FRINTX, FRINTI] {
        assert_eq!(decode(opcode), Some(Err(())));
        for (size, format) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
            for governing in 0..=GOVERNING_MASK {
                for register in 0..=REGISTER_MASK {
                    let word = opcode
                        | (size << SIZE_SHIFT)
                        | (governing << GOVERNING_SHIFT)
                        | (register << SOURCE_SHIFT)
                        | register;
                    let operand = decode(word).unwrap().unwrap();
                    assert_eq!(operand.format, format);
                    assert_eq!(operand.governing, governing as u8);
                    assert_eq!(operand.source, register as u8);
                    assert_eq!(operand.destination, register as u8);
                }
            }
        }
    }
    assert_eq!(decode(0), None);
}
