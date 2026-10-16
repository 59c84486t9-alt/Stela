use super::*;

#[test]
fn widths_aliases_and_reserved_size_are_distinct() {
    for opcode in [ABSOLUTE_OPCODE, NEGATE_OPCODE] {
        for (size, format) in [
            (HALF_SIZE, Format::Half),
            (SINGLE_SIZE, Format::Single),
            (DOUBLE_SIZE, Format::Double),
        ] {
            let word =
                opcode | (size << SIZE_SHIFT) | (31 << SOURCE_SHIFT) | (7 << PREDICATE_SHIFT) | 31;
            let operand = decode(word).unwrap().unwrap();
            assert_eq!(operand.format, format);
            assert_eq!(
                (operand.source, operand.destination, operand.predicate),
                (31, 31, 7)
            );
        }
        assert_eq!(decode(opcode), Some(Err(())));
    }
    assert_eq!(decode(0x6580_8000), None);
}
