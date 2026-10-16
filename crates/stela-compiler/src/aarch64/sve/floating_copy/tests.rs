use super::*;

#[test]
fn immediate_full_range_and_high_predicate_fields() {
    for (size, format) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
        for immediate in 0..=IMMEDIATE_MASK {
            for governing in 0..=COPY_GOVERNING_MASK {
                let word = FCPY
                    | (size << SIZE_SHIFT)
                    | (governing << COPY_GOVERNING_SHIFT)
                    | (immediate << IMMEDIATE_SHIFT)
                    | REGISTER_MASK;
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(operand.format, format);
                assert_eq!(operand.value, expand_immediate(format, immediate as u8));
                assert_eq!(operand.governing, Some(governing as u8));
            }
            let word = FDUP | (size << SIZE_SHIFT) | (immediate << IMMEDIATE_SHIFT);
            assert_eq!(decode(word).unwrap().unwrap().governing, None);
        }
    }
    assert_eq!(decode(FCPY), Some(Err(())));
    assert_eq!(decode(FDUP), Some(Err(())));
    // VFP imm8 0x70 is exactly +1.0 in every destination format.
    assert_eq!(expand_immediate(Format::Half, 0x70), 0x3c00);
    assert_eq!(expand_immediate(Format::Single, 0x70), 0x3f80_0000);
    assert_eq!(
        expand_immediate(Format::Double, 0x70),
        0x3ff0_0000_0000_0000
    );
}
