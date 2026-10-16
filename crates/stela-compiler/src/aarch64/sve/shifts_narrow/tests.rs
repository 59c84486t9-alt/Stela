use super::*;

#[test]
fn all_size_and_immediate_allocations_are_explicit() {
    for encoding in ENCODINGS {
        for tsize in 0..8u32 {
            let immediate_values = if encoding.kind.is_extract() { 1 } else { 8 };
            for immediate in 0..immediate_values {
                let word = encoding.value
                    | ((tsize >> TSIZE_HIGH_OFFSET) << TSIZE_HIGH_SHIFT)
                    | ((tsize & TSIZE_LOW_MASK) << TSIZE_LOW_SHIFT)
                    | (immediate << IMMEDIATE_SHIFT);
                let result = decode(word).expect("owned encoding");
                if tsize == 0 || (encoding.kind.is_extract() && !tsize.is_power_of_two()) {
                    assert_eq!(result, Err(()));
                    continue;
                }
                let operand = result.unwrap();
                assert_eq!(operand.kind, encoding.kind);
                assert_eq!(operand.part, encoding.part);
                let bits = operand.element_size.bits() as u8;
                if encoding.kind.is_extract() {
                    assert_eq!(operand.shift, 0);
                } else if encoding.kind.is_widening() {
                    assert!(operand.shift < bits);
                } else {
                    assert!((1..=bits).contains(&operand.shift));
                }
            }
        }
    }
}

#[test]
fn all_z_register_aliases_decode() {
    for encoding in ENCODINGS {
        for source in 0..=REGISTER_MASK {
            for destination in 0..=REGISTER_MASK {
                let word = encoding.value
                    | (1 << TSIZE_LOW_SHIFT)
                    | (source << SOURCE_SHIFT)
                    | destination;
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(u32::from(operand.source), source);
                assert_eq!(u32::from(operand.destination), destination);
            }
        }
    }
    assert_eq!(decode(0), None);
}
