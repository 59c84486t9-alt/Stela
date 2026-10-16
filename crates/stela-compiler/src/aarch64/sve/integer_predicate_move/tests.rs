use super::*;

#[test]
fn all_registers_and_portions_decode_without_crossing_classes() {
    for (base, element) in [
        (BYTE, ElementSize::Byte),
        (HALFWORD, ElementSize::Halfword),
        (WORD, ElementSize::Word),
        (DOUBLEWORD, ElementSize::Doubleword),
    ] {
        for portion in 0..element.bytes() {
            let encoded_portion = ((portion as u32 & 3) << PORTION_LOW_SHIFT)
                | ((portion as u32 >> 2) << PORTION_HIGH_SHIFT);
            for predicate in 0..=PREDICATE_MASK {
                for destination in 0..=DESTINATION_MASK {
                    let word =
                        base | encoded_portion | (predicate << PREDICATE_SHIFT) | destination;
                    assert_eq!(
                        decode(word),
                        Some(Ok(Operand {
                            destination: destination as u8,
                            predicate: predicate as u8,
                            element_size: element,
                            portion: portion as u8,
                        }))
                    );
                    assert_eq!(decode(word ^ (1 << 9)), None);
                }
            }
        }
    }
}
