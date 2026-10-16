use super::*;

mod prefix;

const FIRST_SIZE: u32 = 1;
const WORD_SIZE: u32 = 2;
const DOUBLEWORD_SIZE: u32 = 3;
const ENCODINGS: [(u32, u32); 25] = [
    (SUNPKLO, FIRST_SIZE),
    (SUNPKHI, FIRST_SIZE),
    (UUNPKLO, FIRST_SIZE),
    (UUNPKHI, FIRST_SIZE),
    (SXTB, FIRST_SIZE),
    (UXTB, FIRST_SIZE),
    (SXTH, WORD_SIZE),
    (UXTH, WORD_SIZE),
    (SXTW, DOUBLEWORD_SIZE),
    (UXTW, DOUBLEWORD_SIZE),
    (SADALP, FIRST_SIZE),
    (UADALP, FIRST_SIZE),
    (ADDP, 0),
    (SMAXP, 0),
    (UMAXP, 0),
    (SMINP, 0),
    (UMINP, 0),
    (ADDHNB, FIRST_SIZE),
    (ADDHNT, FIRST_SIZE),
    (RADDHNB, FIRST_SIZE),
    (RADDHNT, FIRST_SIZE),
    (SUBHNB, FIRST_SIZE),
    (SUBHNT, FIRST_SIZE),
    (RSUBHNB, FIRST_SIZE),
    (RSUBHNT, FIRST_SIZE),
];

#[test]
fn size_allocations_are_complete_and_reserved_sizes_decline() {
    for (encoding, minimum_size) in ENCODINGS {
        for size in 0..=SIZE_MASK {
            let result = decode(encoding | size << SIZE_SHIFT).unwrap();
            assert_eq!(result.is_ok(), size >= minimum_size);
            if let Ok(operand) = result {
                assert_eq!(operand.element_size.bytes(), 1 << size);
            }
        }
    }
}

#[test]
fn all_vector_registers_and_governing_predicates_decode() {
    for (encoding, minimum_size) in ENCODINGS {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                for predicate in 0..=PREDICATE_MASK {
                    let template = decode(encoding | minimum_size << SIZE_SHIFT)
                        .unwrap()
                        .unwrap();
                    let narrow = matches!(template.kind, Kind::NarrowHigh { .. });
                    let predicated = matches!(template.predication, Predication::Merging(_));
                    let right = REGISTER_MASK - source;
                    let word = encoding
                        | minimum_size << SIZE_SHIFT
                        | destination
                        | source << SOURCE_SHIFT
                        | if narrow { right << RIGHT_SHIFT } else { 0 }
                        | if predicated {
                            predicate << PREDICATE_SHIFT
                        } else {
                            0
                        };
                    let operand = decode(word).unwrap().unwrap();
                    assert_eq!(operand.destination, destination as u8);
                    assert_eq!(
                        operand.predication,
                        if predicated {
                            Predication::Merging(predicate as u8)
                        } else {
                            Predication::Unpredicated
                        }
                    );
                    match operand.kind {
                        Kind::Unpack { source: actual, .. }
                        | Kind::Extend { source: actual, .. }
                        | Kind::PairAccumulate { source: actual, .. } => {
                            assert_eq!(actual, source as u8);
                        }
                        Kind::Pair { right: actual, .. } => assert_eq!(actual, source as u8),
                        Kind::NarrowHigh {
                            left: actual_left,
                            right: actual_right,
                            ..
                        } => {
                            assert_eq!(actual_left, source as u8);
                            assert_eq!(actual_right, right as u8);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn distinct_families_and_zeroing_extension_forms_are_not_claimed() {
    const ZEROING_EXTENSION_BIT: u32 = 1 << 20;
    assert!(decode(0).is_none());
    for encoding in [SXTB, UXTB, SXTH, UXTH, SXTW, UXTW] {
        assert!(
            decode((encoding & !ZEROING_EXTENSION_BIT) | DOUBLEWORD_SIZE << SIZE_SHIFT).is_none()
        );
    }
}
