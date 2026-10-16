use super::*;

#[test]
fn basic_allocations_include_all_patterns_and_predicate_registers() {
    for destination in 0..=PREDICATE_MASK {
        assert_eq!(
            decode_basic(PFALSE_CLASS | destination),
            Some(Ok(BasicOperand::False {
                destination: destination as u8
            }))
        );
        for size in 0..=SIZE_MASK {
            let element = ElementSize::from_bytes(1 << size).unwrap();
            for pattern in 0..=PATTERN_MASK {
                for (class, set_flags) in [(PTRUE_CLASS, false), (PTRUES_CLASS, true)] {
                    assert_eq!(
                        decode_basic(
                            class
                                | destination
                                | size << SIZE_SHIFT
                                | pattern << FIRST_SOURCE_SHIFT
                        ),
                        Some(Ok(BasicOperand::True {
                            destination: destination as u8,
                            element,
                            pattern: pattern as u8,
                            set_flags
                        }))
                    );
                }
            }
            for governing in 0..=PREDICATE_MASK {
                assert_eq!(
                    decode_basic(
                        PNEXT_CLASS
                            | destination
                            | governing << FIRST_SOURCE_SHIFT
                            | size << SIZE_SHIFT
                    ),
                    Some(Ok(BasicOperand::Next {
                        destination: destination as u8,
                        governing: governing as u8,
                        element
                    }))
                );
            }
        }
    }
}

#[test]
fn counter_aliases_and_scalar_zero_width_are_explicit() {
    for destination in 0..=PN_MASK {
        for size in 0..=SIZE_MASK {
            assert_eq!(
                decode_basic(PTRUE_PN_CLASS | destination | size << SIZE_SHIFT),
                Some(Ok(BasicOperand::TrueCounter {
                    destination: PN_BASE + destination as u8,
                    element: ElementSize::from_bytes(1 << size).unwrap()
                }))
            );
        }
    }
    for (class, equal) in [(CTERMEQ_CLASS, true), (CTERMNE_CLASS, false)] {
        for first in 0..=SCALAR_REGISTER_MASK {
            for second in 0..=SCALAR_REGISTER_MASK {
                for (size, width) in [(0, Width::W32), (1, Width::X64)] {
                    assert_eq!(
                        decode_basic(
                            class
                                | first << FIRST_SOURCE_SHIFT
                                | second << SECOND_SOURCE_SHIFT
                                | size << SIZE_SHIFT
                        ),
                        Some(Ok(BasicOperand::ConditionalTerminate {
                            first: register(first, false),
                            second: register(second, false),
                            width,
                            equal
                        }))
                    );
                }
            }
        }
    }
    assert!(decode_basic(PFALSE_CLASS ^ (1 << 4)).is_none());
}
