use super::*;

mod field;

#[test]
fn booleans_preserve_all_predicate_register_roles_and_flags() {
    for opcode in [AND, BIC, EOR, NAND, NOR, ORN, ORR] {
        for flags in [false, true] {
            for register in 0..=PREDICATE_MASK {
                let word = opcode
                    | if flags { FLAGS_BIT } else { 0 }
                    | register
                    | (register << SOURCE_SHIFT)
                    | (register << RIGHT_SHIFT)
                    | (register << GOVERNOR_SHIFT);
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(operand.destination, register as u8);
                assert!(
                    matches!(operand.kind, Kind::Boolean { flags: actual, governor, left, right, .. }
                    if actual == flags && governor == register as u8 && left == register as u8 && right == register as u8)
                );
            }
        }
    }
}

#[test]
fn counter_pair_allows_wrapping_destination_and_aliases() {
    let word = PEXT_PAIR | (3 << SIZE_SHIFT) | (7 << SOURCE_SHIFT) | (1 << PEXT_PART_SHIFT) | 15;
    assert_eq!(
        decode(word),
        Some(Ok(Operand {
            destination: 15,
            kind: Kind::ExtractCounter {
                element: ElementSize::Doubleword,
                source: 15,
                part: 1,
                pair: true
            }
        }))
    );
}

#[test]
fn indexed_select_rejects_only_zero_size_encoding() {
    for encoded in 0u32..32 {
        let word = PSEL
            | ((encoded >> 4) << PSEL_IMMEDIATE_HIGH_SHIFT)
            | (((encoded >> 3) & 1) << PSEL_SIZE_HIGH_SHIFT)
            | ((encoded & 7) << PSEL_SIZE_LOW_SHIFT);
        assert_eq!(decode(word).unwrap().is_err(), encoded & 15 == 0);
    }
    assert_eq!(decode(0), None);
}
