use super::*;

#[test]
fn destructive_predicated_binary_reads_destination_and_separate_right() {
    for base in [
        0x65008000, 0x65018000, 0x65028000, 0x65068000, 0x65048000, 0x65078000, 0x65058000,
    ] {
        for destination in 0..32 {
            for right in 0..32 {
                for predicate in 0..8 {
                    let operand = decode(
                        base | destination | (right << LEFT_SHIFT) | (predicate << PREDICATE_SHIFT),
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(operand.destination, destination as u8);
                    assert_eq!(operand.left, destination as u8);
                    assert_eq!(operand.right, RightOperand::Vector(right as u8));
                    assert_eq!(operand.predicate, Some(predicate as u8));
                }
            }
        }
    }
}

#[test]
fn predicated_multiply_add_has_three_independent_sources() {
    let operand =
        decode(0x65200000 | 31 | (30 << LEFT_SHIFT) | (29 << RIGHT_SHIFT) | (7 << PREDICATE_SHIFT))
            .unwrap()
            .unwrap();
    assert_eq!(operand.destination, 31);
    assert_eq!(operand.left, 30);
    assert_eq!(operand.right, RightOperand::Vector(29));
    assert_eq!(operand.predicate, Some(7));
    assert_eq!(operand.kind, Kind::MultiplyAdd { subtract: false });
}

#[test]
fn arithmetic_and_widening_split_half_indices_use_different_fields() {
    for index in 0..8 {
        let arithmetic = decode(
            0x64200800
                | ((index >> 2) << HALF_INDEX_HIGH_SHIFT)
                | ((index & INDEX_HIGH_MASK) << INDEX_HIGH_SHIFT)
                | (7 << RIGHT_SHIFT),
        )
        .unwrap()
        .unwrap();
        let widening = decode(
            0x64e04000
                | ((index >> 1) << INDEX_HIGH_SHIFT)
                | ((index & INDEX_BIT_MASK) << HALF_INDEX_LOW_SHIFT)
                | (7 << RIGHT_SHIFT),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            arithmetic.right,
            RightOperand::Indexed {
                register: 7,
                index: index as u8
            }
        );
        assert_eq!(widening.right, arithmetic.right);
        assert_eq!(arithmetic.kind.output_bits(), 16);
        assert_eq!(widening.kind.output_bits(), 32);
        assert!(arithmetic.kind.is_b16b16());
        assert!(!widening.kind.is_b16b16());
    }
}

#[test]
fn dot_pair_indices_are_not_scalar_half_indices() {
    for index in 0..4 {
        let operand = decode(0x64604000 | (index << INDEX_HIGH_SHIFT) | (7 << RIGHT_SHIFT))
            .unwrap()
            .unwrap();
        assert_eq!(operand.kind, Kind::Dot);
        assert_eq!(
            operand.right,
            RightOperand::Indexed {
                register: 7,
                index: index as u8
            }
        );
        assert_eq!(operand.predicate, None);
    }
    // BFCVT belongs to the conversion decoder, not this family.
    assert_eq!(decode(0x658aa000), None);
}
