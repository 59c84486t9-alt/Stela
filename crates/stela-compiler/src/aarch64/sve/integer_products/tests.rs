use super::*;

#[test]
fn predicated_mad_keeps_destination_as_multiplicand_and_za_as_accumulator() {
    let destination = 31;
    let multiplier = 23;
    let accumulator = 19;
    let predicate = 7;
    let word = MAD_Z_P_ZZZ
        | (2 << SIZE_SHIFT)
        | (multiplier << MULTIPLIER_SHIFT)
        | (predicate << PREDICATE_SHIFT)
        | (accumulator << SOURCE_SHIFT)
        | destination;
    assert_eq!(
        decode(word),
        Some(Ok(Operand {
            kind: Kind::Accumulate { subtract: false },
            destination: destination as u8,
            source: destination as u8,
            multiplier: Multiplier::Vector {
                register: multiplier as u8,
                segment_lane: None
            },
            accumulator: Some(accumulator as u8),
            element_size: ElementSize::Word,
            predication: Predication::Merging(predicate as u8),
            rotation_degrees: 0,
        }))
    );
}

#[test]
fn indexed_halfword_and_long_fields_have_distinct_bit_splits() {
    for index in 0..8 {
        for multiplier in 0..8 {
            let normal = MUL_Z_ZZI_H
                | ((index >> 2) << INDEX_HIGH_SHIFT)
                | ((index & INDEX_TWO_BITS) << INDEX_LOW_SHIFT)
                | (multiplier << MULTIPLIER_SHIFT);
            let long = SMULLT_Z_ZZI_S
                | ((index >> 1) << INDEX_LOW_SHIFT)
                | ((index & INDEX_ONE_BIT) << INDEX_LONG_LOW_SHIFT)
                | (multiplier << MULTIPLIER_SHIFT);
            for (word, element) in [(normal, ElementSize::Halfword), (long, ElementSize::Word)] {
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(operand.element_size, element);
                assert_eq!(
                    operand.multiplier,
                    Multiplier::Vector {
                        register: multiplier as u8,
                        segment_lane: Some(index as u8),
                    }
                );
            }
        }
    }
}

#[test]
fn long_byte_allocations_decline_and_cross_selector_is_explicit() {
    for opcode in [
        SMULLB_Z_ZZ,
        SMULLT_Z_ZZ,
        UMULLB_Z_ZZ,
        UMULLT_Z_ZZ,
        SMLALB_Z_ZZZ,
        SMLALT_Z_ZZZ,
        SQDMLALBT_Z_ZZZ,
        SQDMLSLBT_Z_ZZZ,
        SQDMULLB_Z_ZZ,
        SQDMULLT_Z_ZZ,
    ] {
        assert_eq!(decode(opcode), Some(Err(())));
    }
    let cross = decode(SQDMLALBT_Z_ZZZ | (1 << SIZE_SHIFT))
        .unwrap()
        .unwrap();
    assert_eq!(
        cross.kind,
        Kind::Long {
            signed: true,
            doubling: true,
            accumulate: Accumulate::Add,
            selection: Selection::Cross
        }
    );
}

#[test]
fn signed_immediate_and_complex_rotation_preserve_operand_roles() {
    let immediate = decode(MUL_Z_ZI | (IMMEDIATE_MASK << SOURCE_SHIFT) | REGISTER_MASK)
        .unwrap()
        .unwrap();
    assert_eq!(immediate.multiplier, Multiplier::Immediate(-1));
    assert_eq!(immediate.source, 31);
    for rotation in 0..=ROTATION_MASK {
        let complex = decode(CMLA_Z_ZZZ | (rotation << ROTATION_SHIFT))
            .unwrap()
            .unwrap();
        assert_eq!(
            complex.rotation_degrees,
            rotation as u16 * QUARTER_TURN_DEGREES
        );
        assert_eq!(complex.accumulator, Some(complex.destination));
    }
    assert_eq!(decode(0), None);
}
