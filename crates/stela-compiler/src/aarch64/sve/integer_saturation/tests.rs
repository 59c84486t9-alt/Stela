use super::*;

mod prefix_requirement;

#[test]
fn saturation_preserves_register_aliases_and_all_element_widths() {
    for opcode in [SQADD_Z_ZZ, UQADD_Z_ZZ, SQSUB_Z_ZZ, UQSUB_Z_ZZ] {
        for size in 0..=SIZE_MASK {
            for destination in 0..=REGISTER_MASK {
                for source in 0..=REGISTER_MASK {
                    for right in 0..=REGISTER_MASK {
                        let word = opcode
                            | (size << SIZE_SHIFT)
                            | destination
                            | (source << SOURCE_SHIFT)
                            | (right << RIGHT_SHIFT);
                        let operand = decode(word).unwrap().unwrap();
                        assert_eq!(operand.destination, destination as u8);
                        assert_eq!(operand.left, source as u8);
                        assert_eq!(operand.right, Input::Vector(right as u8));
                        assert_eq!(operand.element_size.bytes(), 1 << size);
                        assert_eq!(operand.predication, Predication::Unpredicated);
                    }
                }
            }
        }
    }
}

#[test]
fn predication_uses_low_eight_predicates_and_destructive_destination() {
    for predicate in 0..=PREDICATE_MASK {
        let operand =
            decode(SUQADD_Z_P_ZZ | (predicate << PREDICATE_SHIFT) | (31 << SOURCE_SHIFT) | 31)
                .unwrap()
                .unwrap();
        assert_eq!(operand.destination, 31);
        assert_eq!(operand.left, 31);
        assert_eq!(operand.right, Input::Vector(31));
        assert_eq!(operand.predication, Predication::Merging(predicate as u8));
        assert_eq!(
            operand.kind,
            Kind::MixedSaturatingAdd {
                signed_destination: true
            }
        );
    }
}

#[test]
fn immediate_scaling_and_widening_reserved_sizes_are_explicit() {
    for opcode in [SQADD_Z_ZI, UQADD_Z_ZI, SQSUB_Z_ZI, UQSUB_Z_ZI] {
        assert_eq!(decode(opcode | IMMEDIATE_SCALE_FLAG), Some(Err(())));
        for size in 1..=SIZE_MASK {
            let operand = decode(
                opcode
                    | (size << SIZE_SHIFT)
                    | IMMEDIATE_SCALE_FLAG
                    | (IMMEDIATE_MASK << SOURCE_SHIFT),
            )
            .unwrap()
            .unwrap();
            assert_eq!(operand.right, Input::Immediate(u16::MAX - 255));
        }
    }
    for opcode in [
        SABDLB_Z_ZZ,
        SABDLT_Z_ZZ,
        UABDLB_Z_ZZ,
        UABDLT_Z_ZZ,
        SABALB_Z_ZZZ,
        SABALT_Z_ZZZ,
        UABALB_Z_ZZZ,
        UABALT_Z_ZZZ,
    ] {
        assert_eq!(decode(opcode), Some(Err(())));
        for size in 1..=SIZE_MASK {
            assert!(decode(opcode | (size << SIZE_SHIFT)).unwrap().is_ok());
        }
    }
}

#[test]
fn complex_rotation_and_noninventory_zeroing_are_distinct() {
    for rotate_270 in [false, true] {
        let word = SQCADD_Z_ZZ | if rotate_270 { COMPLEX_ROTATION_FLAG } else { 0 };
        assert_eq!(
            decode(word).unwrap().unwrap().kind,
            Kind::ComplexAdd { rotate_270 }
        );
    }
    const SQABS_ZEROING: u32 = 0x440a_a000;
    const SQNEG_ZEROING: u32 = 0x440b_a000;
    assert!(decode(SQABS_ZEROING).is_none());
    assert!(decode(SQNEG_ZEROING).is_none());
    assert!(decode(0).is_none());
}
