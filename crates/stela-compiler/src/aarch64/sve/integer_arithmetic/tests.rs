use super::*;

mod prefix_requirement;

#[test]
fn canonical_forms_validate_widths_predicates_and_register_roles() {
    let forms = [
        (ABS_Z_P_Z_M, true, false, false, false),
        (ADCLB_Z_ZZZ, false, true, false, false),
        (ADCLT_Z_ZZZ, false, true, false, false),
        (ADD_Z_P_ZZ, true, false, false, false),
        (ADD_Z_ZI, false, false, false, false),
        (ADD_Z_ZZ, false, false, false, false),
        (CADD_Z_ZZ, false, false, false, false),
        (NEG_Z_P_Z_M, true, false, false, false),
        (SADDLB_Z_ZZ, false, false, true, false),
        (SADDLBT_Z_ZZ, false, false, true, false),
        (SADDLT_Z_ZZ, false, false, true, false),
        (SADDWB_Z_ZZ, false, false, true, false),
        (SADDWT_Z_ZZ, false, false, true, false),
        (SBCLB_Z_ZZZ, false, true, false, false),
        (SBCLT_Z_ZZZ, false, true, false, false),
        (SCLAMP_Z_ZZ, false, false, false, false),
        (SDIV_Z_P_ZZ, true, false, false, true),
        (SDIVR_Z_P_ZZ, true, false, false, true),
        (SMAX_Z_P_ZZ, true, false, false, false),
        (SMAX_Z_ZI, false, false, false, false),
        (SMIN_Z_P_ZZ, true, false, false, false),
        (SMIN_Z_ZI, false, false, false, false),
        (SSUBLB_Z_ZZ, false, false, true, false),
        (SSUBLBT_Z_ZZ, false, false, true, false),
        (SSUBLT_Z_ZZ, false, false, true, false),
        (SSUBLTB_Z_ZZ, false, false, true, false),
        (SSUBWB_Z_ZZ, false, false, true, false),
        (SSUBWT_Z_ZZ, false, false, true, false),
        (SUB_Z_P_ZZ, true, false, false, false),
        (SUB_Z_ZI, false, false, false, false),
        (SUB_Z_ZZ, false, false, false, false),
        (SUBR_Z_P_ZZ, true, false, false, false),
        (SUBR_Z_ZI, false, false, false, false),
        (UADDLB_Z_ZZ, false, false, true, false),
        (UADDLT_Z_ZZ, false, false, true, false),
        (UADDWB_Z_ZZ, false, false, true, false),
        (UADDWT_Z_ZZ, false, false, true, false),
        (UCLAMP_Z_ZZ, false, false, false, false),
        (UDIV_Z_P_ZZ, true, false, false, true),
        (UDIVR_Z_P_ZZ, true, false, false, true),
        (UMAX_Z_P_ZZ, true, false, false, false),
        (UMAX_Z_ZI, false, false, false, false),
        (UMIN_Z_P_ZZ, true, false, false, false),
        (UMIN_Z_ZI, false, false, false, false),
        (USUBLB_Z_ZZ, false, false, true, false),
        (USUBLT_Z_ZZ, false, false, true, false),
        (USUBWB_Z_ZZ, false, false, true, false),
        (USUBWT_Z_ZZ, false, false, true, false),
    ];
    for (opcode, predicated, carry, widening, division) in forms {
        let maximum_size = if carry { 1 } else { SIZE_MASK };
        for size in 0..=maximum_size {
            for destination in 0..=REGISTER_MASK {
                let word = opcode | (size << SIZE_SHIFT) | destination;
                let result = decode(word).unwrap();
                if (widening && size == 0) || (division && size < 2) {
                    assert_eq!(result, Err(()));
                    continue;
                }
                let operand = result.unwrap();
                assert_eq!(operand.destination, destination as u8);
                assert_eq!(
                    operand.element_size.bytes(),
                    if carry { 4 << size } else { 1 << size }
                );
                assert_eq!(
                    operand.predication,
                    if predicated {
                        Predication::Merging(0)
                    } else {
                        Predication::Unpredicated
                    }
                );
            }
        }
    }
}

#[test]
fn immediate_byte_shift_is_reserved_and_signed_minmax_extend_imm8() {
    for opcode in [ADD_Z_ZI, SUB_Z_ZI, SUBR_Z_ZI] {
        assert_eq!(decode(opcode | IMMEDIATE_SHIFT_FLAG), Some(Err(())));
        assert!(
            decode(opcode | (1 << SIZE_SHIFT) | IMMEDIATE_SHIFT_FLAG)
                .unwrap()
                .is_ok()
        );
    }
    for opcode in [SMIN_Z_ZI, SMAX_Z_ZI] {
        let operand = decode(opcode | (IMMEDIATE_MASK << SOURCE_SHIFT))
            .unwrap()
            .unwrap();
        assert!(matches!(
            operand.kind,
            Kind::Binary {
                right: Source::Immediate(-1),
                ..
            }
        ));
    }
}

#[test]
fn aliases_include_z31_and_destructive_sources_keep_roles() {
    for destination in 0..=REGISTER_MASK {
        for source in 0..=REGISTER_MASK {
            let operand = decode(ADD_Z_P_ZZ | (source << SOURCE_SHIFT) | destination)
                .unwrap()
                .unwrap();
            assert_eq!(
                operand.kind,
                Kind::Binary {
                    operation: Binary::Add,
                    left: destination as u8,
                    right: Source::Vector(source as u8)
                }
            );
            let operand = decode(
                ADCLT_Z_ZZZ
                    | (source << SOURCE_SHIFT)
                    | (REGISTER_MASK << RIGHT_SHIFT)
                    | destination,
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                operand.kind,
                Kind::Carry {
                    source: source as u8,
                    carry: REGISTER_MASK as u8,
                    subtract: false,
                    top: true
                }
            );
        }
    }
}
