use super::*;

const MRS_NZCV: u32 = 0xd53b_4200;
const MSR_NZCV: u32 = 0xd51b_4200;
const SYS: u32 = 0xd508_0000;
const SYSL: u32 = 0xd528_0000;
const MSR_IMMEDIATE: u32 = 0xd503_40df;
const ISB: u32 = 0xd503_3fdf;
const NOP: u32 = 0xd503_201f;

#[test]
fn every_structural_register_operand_round_trips_exactly() {
    for (base, direction) in [
        (MRS_REGISTER_INSTRUCTION, Direction::Read),
        (MSR_REGISTER_INSTRUCTION, Direction::Write),
    ] {
        for op0_low in 0..=1 {
            for op1 in 0..=u32::from(OP1_MASK) {
                for crn in 0..=u32::from(CRN_MASK) {
                    for crm in 0..=u32::from(CRM_MASK) {
                        for op2 in 0..=u32::from(OP2_MASK) {
                            for rt in 0..=WORD_REGISTER_MASK {
                                let word = base
                                    | (op0_low << WORD_OP0_LOW_SHIFT)
                                    | (op1 << WORD_OP1_SHIFT)
                                    | (crn << WORD_CRN_SHIFT)
                                    | (crm << WORD_CRM_SHIFT)
                                    | (op2 << WORD_OP2_SHIFT)
                                    | rt;
                                let access = decode(word).unwrap();
                                assert_eq!(access.direction(), direction);
                                assert_eq!(access.rt(), rt as u8);
                                assert_eq!(
                                    access.encoding(),
                                    Encoding::new(
                                        REGISTER_OP0_HIGH_BIT | op0_low as u8,
                                        op1 as u8,
                                        crn as u8,
                                        crm as u8,
                                        op2 as u8,
                                    )
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn fixed_class_bits_and_neighbor_families_are_not_guessed() {
    for word in [SYS, SYSL, MSR_IMMEDIATE, ISB, NOP, u32::MAX] {
        assert!(decode(word).is_none());
    }
    for bit in 0..u32::BITS {
        let mask = 1 << bit;
        if mask & REGISTER_INSTRUCTION_MASK != 0 {
            for word in [MRS_NZCV, MSR_NZCV] {
                let changed = word ^ mask;
                if !matches!(
                    changed & REGISTER_INSTRUCTION_MASK,
                    MRS_REGISTER_INSTRUCTION | MSR_REGISTER_INSTRUCTION
                ) {
                    assert!(decode(changed).is_none());
                }
            }
        }
    }
}

#[test]
fn zero_register_keeps_its_encoded_role_in_both_directions() {
    for word in [MRS_NZCV, MSR_NZCV] {
        let access = decode(word | WORD_REGISTER_MASK).unwrap();
        assert_eq!(access.rt(), WORD_REGISTER_MASK as u8);
        assert_eq!(access.encoding(), Encoding::new(3, 3, 4, 2, 0));
    }
}
