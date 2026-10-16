use super::*;

const REGISTER_WRITE_NZCV: u32 = 0xd51b_4200;
const REGISTER_READ_NZCV: u32 = 0xd53b_4200;
const NOP: u32 = 0xd503_201f;
const SYS: u32 = 0xd508_0000;
const IMMEDIATE_OPERAND_MAX: u8 = 15;
const SPSEL_SELECTOR: (u8, u8) = (0, 5);
const DAIF_SET_SELECTOR: (u8, u8) = (3, 6);
const DAIF_CLEAR_SELECTOR: (u8, u8) = (3, 7);

#[test]
fn all_base_immediate_operands_preserve_the_original_fields() {
    for (op1, op2) in [SPSEL_SELECTOR, DAIF_SET_SELECTOR, DAIF_CLEAR_SELECTOR] {
        for operand in 0..=IMMEDIATE_OPERAND_MAX {
            let word = PSTATE_IMMEDIATE_CLASS
                | (u32::from(op1) << PSTATE_OP1_SHIFT)
                | (u32::from(operand) << PSTATE_CRM_SHIFT)
                | (u32::from(op2) << PSTATE_OP2_SHIFT);
            assert_eq!(
                decode_pstate_immediate(word),
                Some(Encoding::new(
                    PSTATE_IMMEDIATE_OP0,
                    op1,
                    PSTATE_IMMEDIATE_CRN,
                    operand,
                    op2,
                ))
            );
            assert_eq!(decode_pstate_immediate(word ^ 1), None);
            assert_eq!(
                decode_pstate_immediate(word ^ (1 << PSTATE_CRN_TEST_SHIFT)),
                None
            );
        }
    }
}

const PSTATE_CRN_TEST_SHIFT: u32 = 12;

#[test]
fn delegated_flags_aliases_and_other_system_classes_miss() {
    for op2 in 0..=LAST_FLAGS_ALIAS_OP2 {
        for operand in 0..=IMMEDIATE_OPERAND_MAX {
            let word = PSTATE_IMMEDIATE_CLASS
                | (u32::from(operand) << PSTATE_CRM_SHIFT)
                | (u32::from(op2) << PSTATE_OP2_SHIFT);
            assert_eq!(decode_pstate_immediate(word), None);
        }
    }
    for word in [NOP, REGISTER_WRITE_NZCV, REGISTER_READ_NZCV, SYS] {
        assert_eq!(decode_pstate_immediate(word), None);
    }
}
