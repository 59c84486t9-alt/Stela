use super::*;
use alloc::vec::Vec;

#[test]
fn external_table_matches_all_architectural_flag_inputs() {
    for flags in 0..=u32::from(NZCV_NIBBLE) {
        let zero = flags & ZERO != 0;
        let carry = flags & CARRY != 0;
        let expected = (if !carry && !zero { NEGATIVE } else { 0 })
            | (if zero && carry { ZERO } else { 0 })
            | (if carry || zero { CARRY } else { 0 })
            | (if !carry && zero { OVERFLOW } else { 0 });
        let index = ((flags & (ZERO | CARRY)) >> CARRY_BIT) * TABLE_ENTRY_BITS;
        assert_eq!(
            (EXTERNAL_TO_ARM_TABLE >> index) & u32::from(NZCV_NIBBLE),
            expected
        );
        let overflow = flags & OVERFLOW != 0;
        let expected = (if zero || overflow { ZERO } else { 0 })
            | (if carry && !overflow { CARRY } else { 0 });
        let index = (flags & (ZERO | CARRY | OVERFLOW)) * TABLE_ENTRY_BITS;
        assert_eq!(
            (ARM_TO_EXTERNAL_TABLE >> index) & u32::from(NZCV_NIBBLE),
            expected
        );
    }
}

#[test]
fn zero_rotate_mask_keeps_a_nonempty_mapping_interval() {
    let mut code = Vec::new();
    emit(
        &mut code,
        &Operand::RotateMask {
            source: crate::aarch64::Register::Zero,
            rotation: 63,
            mask: 0,
        },
    );
    assert_eq!(code, [0x90]);
}
