//! Baseline scalar FlagM/FlagM2 recipes; guest flags live in GuestState.
use super::load;
use crate::{
    GuestState,
    aarch64::Register,
    aarch64::flags::{Operand, SetWidth},
};
use alloc::vec::Vec;

const NZCV_OFFSET: u32 = core::mem::offset_of!(GuestState, nzcv) as u32;
const NZCV_SHIFT: u8 = 28;
const NEGATIVE_BIT: u8 = 3;
const ZERO_BIT: u8 = 2;
const CARRY_BIT: u8 = 1;
const OVERFLOW_BIT: u8 = 0;
const NEGATIVE: u32 = 1 << NEGATIVE_BIT;
const ZERO: u32 = 1 << ZERO_BIT;
const CARRY: u32 = 1 << CARRY_BIT;
const OVERFLOW: u32 = 1 << OVERFLOW_BIT;
const CARRY_MASK: u32 = CARRY << NZCV_SHIFT;
const NZCV_NIBBLE: u8 = (NEGATIVE | ZERO | CARRY | OVERFLOW) as u8;
const TABLE_ENTRY_BITS: u32 = 4;
const TABLE_STRIDE_SHIFT: u8 = 2;
const EXTERNAL_INDEX_SHIFT: u8 = NZCV_SHIFT + CARRY_BIT - TABLE_STRIDE_SHIFT;
const EXTERNAL_INDEX_MASK: u32 = ((ZERO | CARRY) >> CARRY_BIT) << TABLE_STRIDE_SHIFT;
const ARM_INDEX_SHIFT: u8 = NZCV_SHIFT - TABLE_STRIDE_SHIFT;
const ARM_INDEX_MASK: u32 = (ZERO | CARRY | OVERFLOW) << TABLE_STRIDE_SHIFT;
// AXFLAG's index is (Z << 2) | (C << 1) | V. Input N is ignored.
const ARM_TO_EXTERNAL_TABLE: u32 = (ZERO << TABLE_ENTRY_BITS)
    | (CARRY << (2 * TABLE_ENTRY_BITS))
    | (ZERO << (3 * TABLE_ENTRY_BITS))
    | (ZERO << (4 * TABLE_ENTRY_BITS))
    | (ZERO << (5 * TABLE_ENTRY_BITS))
    | ((ZERO | CARRY) << (6 * TABLE_ENTRY_BITS))
    | (ZERO << (7 * TABLE_ENTRY_BITS));
// XAFLAG's input index is (Z << 1) | C; each nibble is its complete NZCV result.
const EXTERNAL_TO_ARM_TABLE: u32 = NEGATIVE
    | (CARRY << TABLE_ENTRY_BITS)
    | ((CARRY | OVERFLOW) << (2 * TABLE_ENTRY_BITS))
    | ((ZERO | CARRY) << (3 * TABLE_ENTRY_BITS));

/// Family-local instruction encodings. Immediates/displacements follow separately.
#[derive(Clone, Copy)]
enum Opcode {
    Nop,
    LoadEaxNzcv,
    LoadEcxNzcv,
    StoreEaxNzcv,
    XorNzcvImmediate,
    AndNzcvImmediate,
    MoveEcxEax,
    MoveEdxEax,
    MoveEaxEdx,
    MoveEaxImmediate,
    RotateRax,
    ShiftLeftEax,
    ShiftLeftEcx,
    ShiftRightEax,
    ShiftRightEcx,
    ShiftRightEdx,
    ShiftRightEaxCl,
    AndEaxImmediate,
    AndEcxImmediate,
    OrEaxImmediate,
    OrEaxEcx,
    OrEcxEdx,
    XorEaxEdx,
    TestAl,
    TestAx,
    SetZeroDl,
    ZeroExtendEdxDl,
    ShiftLeftEdx,
}
impl Opcode {
    fn emit(self, code: &mut Vec<u8>) {
        code.extend(match self {
            Self::Nop => &[0x90][..],
            Self::LoadEaxNzcv => &[0x8b, 0x87][..],
            Self::LoadEcxNzcv => &[0x8b, 0x8f],
            Self::StoreEaxNzcv => &[0x89, 0x87],
            Self::XorNzcvImmediate => &[0x81, 0xb7],
            Self::AndNzcvImmediate => &[0x81, 0xa7],
            Self::MoveEcxEax => &[0x89, 0xc1],
            Self::MoveEdxEax => &[0x89, 0xc2],
            Self::MoveEaxEdx => &[0x89, 0xd0],
            Self::MoveEaxImmediate => &[0xb8],
            Self::RotateRax => &[0x48, 0xc1, 0xc8],
            Self::ShiftLeftEax => &[0xc1, 0xe0],
            Self::ShiftLeftEcx => &[0xc1, 0xe1],
            Self::ShiftRightEax => &[0xc1, 0xe8],
            Self::ShiftRightEcx => &[0xc1, 0xe9],
            Self::ShiftRightEdx => &[0xc1, 0xea],
            Self::ShiftRightEaxCl => &[0xd3, 0xe8],
            Self::AndEaxImmediate => &[0x25],
            Self::AndEcxImmediate => &[0x81, 0xe1],
            Self::OrEaxImmediate => &[0x0d],
            Self::OrEaxEcx => &[0x09, 0xc8],
            Self::OrEcxEdx => &[0x09, 0xd1],
            Self::XorEaxEdx => &[0x31, 0xd0],
            Self::TestAl => &[0x84, 0xc0],
            Self::TestAx => &[0x66, 0x85, 0xc0],
            Self::SetZeroDl => &[0x0f, 0x94, 0xc2],
            Self::ZeroExtendEdxDl => &[0x0f, 0xb6, 0xd2],
            Self::ShiftLeftEdx => &[0xc1, 0xe2],
        });
    }
    fn immediate(self, code: &mut Vec<u8>, value: u32) {
        self.emit(code);
        code.extend(value.to_le_bytes());
    }
    fn shift(self, code: &mut Vec<u8>, amount: u8) {
        self.emit(code);
        code.push(amount);
    }
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    match *operand {
        Operand::InvertCarry => {
            Opcode::XorNzcvImmediate.immediate(code, NZCV_OFFSET);
            code.extend(CARRY_MASK.to_le_bytes());
            return;
        }
        Operand::RotateMask {
            source,
            rotation,
            mask,
        } => {
            if mask == 0 {
                // Every original instruction retains a nonempty source-map interval.
                Opcode::Nop.emit(code);
                return;
            }
            if source == Register::Zero {
                Opcode::AndNzcvImmediate.immediate(code, NZCV_OFFSET);
                code.extend((!(u32::from(mask) << NZCV_SHIFT)).to_le_bytes());
                return;
            }
            load(code, source);
            if rotation != 0 {
                Opcode::RotateRax.shift(code, rotation);
            }
            Opcode::AndEaxImmediate.immediate(code, u32::from(mask));
            Opcode::ShiftLeftEax.shift(code, NZCV_SHIFT);
            Opcode::LoadEcxNzcv.immediate(code, NZCV_OFFSET);
            Opcode::AndEcxImmediate.immediate(code, !(u32::from(mask) << NZCV_SHIFT));
            Opcode::OrEaxEcx.emit(code);
        }
        Operand::Set { source, width } => {
            if source == Register::Zero {
                Opcode::LoadEaxNzcv.immediate(code, NZCV_OFFSET);
                Opcode::AndEaxImmediate.immediate(code, CARRY_MASK);
                Opcode::OrEaxImmediate.immediate(code, ZERO << NZCV_SHIFT);
                Opcode::StoreEaxNzcv.immediate(code, NZCV_OFFSET);
                return;
            }
            load(code, source);
            // TEST observes only the architectural byte/halfword; SETZ's
            // partial write is zero-extended before the full-register use.
            Opcode::MoveEcxEax.emit(code);
            Opcode::ShiftRightEcx.shift(code, width.bits() - 1);
            Opcode::AndEcxImmediate.immediate(code, 1);
            Opcode::ShiftLeftEcx.shift(code, NZCV_SHIFT + NEGATIVE_BIT);
            match width {
                SetWidth::Byte => Opcode::TestAl,
                SetWidth::Halfword => Opcode::TestAx,
            }
            .emit(code);
            Opcode::SetZeroDl.emit(code);
            Opcode::ZeroExtendEdxDl.emit(code);
            Opcode::ShiftLeftEdx.shift(code, NZCV_SHIFT + ZERO_BIT);
            Opcode::OrEcxEdx.emit(code);
            Opcode::MoveEdxEax.emit(code);
            Opcode::ShiftRightEdx.shift(code, width.bits() - 1);
            Opcode::MoveEaxEdx.emit(code);
            Opcode::ShiftRightEax.shift(code, 1);
            Opcode::XorEaxEdx.emit(code);
            Opcode::AndEaxImmediate.immediate(code, OVERFLOW);
            Opcode::ShiftLeftEax.shift(code, NZCV_SHIFT);
            Opcode::OrEaxEcx.emit(code);
            Opcode::LoadEcxNzcv.immediate(code, NZCV_OFFSET);
            Opcode::AndEcxImmediate.immediate(code, CARRY_MASK);
            Opcode::OrEaxEcx.emit(code);
        }
        Operand::ArmToExternal => {
            emit_conversion(code, ARM_TO_EXTERNAL_TABLE, ARM_INDEX_SHIFT, ARM_INDEX_MASK);
        }
        Operand::ExternalToArm => {
            emit_conversion(
                code,
                EXTERNAL_TO_ARM_TABLE,
                EXTERNAL_INDEX_SHIFT,
                EXTERNAL_INDEX_MASK,
            );
        }
    }
    Opcode::StoreEaxNzcv.immediate(code, NZCV_OFFSET);
}

fn emit_conversion(code: &mut Vec<u8>, table: u32, index_shift: u8, index_mask: u32) {
    Opcode::LoadEcxNzcv.immediate(code, NZCV_OFFSET);
    // Each architectural flag result occupies one nibble of the immediate.
    Opcode::ShiftRightEcx.shift(code, index_shift);
    Opcode::AndEcxImmediate.immediate(code, index_mask);
    Opcode::MoveEaxImmediate.immediate(code, table);
    Opcode::ShiftRightEaxCl.emit(code);
    Opcode::AndEaxImmediate.immediate(code, u32::from(NZCV_NIBBLE));
    Opcode::ShiftLeftEax.shift(code, NZCV_SHIFT);
}

#[cfg(test)]
mod tests {
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
}
