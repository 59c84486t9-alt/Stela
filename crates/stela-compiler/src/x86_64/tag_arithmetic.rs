//! Baseline register-only MTE recipes; guest tag controls are fixed by profile.
use super::{Register, Shift, Width, load, offset, right_operand, store};
use crate::{
    GuestState,
    aarch64::tag_arithmetic::{Kind, Operand},
};
use alloc::vec::Vec;

const NOP: u8 = 0x90;
const REX_W_PREFIX: u8 = 0x48;
const TWO_BYTE_OPCODE: u8 = 0x0f;
const HIGH_BYTE_OFFSET: u32 = 7;
const TOP_BYTE_ROTATE: u8 = 8;
const SIGN_EXTEND_SHIFT: u8 = 8;
const TAG_MASK: u8 = 15;
const MASK_BIT: u32 = 1;
const TOP_NIBBLE_MASK: u8 = 0xf0;
const NZCV_OFFSET: u32 = core::mem::offset_of!(GuestState, nzcv) as u32;
const N_SHIFT: u8 = 31;
const Z_SHIFT: u8 = 30;
const C_SHIFT: u8 = 29;
const MOVZX_ECX_STATE_BYTE: &[u8] = &[TWO_BYTE_OPCODE, 0xb6, 0x8f];
const ADD_ECX_IMM8: &[u8] = &[0x83, 0xc1];
const AND_ECX_IMM8: &[u8] = &[0x83, 0xe1];
const ADD_RAX_IMM32: &[u8] = &[REX_W_PREFIX, 0x05];
const SUB_RAX_IMM32: &[u8] = &[REX_W_PREFIX, 0x2d];
const LEA_RAX_RAX_DISP8: &[u8] = &[REX_W_PREFIX, 0x8d, 0x40];
const ROL_RAX_IMM8: &[u8] = &[REX_W_PREFIX, 0xc1, 0xc0];
const ROR_RAX_IMM8: &[u8] = &[REX_W_PREFIX, 0xc1, 0xc8];
const AND_AL_IMM8: u8 = 0x24;
const OR_AL_CL: &[u8] = &[0x08, 0xc8];
const SHL_RAX_IMM8: &[u8] = &[REX_W_PREFIX, 0xc1, 0xe0];
const SAR_RAX_IMM8: &[u8] = &[REX_W_PREFIX, 0xc1, 0xf8];
const SHL_RCX_IMM8: &[u8] = &[REX_W_PREFIX, 0xc1, 0xe1];
const SAR_RCX_IMM8: &[u8] = &[REX_W_PREFIX, 0xc1, 0xf9];
const SUB_RAX_RCX: &[u8] = &[REX_W_PREFIX, 0x29, 0xc8];
const BTS_RAX_RCX: &[u8] = &[REX_W_PREFIX, TWO_BYTE_OPCODE, 0xab, 0xc8];
const MOV_EDX_IMM32: u8 = 0xba;
const SHL_EDX_CL: &[u8] = &[0xd3, 0xe2];
const OR_STATE_RDX: &[u8] = &[REX_W_PREFIX, 0x09, 0x97];
const SETS_AL: &[u8] = &[TWO_BYTE_OPCODE, 0x98, 0xc0];
const SETE_CL: &[u8] = &[TWO_BYTE_OPCODE, 0x94, 0xc1];
const SETAE_DL: &[u8] = &[TWO_BYTE_OPCODE, 0x93, 0xc2];
const MOVZX_EAX_AL: &[u8] = &[TWO_BYTE_OPCODE, 0xb6, 0xc0];
const MOVZX_ECX_CL: &[u8] = &[TWO_BYTE_OPCODE, 0xb6, 0xc9];
const MOVZX_EDX_DL: &[u8] = &[TWO_BYTE_OPCODE, 0xb6, 0xd2];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const SHL_ECX_IMM8: &[u8] = &[0xc1, 0xe1];
const SHL_EDX_IMM8: &[u8] = &[0xc1, 0xe2];
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
const OR_EAX_EDX: &[u8] = &[0x09, 0xd0];
const MOV_STATE_EAX: &[u8] = &[0x89, 0x87];

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    if operand.destination == Register::Zero
        && !matches!(operand.kind, Kind::Difference { flags: true, .. })
    {
        code.push(NOP);
        return;
    }
    match operand.kind {
        Kind::Offset {
            source,
            subtract,
            address_offset,
            tag_offset,
        } => {
            emit_offset(
                code,
                operand.destination,
                source,
                subtract,
                address_offset,
                tag_offset,
            );
        }
        Kind::Difference { left, right, flags } => {
            load(code, left);
            right_operand(code, right, Width::X64, Shift::Lsl, 0);
            // Each signed56 input must be extended independently: their difference
            // requires57 bits and cannot be recovered from a wrapped shifted SUB.
            for instruction in [SHL_RAX_IMM8, SAR_RAX_IMM8, SHL_RCX_IMM8, SAR_RCX_IMM8] {
                code.extend(instruction);
                code.push(SIGN_EXTEND_SHIFT);
            }
            code.extend(SUB_RAX_RCX);
            store(code, operand.destination);
            if flags {
                emit_difference_flags(code);
            }
        }
        Kind::Mask { address, mask } => {
            emit_mask(code, operand.destination, address, mask);
        }
    }
}

fn tag_input(code: &mut Vec<u8>, source: Register, increment: u8) {
    let source_offset = offset(source).expect("tag address source is GPR or SP");
    code.extend(MOVZX_ECX_STATE_BYTE);
    code.extend((source_offset + HIGH_BYTE_OFFSET).to_le_bytes());
    if increment != 0 {
        code.extend(ADD_ECX_IMM8);
        code.push(increment);
    }
    code.extend(AND_ECX_IMM8);
    code.push(TAG_MASK);
}

fn emit_offset(
    code: &mut Vec<u8>,
    destination: Register,
    source: Register,
    subtract: bool,
    address_offset: u16,
    tag_offset: u8,
) {
    if address_offset == 0 && tag_offset == 0 {
        if destination == source {
            code.push(NOP);
        } else {
            load(code, source);
            store(code, destination);
        }
        return;
    }
    load(code, source);
    // Extract the original tag before address arithmetic; its carry/borrow can
    // cross the tag field and must still reach the preserved high nibble.
    tag_input(code, source, tag_offset);
    if address_offset != 0 {
        let displacement = i32::from(address_offset) * if subtract { -1 } else { 1 };
        if let Ok(displacement) = i8::try_from(displacement) {
            code.extend(LEA_RAX_RAX_DISP8);
            code.extend(displacement.to_le_bytes());
        } else {
            code.extend(if subtract {
                SUB_RAX_IMM32
            } else {
                ADD_RAX_IMM32
            });
            code.extend(u32::from(address_offset).to_le_bytes());
        }
    }
    code.extend(ROL_RAX_IMM8);
    code.extend([TOP_BYTE_ROTATE, AND_AL_IMM8, TOP_NIBBLE_MASK]);
    code.extend(OR_AL_CL);
    code.extend(ROR_RAX_IMM8);
    code.push(TOP_BYTE_ROTATE);
    store(code, destination);
}

fn emit_mask(code: &mut Vec<u8>, destination: Register, address: Register, mask: Register) {
    if destination == mask {
        // Consume the original tag before any in-place update, including when
        // the address aliases the mask. EDX's high half stays zero for tag0..15.
        tag_input(code, address, 0);
        code.push(MOV_EDX_IMM32);
        code.extend(MASK_BIT.to_le_bytes());
        code.extend(SHL_EDX_CL);
        code.extend(OR_STATE_RDX);
        code.extend(
            offset(mask)
                .expect("discarded GMI was handled before emission")
                .to_le_bytes(),
        );
    } else {
        load(code, mask);
        tag_input(code, address, 0);
        code.extend(BTS_RAX_RCX);
        store(code, destination);
    }
}

fn emit_difference_flags(code: &mut Vec<u8>) {
    // Signed56 differences cannot overflow signed64, so guest V is always0.
    // Capture all three predicates before shifts/ORs alter the host flags.
    for instruction in [
        SETS_AL,
        SETE_CL,
        SETAE_DL,
        MOVZX_EAX_AL,
        MOVZX_ECX_CL,
        MOVZX_EDX_DL,
    ] {
        code.extend(instruction);
    }
    for (instruction, amount) in [
        (SHL_EAX_IMM8, N_SHIFT),
        (SHL_ECX_IMM8, Z_SHIFT),
        (SHL_EDX_IMM8, C_SHIFT),
    ] {
        code.extend(instruction);
        code.push(amount);
    }
    code.extend(OR_EAX_ECX);
    code.extend(OR_EAX_EDX);
    code.extend(MOV_STATE_EAX);
    code.extend(NZCV_OFFSET.to_le_bytes());
}
