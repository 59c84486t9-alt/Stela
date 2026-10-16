//! FEAT_CSSC min/max through CMP and CMOV.
use super::{Register, Shift, Width, load, right_operand, store};
use crate::aarch64::integer_minmax::{Kind, Operand, Right};
use alloc::vec::Vec;

const REX_W: u8 = 0x48;
const NOP: u8 = 0x90;
const MOV_ECX_IMM32: u8 = 0xb9; // MOV ECX,imm32
const MOV_RCX_IMM32: &[u8] = &[REX_W, 0xc7, 0xc1];
const CMP_EAX_ECX: &[u8] = &[0x39, 0xc8];
const OPCODE_ESCAPE: u8 = 0x0f;
const MODRM_EAX_ECX: u8 = 0xc1;
const CMOVG: u8 = 0x4f;
const CMOVL: u8 = 0x4c;
const CMOVA: u8 = 0x47;
const CMOVB: u8 = 0x42;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    if operand.destination == Register::Zero {
        code.push(NOP);
        return;
    }
    load(code, operand.left);
    match operand.right {
        Right::Register(register) => right_operand(code, register, Width::X64, Shift::Lsl, 0),
        Right::Immediate(value) => {
            let immediate = if operand.kind.signed() {
                i32::from(value as i8) as u32
            } else {
                u32::from(value)
            };
            if operand.width == Width::X64 && operand.kind.signed() && (value as i8) < 0 {
                code.extend(MOV_RCX_IMM32);
            } else {
                code.push(MOV_ECX_IMM32);
            }
            code.extend(immediate.to_le_bytes());
        }
    }
    // All flag-changing source preparation precedes CMP, including ZR loads.
    if operand.width == Width::X64 {
        code.push(REX_W);
    }
    code.extend(CMP_EAX_ECX);
    if operand.width == Width::X64 {
        code.push(REX_W);
    }
    // A false 32-bit CMOV also clears the destination's high half.
    code.extend([
        OPCODE_ESCAPE,
        match operand.kind {
            Kind::SignedMinimum => CMOVG,
            Kind::SignedMaximum => CMOVL,
            Kind::UnsignedMinimum => CMOVA,
            Kind::UnsignedMaximum => CMOVB,
        },
        MODRM_EAX_ECX,
    ]);
    store(code, operand.destination);
}

#[cfg(test)]
mod tests;
