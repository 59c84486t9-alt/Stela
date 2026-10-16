//! Scalar CSSC recipes; host arithmetic flags never update guest NZCV.
use super::{Register, Width, load, offset, store};
use crate::{
    TargetCpu,
    aarch64::integer_unary::{Kind, Operand},
};
use alloc::vec::Vec;

const REX_W: u8 = 0x48;
const NOP: u8 = 0x90; // NOP keeps the source-map interval nonempty.
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const MOV_EAX_IMM32: u8 = 0xb8;
const NEG_EAX: &[u8] = &[0xf7, 0xd8];
const CMOVS_EAX_ECX: &[u8] = &[0x0f, 0x48, 0xc1];
const BSF_EAX_RDI_DISP32: &[u8] = &[0x0f, 0xbc, 0x87];
const TZCNT_EAX_RDI_DISP32: &[u8] = &[0x0f, 0xbc, 0x87];
const POPCNT_EAX_RDI_DISP32: &[u8] = &[0x0f, 0xb8, 0x87];
const PREFIX_F3: u8 = 0xf3;
const MOV_ECX_IMM32: u8 = 0xb9;
const CMOVZ_EAX_ECX: &[u8] = &[0x0f, 0x44, 0xc1];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const SHR_ECX_ONE: &[u8] = &[0xd1, 0xe9];
const SHR_ECX_IMM8: &[u8] = &[0xc1, 0xe9];
const SUB_EAX_ECX: &[u8] = &[0x29, 0xc8];
const ADD_EAX_ECX: &[u8] = &[0x01, 0xc8];
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const AND_EAX_IMM32: u8 = 0x25;
const MOV_RDX_IMM64: &[u8] = &[REX_W, 0xba]; // MOV RDX,imm64
const AND_ECX_EDX: &[u8] = &[0x21, 0xd1];
const AND_EAX_EDX: &[u8] = &[0x21, 0xd0];
const IMUL_EAX_EAX_IMM32: &[u8] = &[0x69, 0xc0];
const IMUL_EAX_EDX: &[u8] = &[0x0f, 0xaf, 0xc2];
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const PAIR_MASK: u64 = 0x5555_5555_5555_5555;
const TWO_BIT_MASK: u64 = 0x3333_3333_3333_3333;
const NIBBLE_MASK: u64 = 0x0f0f_0f0f_0f0f_0f0f;
const BYTE_SUM_MULTIPLIER: u64 = 0x0101_0101_0101_0101;
const TWO_BIT_SHIFT: u8 = 2;
const NIBBLE_SHIFT: u8 = 4;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    if operand.destination == Register::Zero {
        code.push(NOP);
        return;
    }
    if operand.source == Register::Zero {
        match operand.kind {
            Kind::Absolute | Kind::PopulationCount => code.extend(XOR_EAX_EAX),
            Kind::TrailingZeros => {
                code.push(MOV_EAX_IMM32);
                code.extend(bits(operand.width).to_le_bytes());
            }
        }
        store(code, operand.destination);
        return;
    }
    match operand.kind {
        Kind::Absolute => {
            load(code, operand.source);
            instruction(code, operand.width, MOV_ECX_EAX);
            instruction(code, operand.width, NEG_EAX);
            instruction(code, operand.width, CMOVS_EAX_ECX);
        }
        Kind::PopulationCount if target.supports(TargetCpu::Popcnt) => {
            memory_count(code, operand, POPCNT_EAX_RDI_DISP32, Some(PREFIX_F3));
        }
        Kind::PopulationCount => {
            load(code, operand.source);
            population_count(code, operand.width);
        }
        Kind::TrailingZeros if target.supports(TargetCpu::Bmi1) => {
            memory_count(code, operand, TZCNT_EAX_RDI_DISP32, Some(PREFIX_F3));
        }
        Kind::TrailingZeros => {
            memory_count(code, operand, BSF_EAX_RDI_DISP32, None);
            // MOV preserves BSF's ZF. Replace its undefined zero-input result
            // before use; a 32-bit CMOV is sufficient for either count width.
            code.push(MOV_ECX_IMM32);
            code.extend(bits(operand.width).to_le_bytes());
            code.extend(CMOVZ_EAX_ECX);
        }
    }
    store(code, operand.destination);
}

fn memory_count(code: &mut Vec<u8>, operand: &Operand, opcode: &[u8], prefix: Option<u8>) {
    // Break the count destination dependency before its folded memory read.
    // The memory read precedes the guest destination write, including aliases.
    code.extend(XOR_EAX_EAX);
    if let Some(prefix) = prefix {
        code.push(prefix);
    }
    instruction(code, operand.width, opcode);
    let source = offset(operand.source).expect("nonzero scalar count source");
    code.extend(source.to_le_bytes());
}

// REX.W widens the named 32-bit GPR operands.
fn instruction(code: &mut Vec<u8>, width: Width, opcode: &[u8]) {
    if width == Width::X64 {
        code.push(REX_W);
    }
    code.extend(opcode);
}

fn bits(width: Width) -> u32 {
    match width {
        Width::W32 => u32::BITS,
        Width::X64 => u64::BITS,
    }
}

fn load_mask(code: &mut Vec<u8>, width: Width, value: u64) {
    if width == Width::X64 {
        code.extend(MOV_RDX_IMM64);
        code.extend(value.to_le_bytes());
    }
}

fn mask_copy(code: &mut Vec<u8>, width: Width, value: u64) {
    match width {
        Width::W32 => {
            code.extend(AND_ECX_IMM32);
            code.extend((value as u32).to_le_bytes());
        }
        Width::X64 => instruction(code, width, AND_ECX_EDX),
    }
}

fn mask_accumulator(code: &mut Vec<u8>, width: Width, value: u64) {
    match width {
        Width::W32 => {
            code.push(AND_EAX_IMM32);
            code.extend((value as u32).to_le_bytes());
        }
        Width::X64 => instruction(code, width, AND_EAX_EDX),
    }
}

fn population_count(code: &mut Vec<u8>, width: Width) {
    // Each subtraction produces a two-bit count without borrowing across pairs.
    instruction(code, width, MOV_ECX_EAX);
    instruction(code, width, SHR_ECX_ONE);
    load_mask(code, width, PAIR_MASK);
    mask_copy(code, width, PAIR_MASK);
    instruction(code, width, SUB_EAX_ECX);

    instruction(code, width, MOV_ECX_EAX);
    instruction(code, width, SHR_ECX_IMM8);
    code.push(TWO_BIT_SHIFT);
    load_mask(code, width, TWO_BIT_MASK);
    mask_copy(code, width, TWO_BIT_MASK);
    mask_accumulator(code, width, TWO_BIT_MASK);
    instruction(code, width, ADD_EAX_ECX);

    instruction(code, width, MOV_ECX_EAX);
    instruction(code, width, SHR_ECX_IMM8);
    code.push(NIBBLE_SHIFT);
    instruction(code, width, ADD_EAX_ECX);
    load_mask(code, width, NIBBLE_MASK);
    mask_accumulator(code, width, NIBBLE_MASK);

    match width {
        Width::W32 => {
            code.extend(IMUL_EAX_EAX_IMM32);
            code.extend((BYTE_SUM_MULTIPLIER as u32).to_le_bytes());
        }
        Width::X64 => {
            load_mask(code, width, BYTE_SUM_MULTIPLIER);
            instruction(code, width, IMUL_EAX_EDX);
        }
    }
    instruction(code, width, SHR_EAX_IMM8);
    code.push((bits(width) - u8::BITS) as u8);
}

#[cfg(test)]
mod tests;
