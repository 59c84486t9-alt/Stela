//! Register-offset loads and stores to private RAM.
use super::{
    AddressMode, MemoryTransfer, Register, Shift, Width, memory_address, memory_store, offset,
    right_operand,
};
use crate::aarch64::register_offset::{IndexExtend, Operand};
use alloc::vec::Vec;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    address(
        code,
        operand.base,
        operand.index,
        operand.extend,
        operand.shift,
    );
    transfer(code, operand);
}

/// Shared integer/SIMD address calculation, without guest register writeback.
/// RAX is the result; RCX/RDX and host flags are scratch. SP is checked first.
pub(super) fn address(
    code: &mut Vec<u8>,
    base: Register,
    index: Register,
    extend: IndexExtend,
    shift: u8,
) {
    const MOV_ECX_ECX: &[u8] = &[0x89, 0xc9];
    const MOVSXD_RCX_ECX: &[u8] = &[0x48, 0x63, 0xc9];
    const SHL_RCX_IMM8: &[u8] = &[0x48, 0xc1, 0xe1];
    const LEA_RAX_RAX_RCX: &[u8] = &[0x48, 0x8d, 0x04, 0x08];
    // Validate incoming SP before offset addition, even if the effective
    // address would be aligned. No guest register is committed before access.
    memory_address(code, base, 0, AddressMode::Offset);
    right_operand(code, index, Width::X64, Shift::Lsl, 0);
    match extend {
        IndexExtend::Uxtw => code.extend(MOV_ECX_ECX),
        IndexExtend::Sxtw => code.extend(MOVSXD_RCX_ECX),
        IndexExtend::Lsl | IndexExtend::Sxtx => {}
    }
    if shift != 0 {
        code.extend(SHL_RCX_IMM8);
        code.push(shift);
    }
    code.extend(LEA_RAX_RAX_RCX); // modulo 2^64
}

fn transfer(code: &mut Vec<u8>, operand: &Operand) {
    match operand.transfer {
        MemoryTransfer::Store => {
            right_operand(code, operand.data, Width::X64, Shift::Lsl, 0);
            memory_store::emit(
                code,
                operand.bytes,
                0,
                memory_store::Source::Rcx,
                memory_store::aligned_register_offset(
                    operand.base,
                    operand.index,
                    operand.shift,
                    operand.bytes,
                ),
            );
        }
        MemoryTransfer::Load { signed, width } => {
            if width == Width::X64 {
                code.push(0x48);
            }
            match (operand.bytes, signed) {
                (1, false) => code.extend([0x0f, 0xb6, 0x08]),
                (2, false) => code.extend([0x0f, 0xb7, 0x08]),
                (1, true) => code.extend([0x0f, 0xbe, 0x08]),
                (2, true) => code.extend([0x0f, 0xbf, 0x08]),
                (4, true) => code.extend([0x63, 0x08]),
                (4 | 8, false) => code.extend([0x8b, 0x08]),
                _ => unreachable!("decoder validates signed register-offset size"),
            }
            // A load to ZR still accesses memory and can fault.
            if let Some(displacement) = offset(operand.data) {
                code.extend([0x48, 0x89, 0x8f]);
                code.extend(displacement.to_le_bytes());
            }
        }
    }
    // This addressing class never performs base writeback.
    debug_assert!(operand.base != Register::Zero);
}
