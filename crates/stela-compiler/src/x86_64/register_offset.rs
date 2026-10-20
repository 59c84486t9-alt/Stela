//! Register-offset loads and stores to private RAM.
use super::{
    Access, AddressMode, MemoryTransfer, Register, Shift, Width, memory_address, memory_store,
    offset, right_operand,
};
use crate::aarch64::register_offset::{IndexExtend, Operand};
use alloc::vec::Vec;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, checks: super::MemoryChecks) {
    address(
        code,
        checks,
        operand.base,
        operand.index,
        operand.extend,
        operand.shift,
        operand.bytes,
        operand.transfer == MemoryTransfer::Store,
    );
    transfer(code, operand, checks);
}

/// Shared integer/SIMD address calculation, without guest register writeback.
/// RAX is the result; RCX/RDX and host flags are scratch. SP is checked first,
/// and SCTLR_ELx.A checks the result against the access's `bytes`.
#[allow(clippy::too_many_arguments)]
pub(super) fn address(
    code: &mut Vec<u8>,
    checks: super::MemoryChecks,
    base: Register,
    index: Register,
    extend: IndexExtend,
    shift: u8,
    bytes: u8,
    write: bool,
) {
    // Validate incoming SP before offset addition, even if the effective
    // address would be aligned. No guest register is committed before access.
    // Only the final address is checked against the guest's ranges.
    let base_checks = super::MemoryChecks {
        guest_range: false,
        ..checks
    };
    let access = Access::of(write, bytes.into());
    memory_address(code, base_checks, base, 0, AddressMode::Offset, 1, access);
    index_add(code, index, extend, shift);
    super::address_checks(code, checks, bytes, access);
}

const MOV_ECX_STATE: [u8; 2] = [0x8b, 0x8f];
const MOVSXD_RCX_STATE: [u8; 3] = [0x48, 0x63, 0x8f];
const MOV_RCX_STATE: [u8; 3] = [0x48, 0x8b, 0x8f];
const ADD_RAX_STATE: [u8; 3] = [0x48, 0x03, 0x87];
const SHL_RCX_IMM8: [u8; 3] = [0x48, 0xc1, 0xe1];
/// LEA RAX,[RAX+RCX*scale]: the SIB byte's scale field, RCX index, RAX base.
const LEA_RAX_RAX_RCX: [u8; 3] = [0x48, 0x8d, 0x04];
const SIB_RCX_INDEX_RAX_BASE: u8 = 0x08;
const SIB_SCALE_SHIFT: u8 = 6;
/// The largest shift a SIB scale applies (times eight).
const MAX_SCALE_SHIFT: u8 = 3;

/// The index register, extended and shifted, added to the base in RAX
/// modulo 2^64. A W index is read with its extension from its frame slot;
/// a ZR index adds nothing. RCX and host flags are scratch.
pub(crate) fn index_add(code: &mut Vec<u8>, index: Register, extend: IndexExtend, shift: u8) {
    let Some(slot) = offset(index) else {
        return;
    };
    match extend {
        IndexExtend::Uxtw => code.extend(MOV_ECX_STATE),
        IndexExtend::Sxtw => code.extend(MOVSXD_RCX_STATE),
        IndexExtend::Lsl | IndexExtend::Sxtx if shift == 0 => {
            code.extend(ADD_RAX_STATE);
            code.extend(slot.to_le_bytes());
            return;
        }
        IndexExtend::Lsl | IndexExtend::Sxtx => code.extend(MOV_RCX_STATE),
    }
    code.extend(slot.to_le_bytes());
    let scale = if shift > MAX_SCALE_SHIFT {
        code.extend(SHL_RCX_IMM8);
        code.push(shift);
        0
    } else {
        shift
    };
    code.extend(LEA_RAX_RAX_RCX);
    code.push(scale << SIB_SCALE_SHIFT | SIB_RCX_INDEX_RAX_BASE);
}

fn transfer(code: &mut Vec<u8>, operand: &Operand, checks: super::MemoryChecks) {
    match operand.transfer {
        MemoryTransfer::Store => {
            right_operand(code, operand.data, Width::X64, Shift::Lsl, 0);
            memory_store::emit(
                code,
                operand.bytes,
                0,
                memory_store::Source::Rcx,
                checks.stack_alignment
                    && memory_store::aligned_register_offset(
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
