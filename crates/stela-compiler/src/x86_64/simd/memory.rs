//! SIMD loads and stores to private RAM, immediate and register offsets.
use super::{commit, read_vector, vector_offset};
use crate::aarch64::simd::memory::Operand;
use alloc::vec::Vec;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;
const OPERAND_SIZE_PREFIX: u8 = 0x66;
const REP_PREFIX: u8 = 0xf3;
const TWO_BYTE_OPCODE: u8 = 0x0f;
const MOVD_LOAD_OPCODE: u8 = 0x6e;
const MOVQ_LOAD_OPCODE: u8 = 0x7e;
const MOVDQU_LOAD_OPCODE: u8 = 0x6f;
const DISP8_ADDRESS: u8 = 0x40;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MOVZX_ECX_BYTE_AT_RAX: [u8; 3] = [0x0f, 0xb6, 0x08];
const MOVZX_ECX_WORD_AT_RAX: [u8; 3] = [0x0f, 0xb7, 0x08];
const MOVD_XMM0_ECX: [u8; 4] = [0x66, 0x0f, 0x6e, 0xc1];
const MOV_RCX_STATE_DISP32: [u8; 3] = [0x48, 0x8b, 0x8f];

pub(super) fn emit_register_offset(
    code: &mut Vec<u8>,
    operand: &Operand,
    checks: super::super::MemoryChecks,
) {
    super::super::register_offset::address(
        code,
        checks,
        operand.base,
        operand.index,
        operand.extend,
        operand.shift,
        operand.bytes,
    );
    let aligned = checks.stack_alignment
        && super::super::memory_store::aligned_register_offset(
            operand.base,
            operand.index,
            operand.shift,
            operand.bytes,
        );
    transfer(code, operand.load, operand.bytes, operand.vector, aligned);
}

/// S/D/Q at [RAX+displacement], using XMM0/XMM1. Loads zero higher bits.
/// Pair transfers use only positive second-element displacements 4/8/16.
pub(super) fn wide_transfer(
    code: &mut Vec<u8>,
    load: bool,
    bytes: u8,
    xmm: u8,
    displacement: u8,
    aligned: bool,
) {
    if !load {
        super::super::memory_store::emit(
            code,
            bytes,
            displacement,
            super::super::memory_store::Source::Xmm(xmm),
            aligned,
        );
        return;
    }
    let (prefix, opcode) = match bytes {
        DWORD_BYTES => (OPERAND_SIZE_PREFIX, MOVD_LOAD_OPCODE),
        QWORD_BYTES => (REP_PREFIX, MOVQ_LOAD_OPCODE),
        VECTOR_BYTES => (REP_PREFIX, MOVDQU_LOAD_OPCODE),
        _ => unreachable!("decoder validates wide vector memory width"),
    };
    let address_mode = if displacement == 0 { 0 } else { DISP8_ADDRESS };
    let modrm = (xmm << MODRM_REGISTER_SHIFT) | address_mode;
    code.extend([prefix, TWO_BYTE_OPCODE, opcode, modrm]);
    if displacement != 0 {
        code.push(displacement);
    }
}

/// Transfer one vector through RAX, without base writeback. A failed load
/// commits nothing.
pub(in crate::x86_64) fn transfer(
    code: &mut Vec<u8>,
    load: bool,
    bytes: u8,
    vector: u8,
    aligned: bool,
) {
    if load {
        match bytes {
            BYTE_BYTES | HALFWORD_BYTES => {
                // Never widen a guest access. MOVD clears every upper vector bit.
                code.extend(if bytes == BYTE_BYTES {
                    MOVZX_ECX_BYTE_AT_RAX
                } else {
                    MOVZX_ECX_WORD_AT_RAX
                });
                code.extend(MOVD_XMM0_ECX);
            }
            DWORD_BYTES | QWORD_BYTES | VECTOR_BYTES => {
                wide_transfer(code, true, bytes, 0, 0, aligned)
            }
            _ => unreachable!("decoder validates vector memory width"),
        }
        commit(code, vector, 0);
    } else if bytes <= HALFWORD_BYTES {
        code.extend(MOV_RCX_STATE_DISP32);
        code.extend(vector_offset(vector).to_le_bytes());
        super::super::memory_store::emit(
            code,
            bytes,
            0,
            super::super::memory_store::Source::Rcx,
            aligned,
        );
    } else {
        read_vector(code, vector, 0);
        wide_transfer(code, false, bytes, 0, 0, aligned);
    }
}
