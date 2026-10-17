//! LSE atomics. RDX holds the checked guest address on entry.
use super::{load, offset, store};
use crate::aarch64::{
    Register,
    atomic::{Kind, Operand},
};
use alloc::vec::Vec;

mod compare_exchange;
mod compare_exchange_pair;
mod read_modify_write;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const ATOMIC_GRANULE_BYTES: u8 = 16;
const DOUBLEWORD_PAIR_BYTES: u8 = 2 * QWORD_BYTES;
const ATOMIC_GRANULE_MASK: u8 = ATOMIC_GRANULE_BYTES - 1;
const TEST_AL_IMM8: &[u8] = &[0xa8];
const JE_REL8: u8 = 0x74;
const JBE_REL8: u8 = 0x76;
const UD2: &[u8] = &[0x0f, 0x0b];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const AND_ECX_IMM8: &[u8] = &[0x83, 0xe1];
const CMP_CL_IMM8: &[u8] = &[0x80, 0xf9];
const ADD_RAX_IMM32: &[u8] = &[0x48, 0x05];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const LOCK: u8 = 0xf0;
const OPERAND_SIZE_PREFIX: u8 = 0x66;
const REX_PREFIX: u8 = 0x40;
const REX_W_BIT: u8 = 0x08;
const REX_R_BIT: u8 = 0x04;
const TWO_BYTE_OPCODE: u8 = 0x0f;
const CMPXCHG_BYTE: u8 = 0xb0;
const CMPXCHG_WIDER: u8 = 0xb1;
const RDX_ADDRESS: u8 = 2;
const REGISTER_SHIFT: u8 = 3;
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const XOR_ECX_ECX: &[u8] = &[0x31, 0xc9];
const STATE_RAX: u8 = 0x87;
const STATE_RCX: u8 = 0x8f;
const MOVZX_BYTE: u8 = 0xb6;
const MOVZX_HALFWORD: u8 = 0xb7;
const MOV: u8 = 0x8b;

#[derive(Clone, Copy)]
enum InputRegister {
    Rax,
    Rcx,
}

#[derive(Clone, Copy)]
pub(super) enum ValueRegister {
    Rcx,
    R8,
}

pub(super) fn requires_cx16(operand: &Operand) -> bool {
    matches!(operand.kind, Kind::CompareExchangePair { .. })
        && operand.bytes == DOUBLEWORD_PAIR_BYTES
}

pub(super) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    target: crate::TargetCpu,
    checks: super::MemoryChecks,
) {
    address(code, operand.base, operand.bytes, checks);
    match operand.kind {
        Kind::CompareExchange { .. } => compare_exchange::emit(code, operand),
        Kind::CompareExchangePair { .. } => compare_exchange_pair::emit(code, operand, target),
        Kind::ReadModifyWrite { .. } => read_modify_write::emit(code, operand),
    }
}

/// SP is checked first. LSE2 accesses must fit the selected aligned 16-byte granule.
/// RAX/RCX are scratch, RDX receives the address, and guest state is untouched.
pub(super) fn address(code: &mut Vec<u8>, base: Register, bytes: u8, checks: super::MemoryChecks) {
    address_offset(code, base, bytes, 0, checks, true);
}

/// Check SP before adding the displacement. SCTLR_ELx.A and then, with
/// `granule`, the single-copy-atomic boundary apply to the effective address;
/// a known-aligned SP needs no run-time boundary test. Without the SP
/// alignment check, SP is an ordinary base.
pub(super) fn address_offset(
    code: &mut Vec<u8>,
    base: Register,
    bytes: u8,
    displacement: i32,
    checks: super::MemoryChecks,
    granule: bool,
) {
    load(code, base);
    let aligned_sp = base == Register::Sp && checks.stack_alignment;
    if aligned_sp {
        code.extend(TEST_AL_IMM8);
        code.push(ATOMIC_GRANULE_MASK);
        code.extend([JE_REL8, UD2.len() as u8]);
        code.extend(UD2);
    }
    if displacement != 0 {
        code.extend(ADD_RAX_IMM32);
        code.extend(displacement.to_le_bytes());
    }
    super::alignment_check(code, checks, bytes);
    if granule && bytes != BYTE_BYTES {
        if !aligned_sp {
            code.extend(MOV_ECX_EAX);
            code.extend(AND_ECX_IMM8);
            code.push(ATOMIC_GRANULE_MASK);
            code.extend(CMP_CL_IMM8);
            code.push(ATOMIC_GRANULE_BYTES - bytes);
            code.extend([JBE_REL8, UD2.len() as u8]);
            code.extend(UD2);
        } else if displacement.rem_euclid(i32::from(ATOMIC_GRANULE_BYTES))
            > i32::from(ATOMIC_GRANULE_BYTES - bytes)
        {
            code.extend(UD2);
        }
    }
    code.extend(MOV_RDX_RAX);
}

fn input(code: &mut Vec<u8>, bytes: u8, register: Register, destination: InputRegister) {
    let rcx = matches!(destination, InputRegister::Rcx);
    let Some(displacement) = offset(register) else {
        code.extend(if rcx { XOR_ECX_ECX } else { XOR_EAX_EAX });
        return;
    };
    let modrm = if rcx { STATE_RCX } else { STATE_RAX };
    match bytes {
        BYTE_BYTES => code.extend([TWO_BYTE_OPCODE, MOVZX_BYTE, modrm]),
        HALFWORD_BYTES => code.extend([TWO_BYTE_OPCODE, MOVZX_HALFWORD, modrm]),
        DWORD_BYTES => code.extend([MOV, modrm]),
        QWORD_BYTES => code.extend([REX_PREFIX | REX_W_BIT, MOV, modrm]),
        _ => unreachable!("decoder validates atomic widths"),
    }
    code.extend(displacement.to_le_bytes());
}

pub(super) fn input_rax(code: &mut Vec<u8>, bytes: u8, register: Register) {
    input(code, bytes, register, InputRegister::Rax);
}

pub(super) fn input_rcx(code: &mut Vec<u8>, bytes: u8, register: Register) {
    input(code, bytes, register, InputRegister::Rcx);
}

pub(super) fn read_rax(code: &mut Vec<u8>, bytes: u8) {
    match bytes {
        BYTE_BYTES => code.extend([TWO_BYTE_OPCODE, MOVZX_BYTE, RDX_ADDRESS]),
        HALFWORD_BYTES => code.extend([TWO_BYTE_OPCODE, MOVZX_HALFWORD, RDX_ADDRESS]),
        DWORD_BYTES => code.extend([MOV, RDX_ADDRESS]),
        QWORD_BYTES => code.extend([REX_PREFIX | REX_W_BIT, MOV, RDX_ADDRESS]),
        _ => unreachable!("decoder validates atomic widths"),
    }
}

/// Input staging and exact-width updates keep the complete old value zero-extended.
pub(super) fn commit_rax(code: &mut Vec<u8>, bytes: u8, destination: Register) {
    debug_assert!(matches!(
        bytes,
        BYTE_BYTES | HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES
    ));
    store(code, destination);
}

pub(super) fn locked_compare_exchange(code: &mut Vec<u8>, bytes: u8, source: ValueRegister) {
    code.push(LOCK);
    if bytes == HALFWORD_BYTES {
        code.push(OPERAND_SIZE_PREFIX);
    }
    let extended = matches!(source, ValueRegister::R8);
    let rex =
        if bytes == QWORD_BYTES { REX_W_BIT } else { 0 } | if extended { REX_R_BIT } else { 0 };
    if rex != 0 {
        code.push(REX_PREFIX | rex);
    }
    code.extend([
        TWO_BYTE_OPCODE,
        if bytes == BYTE_BYTES {
            CMPXCHG_BYTE
        } else {
            CMPXCHG_WIDER
        },
    ]);
    let source_low = u8::from(!extended); // RCX=1; R8's low register bits=0.
    code.push((source_low << REGISTER_SHIFT) | RDX_ADDRESS);
}
