//! Incremental architectural predicate-test flags.

use super::{CHUNK_BITS, bind, jump};
use alloc::vec::Vec;

const JZ: &[u8] = &[0x0f, 0x84];
const MOV_R8D_IMM32: &[u8] = &[0x41, 0xb8];
const XOR_R9D_R9D: &[u8] = &[0x45, 0x31, 0xc9];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const MOV_RDX_R11: &[u8] = &[0x4c, 0x89, 0xda];
const MOVABS_RCX: &[u8] = &[0x48, 0xb9];
const AND_RDX_RCX: &[u8] = &[0x48, 0x21, 0xca];
const TEST_RDX_RDX: &[u8] = &[0x48, 0x85, 0xd2];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const AND_RCX_RDX: &[u8] = &[0x48, 0x21, 0xd1];
const OR_R9_RCX: &[u8] = &[0x49, 0x09, 0xc9];
const TEST_R10D_R10D: &[u8] = &[0x45, 0x85, 0xd2];
const JNZ: &[u8] = &[0x0f, 0x85];
const BSF_RCX_RDX: &[u8] = &[0x48, 0x0f, 0xbc, 0xca];
const BSR_RCX_RDX: &[u8] = &[0x48, 0x0f, 0xbd, 0xca];
const BT_RAX_RCX: &[u8] = &[0x48, 0x0f, 0xa3, 0xc8];
const SETC_CL: &[u8] = &[0x0f, 0x92, 0xc1];
const SETNC_CL: &[u8] = &[0x0f, 0x93, 0xc1];
const MOVZX_ECX_CL: &[u8] = &[0x0f, 0xb6, 0xc9];
const SHL_ECX_IMM8: &[u8] = &[0xc1, 0xe1];
const OR_R8D_ECX: &[u8] = &[0x41, 0x09, 0xc8];
const AND_R8D_IMM32: &[u8] = &[0x41, 0x81, 0xe0];
const MOV_R10D_ONE: &[u8] = &[0x41, 0xba, 1, 0, 0, 0];
const TEST_R9_R9: &[u8] = &[0x4d, 0x85, 0xc9];
const SETZ_AL: &[u8] = &[0x0f, 0x94, 0xc0];
const MOVZX_EAX_AL: &[u8] = &[0x0f, 0xb6, 0xc0];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const OR_EAX_R8D: &[u8] = &[0x44, 0x09, 0xc0];
const MOV_STATE_DISP32_EAX: &[u8] = &[0x89, 0x87];
const NZCV_N_SHIFT: u8 = 31;
const NZCV_Z_SHIFT: u8 = 30;
const NZCV_C_SHIFT: u8 = 29;

pub(crate) fn leading_bits(element: crate::aarch64::scalable::ElementSize) -> u64 {
    (0..CHUNK_BITS)
        .step_by(element.bytes())
        .fold(0, |mask, bit| mask | (1 << bit))
}

pub(crate) fn begin_predtest(code: &mut Vec<u8>) {
    code.extend(MOV_R8D_IMM32);
    code.extend((1u32 << NZCV_C_SHIFT).to_le_bytes());
    code.extend(XOR_R9D_R9D);
    code.extend(XOR_R10D_R10D);
}

pub(crate) fn accumulate_predtest(
    code: &mut Vec<u8>,
    element: crate::aarch64::scalable::ElementSize,
) {
    code.extend(MOV_RDX_R11);
    if element != crate::aarch64::scalable::ElementSize::Byte {
        code.extend(MOVABS_RCX);
        code.extend(leading_bits(element).to_le_bytes());
        code.extend(AND_RDX_RCX);
    }
    code.extend(TEST_RDX_RDX);
    let empty = jump(code, JZ);
    code.extend(MOV_RCX_RAX);
    code.extend(AND_RCX_RDX);
    code.extend(OR_R9_RCX);
    code.extend(TEST_R10D_R10D);
    let seen = jump(code, JNZ);
    code.extend(BSF_RCX_RDX);
    code.extend(BT_RAX_RCX);
    code.extend(SETC_CL);
    code.extend(MOVZX_ECX_CL);
    code.extend(SHL_ECX_IMM8);
    code.push(NZCV_N_SHIFT);
    code.extend(OR_R8D_ECX);
    bind(code, seen);
    code.extend(BSR_RCX_RDX);
    code.extend(BT_RAX_RCX);
    code.extend(SETNC_CL);
    code.extend(MOVZX_ECX_CL);
    code.extend(SHL_ECX_IMM8);
    code.push(NZCV_C_SHIFT);
    code.extend(AND_R8D_IMM32);
    code.extend((!(1u32 << NZCV_C_SHIFT)).to_le_bytes());
    code.extend(OR_R8D_ECX);
    code.extend(MOV_R10D_ONE);
    bind(code, empty);
}

pub(crate) fn finish_predtest(code: &mut Vec<u8>) {
    code.extend(TEST_R9_R9);
    code.extend(SETZ_AL);
    code.extend(MOVZX_EAX_AL);
    code.extend(SHL_EAX_IMM8);
    code.push(NZCV_Z_SHIFT);
    code.extend(OR_EAX_R8D);
    code.extend(MOV_STATE_DISP32_EAX);
    code.extend((core::mem::offset_of!(crate::GuestState, nzcv) as u32).to_le_bytes());
}
