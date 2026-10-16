//! Integer quantization selectors shared by IEEE Half and BF16 mappings.
use super::super::shuffle;
use super::{
    AND_ECX_IMM32, Condition, MOV_ECX_STATE, SHR_ECX_IMM8, TEST_ECX_IMM32, branch, resolve,
};
use crate::GuestState;
use alloc::vec::Vec;

const ROUND_TOWARD_POSITIVE: u8 = 1;
const MOVD_XMM_EXTENDED_GPR_PREFIX: &[u8] = &[0x66, 0x41, 0x0f, 0x6e];
const AND_ECX_IMM8: &[u8] = &[0x83, 0xe1];
const TEST_ECX_ECX: &[u8] = &[0x85, 0xc9];
const SETE_AL: &[u8] = &[0x0f, 0x94, 0xc0];
const MOV_R11D_EAX: &[u8] = &[0x44, 0x8b, 0xd8];
const LEA_EDX_RCX_PLUS_ONE: &[u8] = &[0x8d, 0x51, 0x01];
const SHR_EDX_ONE: &[u8] = &[0xd1, 0xea];
const AND_EDX_ONE: &[u8] = &[0x83, 0xe2, 0x01];
const NEG_EDX: &[u8] = &[0xf7, 0xda];
const AND_EDX_IMM32: &[u8] = &[0x81, 0xe2];
const MOV_R9D_EDX: &[u8] = &[0x41, 0x89, 0xd1];
const XOR_R8D_R8D: &[u8] = &[0x45, 0x31, 0xc0];
const MOV_R8D_IMM32: &[u8] = &[0x41, 0xb8];
const CMP_ECX_IMM8: &[u8] = &[0x83, 0xf9];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const MOVZX_EAX_AL: &[u8] = &[0x0f, 0xb6, 0xc0];
const REGISTER_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const REPLICATE_FIRST_DWORD: u8 = 0;

/// Low ModRM bits of the caller-volatile extended rounding registers.
#[repr(u8)]
pub(in crate::x86_64) enum IntegerRoundingRegister {
    Bias = 0,      // R8D
    Direction = 1, // R9D
    Parity = 3,    // R11D
}

pub(in crate::x86_64) fn broadcast_integer_rounding(
    code: &mut Vec<u8>,
    vector: u8,
    register: IntegerRoundingRegister,
) {
    code.extend(MOVD_XMM_EXTENDED_GPR_PREFIX);
    code.push(REGISTER_DIRECT | vector << MODRM_REGISTER_SHIFT | register as u8);
    shuffle(code, vector, vector, REPLICATE_FIRST_DWORD);
}

/// Prepare integer quantization bias, sign direction and retained-bit parity.
/// R10D starts fresh exception accumulation; ordinary arithmetic keeps guest RC,
/// while BF16 conversion selects nearest-even when alternative handling is set.
pub(in crate::x86_64) fn integer_rounding_policy(
    code: &mut Vec<u8>,
    discarded_bits: u8,
    alternative_nearest: bool,
) {
    use crate::aarch64::floating::{FPCR_AH, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT};
    assert!(discarded_bits > 0 && u32::from(discarded_bits) < u32::BITS);
    let discarded_mask = (1u32 << discarded_bits) - 1;
    let nearest_bias = discarded_mask >> 1;
    code.extend(MOV_ECX_STATE);
    code.extend((core::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
    if alternative_nearest {
        code.extend(TEST_ECX_IMM32);
        code.extend(FPCR_AH.to_le_bytes());
        let ordinary = branch(code, Condition::Zero);
        code.extend(AND_ECX_IMM32);
        code.extend((!(FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT)).to_le_bytes());
        let ready = code.len();
        resolve(code, ordinary, ready);
    }
    code.extend(SHR_ECX_IMM8);
    code.push(FPCR_ROUNDING_SHIFT as u8);
    code.extend(AND_ECX_IMM8);
    code.push(FPCR_ROUNDING_MASK as u8);
    code.extend(TEST_ECX_ECX);
    code.extend(SETE_AL);
    code.extend(MOVZX_EAX_AL);
    code.extend(MOV_R11D_EAX);
    // -(((mode+1)>>1)&1) selects both directed modes, independent of sign.
    code.extend(LEA_EDX_RCX_PLUS_ONE);
    code.extend(SHR_EDX_ONE);
    code.extend(AND_EDX_ONE);
    code.extend(NEG_EDX);
    code.extend(AND_EDX_IMM32);
    code.extend(discarded_mask.to_le_bytes());
    code.extend(MOV_R9D_EDX);
    code.extend(XOR_R8D_R8D);
    code.extend(TEST_ECX_ECX);
    let not_nearest = branch(code, Condition::NotZero);
    code.extend(MOV_R8D_IMM32);
    code.extend(nearest_bias.to_le_bytes());
    const JMP_REL32: u8 = 0xe9;
    code.push(JMP_REL32);
    let nearest = code.len();
    code.extend(0i32.to_le_bytes());
    let directed = code.len();
    resolve(code, not_nearest, directed);
    code.extend(CMP_ECX_IMM8);
    code.push(ROUND_TOWARD_POSITIVE);
    let not_positive = branch(code, Condition::NotZero);
    code.extend(MOV_R8D_IMM32);
    code.extend(discarded_mask.to_le_bytes());
    let ready = code.len();
    resolve(code, not_positive, ready);
    resolve(code, nearest, ready);
    code.extend(XOR_R10D_R10D);
}
