//! Exact packed Single products with integer Half rounding and private status.
//! The parent stages and classifies active inputs before entering this module.
use super::super::super::super::isa::ShiftOpcode;
use super::super::super::numerical::{
    ArithmeticOpcode, Condition, RESULT_MINIMUM_EXPONENT, branch, emit_opcode_to, resolve,
};
use super::super::super::{Host, packed, shuffle};
use crate::{
    GuestAddress, GuestState,
    aarch64::{
        floating::{BinaryOperation, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT, Format, INEXACT},
        simd::arithmetic::{Operand, Shape},
    },
    block::ExitKind,
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const RESULT: u8 = 2;
const TEMPORARY: u8 = 3;
const SIGN: u8 = 4;
const ZERO: u8 = 5;
const CONSTANT: u8 = 6;
const ACCUMULATED: u8 = 7;
const EAX: u8 = 0;
const REPLICATE_FIRST_DWORD: u8 = 0;
const SIGN_BITS: u8 = 1;
const GROUP_LANES: u8 = 4;
const GROUP_BYTES: u8 = GROUP_LANES * (u16::BITS / u8::BITS) as u8;
const ACTIVE_LANE_MASK: u32 = (1 << GROUP_LANES) - 1;
const GROUP_COUNT: u32 = 2;
const SINGLE_BITS: u8 = u32::BITS as u8;
const SIGN_POSITION: u8 = SINGLE_BITS - SIGN_BITS;
const HALF_BITS: u8 = u16::BITS as u8;
const HALF_SIGN_POSITION: u8 = HALF_BITS - SIGN_BITS;
const DISCARDED_BITS: u8 = (Format::Single.fraction_bits() - Format::Half.fraction_bits()) as u8;
const DISCARDED_MASK: u32 = (1 << DISCARDED_BITS) - 1;
const NEAREST_BIAS: u32 = DISCARDED_MASK >> 1;
const SINGLE_HALF_BIAS: u32 = (Format::Single.exponent_bias() - Format::Half.exponent_bias())
    << Format::Single.fraction_bits();
const MINIMUM_PRODUCT: u32 =
    SINGLE_HALF_BIAS + ((RESULT_MINIMUM_EXPONENT as u32) << Format::Single.fraction_bits());
const MAXIMUM_PRODUCT: u32 = SINGLE_HALF_BIAS
    + (((Format::Half.exponent_mask() >> Format::Half.fraction_bits()) as u32)
        << Format::Single.fraction_bits());
const ROUND_TOWARD_POSITIVE: u8 = 1;
const REGISTER_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MOVD_XMM_EAX_PREFIX: &[u8] = &[0x66, 0x0f, 0x6e];
const MOVD_XMM_EXTENDED_GPR_PREFIX: &[u8] = &[0x66, 0x41, 0x0f, 0x6e];
const MOV_EAX_IMM32: u8 = 0xb8;
const MOV_ECX_STATE: &[u8] = &[0x8b, 0x8f];
const SHR_ECX_IMM8: &[u8] = &[0xc1, 0xe9];
const AND_ECX_IMM8: &[u8] = &[0x83, 0xe1];
const TEST_ECX_ECX: &[u8] = &[0x85, 0xc9];
const SETE_AL: &[u8] = &[0x0f, 0x94, 0xc0];
const SETNE_AL: &[u8] = &[0x0f, 0x95, 0xc0];
const MOVZX_EAX_AL: &[u8] = &[0x0f, 0xb6, 0xc0];
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
const TEST_EAX_IMM32: u8 = 0xa9;
const NOT_EAX: &[u8] = &[0xf7, 0xd0];
const AND_EAX_IMM8: &[u8] = &[0x83, 0xe0];
const OR_R10D_EAX: &[u8] = &[0x41, 0x09, 0xc2];
const TEST_R10D_R10D: &[u8] = &[0x45, 0x85, 0xd2];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const MOV_R10D_EAX: &[u8] = &[0x41, 0x89, 0xc2];
const MOV_ECX_IMM32: u8 = 0xb9;
const DEC_ECX: &[u8] = &[0xff, 0xc9];
const JMP_REL32: u8 = 0xe9;

/// Low ModRM bits of the caller-volatile extended rounding registers.
#[repr(u8)]
enum RoundingRegister {
    Bias = 0,      // R8D
    Direction = 1, // R9D
    Parity = 3,    // R11D
}

fn jump(code: &mut Vec<u8>) -> usize {
    code.push(JMP_REL32);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}

fn constant(code: &mut Vec<u8>, vector: u8, value: u32) {
    code.push(MOV_EAX_IMM32);
    code.extend(value.to_le_bytes());
    code.extend(MOVD_XMM_EAX_PREFIX);
    code.push(REGISTER_DIRECT | vector << MODRM_REGISTER_SHIFT);
    shuffle(code, vector, vector, REPLICATE_FIRST_DWORD);
}

fn broadcast_rounding(code: &mut Vec<u8>, vector: u8, register: RoundingRegister) {
    code.extend(MOVD_XMM_EXTENDED_GPR_PREFIX);
    code.push(REGISTER_DIRECT | vector << MODRM_REGISTER_SHIFT | register as u8);
    shuffle(code, vector, vector, REPLICATE_FIRST_DWORD);
}

/// Uniform guest rounding selectors; AH does not alter ordinary binary policy.
/// Bias/direction/parity for RN, R+, R-, RZ are respectively
/// (0xfff,0,1), (0x1fff,0x1fff,0), (0,0x1fff,0), (0,0,0).
fn rounding_policy(code: &mut Vec<u8>) {
    code.extend(MOV_ECX_STATE);
    code.extend((std::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
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
    code.extend(DISCARDED_MASK.to_le_bytes());
    code.extend(MOV_R9D_EDX);
    code.extend(XOR_R8D_R8D);
    code.extend(TEST_ECX_ECX);
    let not_nearest = branch(code, Condition::NotZero);
    code.extend(MOV_R8D_IMM32);
    code.extend(NEAREST_BIAS.to_le_bytes());
    let nearest = jump(code);
    let directed = code.len();
    resolve(code, not_nearest, directed);
    code.extend(CMP_ECX_IMM8);
    code.push(ROUND_TOWARD_POSITIVE);
    let not_positive = branch(code, Condition::NotZero);
    code.extend(MOV_R8D_IMM32);
    code.extend(DISCARDED_MASK.to_le_bytes());
    let ready = code.len();
    resolve(code, not_positive, ready);
    resolve(code, nearest, ready);
    code.extend(XOR_R10D_R10D);
}

/// Even inactive raw Half fields become finite normal Single values. Thus this
/// exact 11-bit widening and the following 22-bit product cannot raise status.
fn widen(code: &mut Vec<u8>, destination: u8, source: u8) {
    packed(code, Host::MoveAligned, destination, source);
    packed(code, Host::UnpackLowWord, destination, ZERO);
    packed(code, Host::MoveAligned, SIGN, destination);
    ShiftOpcode::LeftDword.emit(code, SIGN, SINGLE_BITS - HALF_BITS);
    ShiftOpcode::RightDword.emit(code, SIGN, SIGN_POSITION);
    ShiftOpcode::LeftDword.emit(code, SIGN, SIGN_POSITION);
    ShiftOpcode::LeftDword.emit(code, destination, SINGLE_BITS - HALF_BITS + SIGN_BITS);
    ShiftOpcode::RightDword.emit(
        code,
        destination,
        SINGLE_BITS - HALF_BITS + SIGN_BITS - DISCARDED_BITS,
    );
    packed(code, Host::AddDword, destination, CONSTANT);
    packed(code, Host::Or, destination, SIGN);
}

/// One four-lane group, with fresh IXC accumulating only in private R10D.
fn group(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    packed(code, Host::Xor, ZERO, ZERO);
    constant(code, CONSTANT, SINGLE_HALF_BIAS);
    widen(code, RESULT, LEFT);
    widen(code, TEMPORARY, RIGHT);
    emit_opcode_to(
        code,
        Format::Single,
        Shape::Vector128,
        ArithmeticOpcode::Multiply,
        RESULT,
        TEMPORARY,
    );
    packed(code, Host::MoveAligned, SIGN, RESULT);
    ShiftOpcode::ArithmeticDword.emit(code, SIGN, SIGN_POSITION);
    ShiftOpcode::LeftDword.emit(code, RESULT, SIGN_BITS);
    ShiftOpcode::RightDword.emit(code, RESULT, SIGN_BITS);
    // Both sides of the unsigned interval must fit before target rounding.
    constant(code, ZERO, MINIMUM_PRODUCT);
    constant(code, CONSTANT, MAXIMUM_PRODUCT - MINIMUM_PRODUCT - 1);
    packed(code, Host::MoveAligned, TEMPORARY, RESULT);
    packed(code, Host::SubDword, TEMPORARY, ZERO);
    packed(code, Host::SubDword, CONSTANT, TEMPORARY);
    packed(code, Host::Or, TEMPORARY, CONSTANT);
    packed(code, Host::DwordSignMask, EAX, TEMPORARY);
    code.push(TEST_EAX_IMM32);
    code.extend(ACTIVE_LANE_MASK.to_le_bytes());
    helper.push(branch(code, Condition::NotZero));
    // MULPS was exact; Half IXC comes from the discarded thirteen bits.
    packed(code, Host::MoveAligned, TEMPORARY, RESULT);
    ShiftOpcode::LeftDword.emit(code, TEMPORARY, SINGLE_BITS - DISCARDED_BITS);
    packed(code, Host::Xor, ZERO, ZERO);
    packed(code, Host::EqualDword, TEMPORARY, ZERO);
    packed(code, Host::DwordSignMask, EAX, TEMPORARY);
    code.extend(NOT_EAX);
    code.extend(AND_EAX_IMM8);
    code.push(ACTIVE_LANE_MASK as u8);
    code.extend(OR_R10D_EAX);
    // Increment = retained parity + ((product sign & direction) XOR bias).
    packed(code, Host::MoveAligned, TEMPORARY, RESULT);
    ShiftOpcode::RightDword.emit(code, TEMPORARY, DISCARDED_BITS);
    broadcast_rounding(code, ZERO, RoundingRegister::Parity);
    packed(code, Host::And, TEMPORARY, ZERO);
    broadcast_rounding(code, ZERO, RoundingRegister::Direction);
    packed(code, Host::And, ZERO, SIGN);
    broadcast_rounding(code, CONSTANT, RoundingRegister::Bias);
    packed(code, Host::Xor, ZERO, CONSTANT);
    packed(code, Host::AddDword, TEMPORARY, ZERO);
    packed(code, Host::AddDword, RESULT, TEMPORARY);
    // The nonnegative increment preserves the preguard's lower bound.
    constant(code, CONSTANT, MAXIMUM_PRODUCT);
    packed(code, Host::GreaterDword, CONSTANT, RESULT);
    packed(code, Host::DwordSignMask, EAX, CONSTANT);
    code.extend(NOT_EAX);
    code.push(TEST_EAX_IMM32);
    code.extend(ACTIVE_LANE_MASK.to_le_bytes());
    helper.push(branch(code, Condition::NotZero));
    constant(code, CONSTANT, SINGLE_HALF_BIAS);
    packed(code, Host::SubDword, RESULT, CONSTANT);
    ShiftOpcode::RightDword.emit(code, RESULT, DISCARDED_BITS);
    ShiftOpcode::LeftDword.emit(code, SIGN, HALF_SIGN_POSITION);
    packed(code, Host::Or, RESULT, SIGN);
    // Negative raw Half bits are sign-extended before signed saturation packing.
    packed(code, Host::PackSignedDwordToWord, RESULT, RESULT);
}

pub(super) fn supports(operand: &Operand) -> bool {
    operand.shape != Shape::Scalar
        && matches!(
            operand.operation,
            BinaryOperation::Multiply | BinaryOperation::MultiplyExtended
        )
}

/// Return XMM0 and private fresh IXC after every group passes. No stack or host
/// environment changes are needed, so every failed guard enters the cold helper.
pub(super) fn emit(code: &mut Vec<u8>, shape: Shape, mut helper: Vec<usize>, pc: GuestAddress) {
    rounding_policy(code);
    if shape == Shape::Vector128 {
        // ECX is dead after rounding_policy; group scratch uses only EAX.
        code.push(MOV_ECX_IMM32);
        code.extend(GROUP_COUNT.to_le_bytes());
        packed(code, Host::Xor, ACCUMULATED, ACCUMULATED);
        let repeat = code.len();
        group(code, &mut helper);
        ShiftOpcode::RightBytes.emit(code, ACCUMULATED, GROUP_BYTES);
        packed(code, Host::UnpackLowQword, ACCUMULATED, RESULT);
        ShiftOpcode::RightBytes.emit(code, LEFT, GROUP_BYTES);
        ShiftOpcode::RightBytes.emit(code, RIGHT, GROUP_BYTES);
        code.extend(DEC_ECX);
        let more = branch(code, Condition::NotZero);
        resolve(code, more, repeat);
        packed(code, Host::MoveAligned, LEFT, ACCUMULATED);
    } else {
        group(code, &mut helper);
        // Q0 clears the complete upper qword, despite PACKSSDW duplication.
        packed(code, Host::MoveQword, LEFT, RESULT);
    }
    code.extend(TEST_R10D_R10D);
    code.extend(SETNE_AL);
    code.extend(MOVZX_EAX_AL);
    code.extend(SHL_EAX_IMM8);
    code.push(INEXACT.trailing_zeros() as u8);
    code.extend(MOV_R10D_EAX);
    let completed = jump(code);
    let helper_start = code.len();
    super::super::super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, completed, success);
}
