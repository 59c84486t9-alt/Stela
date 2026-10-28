//! Half-precision products: packed single multiplies with integer rounding to half.
use super::super::super::super::isa::ShiftOpcode;
use super::super::super::numerical::{
    ArithmeticOpcode, Condition, IntegerRoundingRegister, RESULT_MINIMUM_EXPONENT, branch,
    broadcast_integer_rounding, emit_opcode_to, integer_rounding_policy, resolve,
    widen_half_to_single,
};
use super::super::super::{Host, packed, shuffle};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, ShiftOp, Size, Unary};
use crate::{
    GuestAddress,
    aarch64::{
        floating::{BinaryOperation, Format, INEXACT},
        simd::arithmetic::{Operand, Shape},
    },
    block::ExitKind,
};
use alloc::vec::Vec;

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
const SINGLE_HALF_BIAS: u32 = (Format::Single.exponent_bias() - Format::Half.exponent_bias())
    << Format::Single.fraction_bits();
const MINIMUM_PRODUCT: u32 =
    SINGLE_HALF_BIAS + ((RESULT_MINIMUM_EXPONENT as u32) << Format::Single.fraction_bits());
const MAXIMUM_PRODUCT: u32 = SINGLE_HALF_BIAS
    + (((Format::Half.exponent_mask() >> Format::Half.fraction_bits()) as u32)
        << Format::Single.fraction_bits());
use Gpr::{R10, Rax, Rcx};

fn jump(code: &mut Code) -> usize {
    code.asm().jmp().offset()
}

fn constant(code: &mut Code, vector: u8, value: u32) {
    let mut asm = code.asm();
    asm.mov_imm32(Rax, value);
    asm.movd_to_xmm(vector, Rax);
    shuffle(code, vector, vector, REPLICATE_FIRST_DWORD);
}

/// One four-lane group, with fresh IXC accumulating only in private R10D.
fn group(code: &mut Code, helper: &mut Vec<usize>) {
    packed(code, Host::Xor, ZERO, ZERO);
    constant(code, CONSTANT, SINGLE_HALF_BIAS);
    widen_half_to_single(code, RESULT, LEFT, SIGN, ZERO, CONSTANT);
    widen_half_to_single(code, TEMPORARY, RIGHT, SIGN, ZERO, CONSTANT);
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
    code.asm()
        .test_accumulator_imm(Size::Dword, ACTIVE_LANE_MASK as i32);
    helper.push(branch(code, Condition::NotZero));
    // MULPS was exact; Half IXC comes from the discarded thirteen bits.
    packed(code, Host::MoveAligned, TEMPORARY, RESULT);
    ShiftOpcode::LeftDword.emit(code, TEMPORARY, SINGLE_BITS - DISCARDED_BITS);
    packed(code, Host::Xor, ZERO, ZERO);
    packed(code, Host::EqualDword, TEMPORARY, ZERO);
    packed(code, Host::DwordSignMask, EAX, TEMPORARY);
    let mut asm = code.asm();
    asm.unary(Unary::Not, Size::Dword, Rax);
    asm.alu_imm8(Alu::And, Size::Dword, Rax, ACTIVE_LANE_MASK as i8);
    asm.alu(Alu::Or, Size::Dword, R10, Rax);
    // Increment = retained parity + ((product sign & direction) XOR bias).
    packed(code, Host::MoveAligned, TEMPORARY, RESULT);
    ShiftOpcode::RightDword.emit(code, TEMPORARY, DISCARDED_BITS);
    broadcast_integer_rounding(code, ZERO, IntegerRoundingRegister::Parity);
    packed(code, Host::And, TEMPORARY, ZERO);
    broadcast_integer_rounding(code, ZERO, IntegerRoundingRegister::Direction);
    packed(code, Host::And, ZERO, SIGN);
    broadcast_integer_rounding(code, CONSTANT, IntegerRoundingRegister::Bias);
    packed(code, Host::Xor, ZERO, CONSTANT);
    packed(code, Host::AddDword, TEMPORARY, ZERO);
    packed(code, Host::AddDword, RESULT, TEMPORARY);
    // The nonnegative increment preserves the preguard's lower bound.
    constant(code, CONSTANT, MAXIMUM_PRODUCT);
    packed(code, Host::GreaterDword, CONSTANT, RESULT);
    packed(code, Host::DwordSignMask, EAX, CONSTANT);
    let mut asm = code.asm();
    asm.unary(Unary::Not, Size::Dword, Rax);
    asm.test_accumulator_imm(Size::Dword, ACTIVE_LANE_MASK as i32);
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
pub(super) fn emit(code: &mut Code, shape: Shape, mut helper: Vec<usize>, pc: GuestAddress) {
    integer_rounding_policy(code, DISCARDED_BITS, false);
    if shape == Shape::Vector128 {
        // ECX is dead after integer_rounding_policy; group scratch uses only EAX.
        code.asm().mov_imm32(Rcx, GROUP_COUNT);
        packed(code, Host::Xor, ACCUMULATED, ACCUMULATED);
        let repeat = code.len();
        group(code, &mut helper);
        ShiftOpcode::RightBytes.emit(code, ACCUMULATED, GROUP_BYTES);
        packed(code, Host::UnpackLowQword, ACCUMULATED, RESULT);
        ShiftOpcode::RightBytes.emit(code, LEFT, GROUP_BYTES);
        ShiftOpcode::RightBytes.emit(code, RIGHT, GROUP_BYTES);
        code.asm().dec(Size::Dword, Rcx);
        let more = branch(code, Condition::NotZero);
        resolve(code, more, repeat);
        packed(code, Host::MoveAligned, LEFT, ACCUMULATED);
    } else {
        group(code, &mut helper);
        // Q0 clears the complete upper qword, despite PACKSSDW duplication.
        packed(code, Host::MoveQword, LEFT, RESULT);
    }
    let mut asm = code.asm();
    asm.test(Size::Dword, R10, R10);
    asm.setcc(Cond::Ne, Rax);
    asm.movzx(Size::Dword, Rax, Size::Byte, Rax);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Dword,
        Rax,
        INEXACT.trailing_zeros() as u8,
    );
    asm.mov(Size::Dword, R10, Rax);
    let completed = jump(code);
    let helper_start = code.len();
    super::super::super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, completed, success);
}
