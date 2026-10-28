//! FRINT*: integer baseline, or SSE4.1 ROUND with exceptions masked.
use super::numerical::{emit_opcode_to, float_lanes, helper_section, jump};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Rm, ShiftOp, Size};
use crate::x86_64::simd::encode::{BitTest, guest};
use Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdx};
use alloc::vec::Vec;
pub(in crate::x86_64) mod kernel;
use super::super::isa::ShiftOpcode;
use super::numerical::{
    ArithmeticOpcode, Condition, EXPONENT_VECTOR, branch, clear_scalar, prepare_vector_input_range,
    read_numerical_vector, resolve, test_control, vector_exponent_range,
};
use super::{Host, commit, packed, read_vector};
use crate::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{
            FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, FPCR_ROUNDING_SHIFT, Format, INEXACT,
            rounding::RoundingOperation,
        },
        simd::{arithmetic::Shape, rounding::Operand},
    },
};

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const TEMP: u8 = 2;
const RESIDUAL: u8 = 3;
const MASK: u8 = 4;
const CONSTANT: u8 = 5;
const SAVED_HALF: u8 = 6;
const ORIGINAL_HALF: u8 = 7;
const SIGN_BITS: u32 = 1;
const ACCUMULATOR_GPR: u8 = 0;
const FIRST_LANE: u8 = 0;
const BROADCAST_LOW_DWORD: u8 = 0;
const SINGLE_LOW_MASK: u32 = 0x03;
const SINGLE_FULL_MASK: u32 = 0x0f;
const DOUBLE_FULL_MASK: u32 = 0x05;
const BITS_PER_BYTE: u32 = u8::BITS;
const PRECISION_SUPPRESSED: u8 = 1 << 3;
const ROUND_NEAREST: u8 = 0;
const ROUND_NEGATIVE: u8 = 1;
const ROUND_POSITIVE: u8 = 2;
const ROUND_ZERO: u8 = 3;
const FPCR_LOW_ROUNDING_BIT: u32 = 1 << FPCR_ROUNDING_SHIFT;
const FPCR_HIGH_ROUNDING_BIT: u32 = 1 << (FPCR_ROUNDING_SHIFT + 1);
const INEXACT_SHIFT: u8 = INEXACT.trailing_zeros() as u8;
const COMPARE_LESS_EQUAL: u8 = 2;
const ADJACENT_DWORDS: u8 = 0xb1;

#[derive(Clone, Copy)]
enum Direction {
    NearestEven,
    NearestAway,
    Positive,
    Negative,
    Zero,
}

/// `and eax, value; cmp eax, value`: ZF is set when every `value` bit is set.
fn all_bits(code: &mut Code, value: u32) {
    let mut asm = code.asm();
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, value as i32);
    asm.alu_accumulator_imm32(Alu::Cmp, Size::Dword, value as i32);
}

fn exponent_mask(format: Format) -> u32 {
    (1 << (format.bits() - format.fraction_bits() - SIGN_BITS)) - 1
}

fn bias(format: Format) -> u32 {
    exponent_mask(format) >> 1
}

fn sign_bit(format: Format) -> u8 {
    (format.bits() - SIGN_BITS) as u8
}

fn lanes(operand: &Operand) -> u32 {
    match operand.shape {
        Shape::Scalar => 1,
        Shape::Vector64 => u64::BITS / operand.format.bits(),
        Shape::Vector128 => u128::BITS / operand.format.bits(),
    }
}

fn fixed_direction(operation: RoundingOperation) -> Option<Direction> {
    Some(match operation {
        RoundingOperation::NearestEven => Direction::NearestEven,
        RoundingOperation::NearestAway => Direction::NearestAway,
        RoundingOperation::TowardPositive => Direction::Positive,
        RoundingOperation::TowardNegative => Direction::Negative,
        RoundingOperation::TowardZero
        | RoundingOperation::Signed32Zero
        | RoundingOperation::Signed64Zero => Direction::Zero,
        _ => return None,
    })
}

/// Dynamic FPCR is read at execution time, without installing host control.
fn current_direction(code: &mut Code, mut emit: impl FnMut(&mut Code, Direction)) {
    test_control(code, FPCR_HIGH_ROUNDING_BIT);
    let high = branch(code, Condition::NotZero);
    test_control(code, FPCR_LOW_ROUNDING_BIT);
    let positive = branch(code, Condition::NotZero);
    emit(code, Direction::NearestEven);
    let nearest_done = jump(code);
    let positive_start = code.len();
    resolve(code, positive, positive_start);
    emit(code, Direction::Positive);
    let positive_done = jump(code);
    let high_start = code.len();
    resolve(code, high, high_start);
    test_control(code, FPCR_LOW_ROUNDING_BIT);
    let zero = branch(code, Condition::NotZero);
    emit(code, Direction::Negative);
    let negative_done = jump(code);
    let zero_start = code.len();
    resolve(code, zero, zero_start);
    emit(code, Direction::Zero);
    let done = code.len();
    for patch in [nearest_done, positive_done, negative_done] {
        resolve(code, patch, done);
    }
}

fn direction(
    code: &mut Code,
    operation: RoundingOperation,
    mut emit: impl FnMut(&mut Code, Direction),
) {
    if let Some(fixed) = fixed_direction(operation) {
        emit(code, fixed);
    } else {
        current_direction(code, emit);
    }
}

fn read_lane(code: &mut Code, format: Format, xmm: u8) {
    let mut asm = code.asm();
    if format == Format::Double {
        asm.movq_from_xmm(Rax, xmm);
    } else {
        asm.movd_from_xmm(Rax, xmm);
    }
    if format == Format::Half {
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, u16::MAX.into());
    }
}

fn source_class(code: &mut Code, format: Format, helper: &mut Vec<usize>) {
    let mut asm = code.asm();
    asm.mov(Size::Qword, Rdx, Rax);
    asm.mov(Size::Qword, Rcx, Rax);
    asm.shift_imm(ShiftOp::Shr, Size::Qword, Rcx, format.fraction_bits() as u8);
    asm.alu_imm32(Alu::And, Size::Dword, Rcx, exponent_mask(format) as i32);
    asm.mov(Size::Dword, R8, Rcx);
    asm.dec(Size::Dword, R8);
    asm.alu_imm32(
        Alu::Cmp,
        Size::Dword,
        R8,
        (exponent_mask(format) - 1) as i32,
    );
    let normal = branch(code, Condition::Below);
    shifted_out(code, (u64::BITS - (format.bits() - SIGN_BITS)) as u8);
    helper.push(branch(code, Condition::NotZero)); // only signed zero survives the nonnormal case
    let accepted = code.len();
    resolve(code, normal, accepted);
}

/// `mov r9, rdx; shl r9, amount`: ZF reports whether the source's low
/// `64 - amount` bits are all zero.
fn shifted_out(code: &mut Code, amount: u8) {
    let mut asm = code.asm();
    asm.mov(Size::Qword, R9, Rdx);
    asm.shift_imm(ShiftOp::Shl, Size::Qword, R9, amount);
}

/// `xor r8d, r8d`.
fn clear_bias(code: &mut Code) {
    code.asm().alu(Alu::Xor, Size::Dword, R8, R8);
}

/// `bt rdx, sign`: CF is the source sign.
fn test_sign(code: &mut Code, format: Format) {
    code.asm()
        .bit_imm(BitTest::Bt, Size::Qword, Rdx, sign_bit(format));
}

fn fractional_bias(code: &mut Code, format: Format, rounding: Direction) {
    match rounding {
        Direction::NearestEven => {
            let mut asm = code.asm();
            asm.shift_one(ShiftOp::Shr, Size::Qword, R8);
            asm.dec(Size::Qword, R8);
            asm.bit(BitTest::Bt, Size::Qword, Rax, Rcx);
            asm.alu_imm8(Alu::Adc, Size::Qword, R8, 0);
        }
        Direction::NearestAway => code.asm().shift_one(ShiftOp::Shr, Size::Qword, R8),
        Direction::Positive | Direction::Negative => {
            clear_bias(code);
            test_sign(code, format);
            let condition = if matches!(rounding, Direction::Positive) {
                Cond::Ae
            } else {
                Cond::B
            };
            code.asm().cmov(condition, Size::Qword, R8, R9);
        }
        Direction::Zero => clear_bias(code),
    }
}

fn or_one(code: &mut Code, format: Format) {
    let one = u64::from(bias(format)) << format.fraction_bits();
    let mut asm = code.asm();
    if format == Format::Double {
        asm.mov_imm64(R8, one);
        asm.alu(Alu::Or, Size::Qword, Rax, R8);
    } else {
        asm.alu_accumulator_imm32(Alu::Or, Size::Dword, one as i32);
    }
}

fn small_increment(code: &mut Code, format: Format, rounding: Direction, done: &mut Vec<usize>) {
    match rounding {
        Direction::NearestEven | Direction::NearestAway => {
            code.asm()
                .alu_imm32(Alu::Cmp, Size::Dword, Rcx, (bias(format) - 1) as i32);
            done.push(branch(code, Condition::Below));
            if matches!(rounding, Direction::NearestEven) {
                shifted_out(code, (u64::BITS - format.fraction_bits()) as u8);
                done.push(branch(code, Condition::Zero));
            }
            or_one(code, format);
        }
        Direction::Positive | Direction::Negative => {
            test_sign(code, format);
            done.push(branch(
                code,
                if matches!(rounding, Direction::Positive) {
                    Condition::Below
                } else {
                    Condition::AboveOrEqual
                },
            ));
            or_one(code, format);
        }
        Direction::Zero => (),
    }
}

fn bounded(code: &mut Code, format: Format, width: u32, helper: &mut Vec<usize>) {
    let mut asm = code.asm();
    asm.mov(Size::Qword, R9, Rax);
    asm.bit_imm(BitTest::Btr, Size::Qword, R9, sign_bit(format));
    asm.mov_imm64(
        R8,
        u64::from(bias(format) + width - 1) << format.fraction_bits(),
    );
    asm.alu(Alu::Cmp, Size::Qword, R9, R8);
    helper.push(branch(code, Condition::Above));
    let smaller = branch(code, Condition::Below);
    code.asm()
        .bit_imm(BitTest::Bt, Size::Qword, Rax, sign_bit(format));
    helper.push(branch(code, Condition::AboveOrEqual)); // equality is valid only at the negative limit
    let accepted = code.len();
    resolve(code, smaller, accepted);
}

fn integer_lane(code: &mut Code, operand: &Operand, helper: &mut Vec<usize>) {
    let format = operand.format;
    read_lane(code, format, SOURCE);
    source_class(code, format, helper);
    let mut done = Vec::new();
    let integral = bias(format) + format.fraction_bits();
    code.asm()
        .alu_imm32(Alu::Cmp, Size::Dword, Rcx, bias(format) as i32);
    let small = branch(code, Condition::Below);
    code.asm()
        .alu_imm32(Alu::Cmp, Size::Dword, Rcx, integral as i32);
    done.push(branch(code, Condition::AboveOrEqual));
    let mut asm = code.asm();
    asm.mov_imm32(R8, integral);
    asm.alu(Alu::Sub, Size::Dword, R8, Rcx);
    asm.mov(Size::Dword, Rcx, R8);
    asm.mov_imm32(R8, 1);
    asm.shift_cl(ShiftOp::Shl, Size::Qword, R8);
    asm.mov(Size::Qword, R9, R8);
    asm.dec(Size::Qword, R9);
    direction(code, operand.operation, |code, rounding| {
        fractional_bias(code, format, rounding)
    });
    let mut asm = code.asm();
    asm.alu(Alu::Add, Size::Qword, Rax, R8);
    asm.alu(Alu::Or, Size::Qword, Rax, R9);
    asm.alu(Alu::Xor, Size::Qword, Rax, R9);
    done.push(jump(code));
    let small_start = code.len();
    resolve(code, small, small_start);
    let mut asm = code.asm();
    if format == Format::Double {
        asm.shift_imm(ShiftOp::Shr, Size::Qword, Rax, sign_bit(format));
        asm.shift_imm(ShiftOp::Shl, Size::Qword, Rax, sign_bit(format));
    } else {
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, (1u32 << sign_bit(format)) as i32);
    }
    shifted_out(code, (u64::BITS - (format.bits() - SIGN_BITS)) as u8);
    done.push(branch(code, Condition::Zero));
    direction(code, operand.operation, |code, rounding| {
        small_increment(code, format, rounding, &mut done)
    });
    let rounded = code.len();
    for patch in done {
        resolve(code, patch, rounded);
    }
    if let Some(width) = operand.operation.signed_width() {
        bounded(code, format, width, helper);
    }
    if operand.operation.exact() {
        let mut asm = code.asm();
        asm.alu(Alu::Cmp, Size::Qword, Rax, Rdx);
        asm.setcc(Cond::Ne, R8);
        asm.movzx(Size::Dword, R8, Size::Byte, R8);
        asm.alu(Alu::Or, Size::Dword, R10, R8);
    }
}

fn insert_lane(code: &mut Code, operand: &Operand) {
    match operand.format {
        Format::Half => {
            code.asm().pinsrw(RESULT, Rax, (lanes(operand) - 1) as u8);
        }
        Format::Single => {
            code.asm().movd_to_xmm(TEMP, Rax);
            ShiftOpcode::LeftBytes.emit(
                code,
                TEMP,
                ((lanes(operand) - 1) * (Format::Single.bits() / BITS_PER_BYTE)) as u8,
            );
            packed(code, Host::Or, RESULT, TEMP);
        }
        Format::Double => {
            packed(code, Host::MoveGprQword, TEMP, ACCUMULATOR_GPR);
            code.asm().movlhps(RESULT, Rm::Xmm(TEMP));
        }
    }
}

/// `xor r10d, r10d`: R10D accumulates whether any lane was inexact.
fn clear_inexact(code: &mut Code) {
    code.asm().alu(Alu::Xor, Size::Dword, R10, R10);
}

fn integer_rounding(code: &mut Code, operand: &Operand, helper: &mut Vec<usize>) {
    if operand.operation.exact() {
        clear_inexact(code);
    }
    if operand.shape == Shape::Scalar {
        integer_lane(code, operand, helper);
        if operand.format == Format::Double {
            packed(code, Host::MoveGprQword, RESULT, ACCUMULATOR_GPR);
        } else {
            code.asm().movd_to_xmm(RESULT, Rax);
        }
    } else {
        packed(code, Host::Xor, RESULT, RESULT);
        code.asm().mov_imm32(R11, lanes(operand));
        let repeat = code.len();
        integer_lane(code, operand, helper);
        let lane_bytes = (operand.format.bits() / BITS_PER_BYTE) as u8;
        ShiftOpcode::RightBytes.emit(code, SOURCE, lane_bytes);
        ShiftOpcode::RightBytes.emit(code, RESULT, lane_bytes);
        insert_lane(code, operand);
        code.asm().dec(Size::Dword, R11);
        let repeat_branch = branch(code, Condition::NotZero);
        resolve(code, repeat_branch, repeat);
    }
}

fn packed_left(format: Format) -> ShiftOpcode {
    match format {
        Format::Half => ShiftOpcode::LeftWord,
        Format::Single => ShiftOpcode::LeftDword,
        Format::Double => ShiftOpcode::LeftQword,
    }
}

fn packed_right(format: Format) -> ShiftOpcode {
    match format {
        Format::Half => ShiftOpcode::RightWord,
        Format::Single => ShiftOpcode::RightDword,
        Format::Double => ShiftOpcode::RightQword,
    }
}

fn checked_source(code: &mut Code, operand: &Operand, helper: &mut Vec<usize>) {
    let format = operand.format;
    prepare_vector_input_range(code, format);
    vector_exponent_range(code, format, operand.shape, SOURCE);
    packed(code, Host::MoveAligned, ORIGINAL_HALF, SOURCE);
    packed_left(format).emit(code, ORIGINAL_HALF, SIGN_BITS as u8);
    packed_right(format).emit(code, ORIGINAL_HALF, SIGN_BITS as u8);
    packed(code, Host::Xor, RESIDUAL, RESIDUAL);
    packed(
        code,
        if format == Format::Half {
            Host::EqualWord
        } else {
            Host::EqualDword
        },
        ORIGINAL_HALF,
        RESIDUAL,
    );
    if format == Format::Double {
        super::shuffle(code, SAVED_HALF, ORIGINAL_HALF, ADJACENT_DWORDS);
        packed(code, Host::And, ORIGINAL_HALF, SAVED_HALF);
    }
    packed(code, Host::Or, EXPONENT_VECTOR, ORIGINAL_HALF);
    let mask = if format == Format::Half {
        Host::ByteSignMask.register(code, 0, EXPONENT_VECTOR, TargetCpu::Baseline);
        (1u32 << (lanes(operand) * (format.bits() / BITS_PER_BYTE))) - 1
    } else {
        Host::DwordSignMask.register(code, 0, EXPONENT_VECTOR, TargetCpu::Baseline);
        match (format, operand.shape) {
            (_, Shape::Scalar) => 1,
            (Format::Single, Shape::Vector64) => SINGLE_LOW_MASK,
            (Format::Single, Shape::Vector128) => SINGLE_FULL_MASK,
            (Format::Double, Shape::Vector128) => DOUBLE_FULL_MASK,
            _ => unreachable!("decoded checked round arrangement"),
        }
    };
    all_bits(code, mask);
    helper.push(branch(code, Condition::NotZero));
}

fn round_instruction(
    code: &mut Code,
    format: Format,
    shape: Shape,
    rounding: Direction,
    target: TargetCpu,
) {
    let opcode = match (format, shape) {
        (Format::Single, Shape::Scalar) => Host::RoundScalarSingle,
        (Format::Double, Shape::Scalar) => Host::RoundScalarDouble,
        (Format::Single, _) => Host::RoundPackedSingle,
        (Format::Double, _) => Host::RoundPackedDouble,
        _ => unreachable!("half rounds after exact widening"),
    };
    let mode = match rounding {
        Direction::NearestEven => ROUND_NEAREST,
        Direction::Positive => ROUND_POSITIVE,
        Direction::Negative => ROUND_NEGATIVE,
        Direction::Zero => ROUND_ZERO,
        Direction::NearestAway => unreachable!("ties-away uses an exact residual"),
    };
    opcode.register_imm(code, RESULT, SOURCE, PRECISION_SUPPRESSED | mode, target);
}

fn splat(code: &mut Code, format: Format, vector: u8, bits: u64) {
    code.asm().mov_imm64(Rax, bits);
    packed(code, Host::MoveGprQword, vector, ACCUMULATOR_GPR);
    if format == Format::Single {
        super::shuffle(code, vector, vector, BROADCAST_LOW_DWORD);
    } else {
        packed(code, Host::UnpackLowQword, vector, vector);
    }
}

fn magnitude_mask(code: &mut Code, format: Format, vector: u8) {
    packed(code, Host::EqualDword, vector, vector);
    packed_right(format).emit(code, vector, SIGN_BITS as u8);
}

fn ties_away(code: &mut Code, format: Format, shape: Shape, target: TargetCpu) {
    round_instruction(code, format, shape, Direction::Zero, target);
    packed(code, Host::MoveAligned, RESIDUAL, SOURCE);
    emit_opcode_to(
        code,
        format,
        shape,
        ArithmeticOpcode::Subtract,
        RESIDUAL,
        RESULT,
    );
    magnitude_mask(code, format, MASK);
    packed(code, Host::And, RESIDUAL, MASK);
    splat(
        code,
        format,
        CONSTANT,
        u64::from(bias(format) - 1) << format.fraction_bits(),
    );
    // 0.5 <= abs(x-trunc(x)), with an ordered predicate and guarded finite data.
    code.asm().float_compare(
        float_lanes(format, shape),
        CONSTANT,
        Rm::Xmm(RESIDUAL),
        COMPARE_LESS_EQUAL,
    );
    packed(code, Host::EqualDword, MASK, MASK);
    packed_left(format).emit(code, MASK, sign_bit(format));
    packed(code, Host::And, MASK, SOURCE);
    splat(
        code,
        format,
        RESIDUAL,
        u64::from(bias(format)) << format.fraction_bits(),
    );
    packed(code, Host::Or, RESIDUAL, MASK);
    packed(code, Host::And, RESIDUAL, CONSTANT);
    emit_opcode_to(code, format, shape, ArithmeticOpcode::Add, RESULT, RESIDUAL);
    // An exact zero sum can take the host rounding mode's sign, so force the
    // architectural sign on every result, including signed zero.
    magnitude_mask(code, format, MASK);
    packed(code, Host::And, RESULT, MASK);
    packed(code, Host::EqualDword, CONSTANT, CONSTANT);
    packed(code, Host::Xor, MASK, CONSTANT);
    packed(code, Host::And, MASK, SOURCE);
    packed(code, Host::Or, RESULT, MASK);
}

fn checked_compute(
    code: &mut Code,
    operation: RoundingOperation,
    format: Format,
    shape: Shape,
    target: TargetCpu,
) {
    if operation == RoundingOperation::NearestAway {
        ties_away(code, format, shape, target);
    } else {
        direction(code, operation, |code, mode| {
            round_instruction(code, format, shape, mode, target)
        });
    }
}

fn half_bias(code: &mut Code, vector: u8) {
    let adjustment = (bias(Format::Single) - bias(Format::Half)) << Format::Single.fraction_bits();
    let position = adjustment.trailing_zeros();
    let digits = (adjustment >> position).ilog2() + 1;
    packed(code, Host::EqualDword, vector, vector);
    ShiftOpcode::RightDword.emit(code, vector, (u32::BITS - digits) as u8);
    ShiftOpcode::LeftDword.emit(code, vector, position as u8);
}

fn widen_half(code: &mut Code, upper: bool) {
    let sign_shift = (Format::Single.bits() - Format::Half.bits()) as u8;
    let strip_sign = sign_shift + SIGN_BITS as u8;
    let fraction_shift = (Format::Single.fraction_bits() - Format::Half.fraction_bits()) as u8;
    packed(code, Host::MoveAligned, RESULT, ORIGINAL_HALF);
    if upper {
        ShiftOpcode::RightBytes.emit(code, RESULT, (u64::BITS / BITS_PER_BYTE) as u8);
    }
    packed(code, Host::Xor, CONSTANT, CONSTANT);
    packed(code, Host::UnpackLowWord, RESULT, CONSTANT);
    packed(code, Host::MoveAligned, TEMP, RESULT);
    ShiftOpcode::LeftDword.emit(code, TEMP, sign_shift);
    ShiftOpcode::RightDword.emit(code, TEMP, sign_bit(Format::Single));
    ShiftOpcode::LeftDword.emit(code, TEMP, sign_bit(Format::Single));
    packed(code, Host::MoveAligned, RESIDUAL, RESULT);
    ShiftOpcode::LeftDword.emit(code, RESIDUAL, strip_sign);
    ShiftOpcode::RightDword.emit(code, RESIDUAL, strip_sign);
    packed(code, Host::EqualDword, RESIDUAL, CONSTANT);
    ShiftOpcode::LeftDword.emit(code, RESULT, strip_sign);
    ShiftOpcode::RightDword.emit(code, RESULT, strip_sign - fraction_shift);
    half_bias(code, MASK);
    packed(code, Host::AddDword, RESULT, MASK);
    packed(code, Host::AndNot, RESIDUAL, RESULT); // preserve exact half zeros
    packed(code, Host::Or, RESIDUAL, TEMP);
    packed(code, Host::MoveAligned, SOURCE, RESIDUAL);
}

fn pack_half(code: &mut Code, target: TargetCpu) {
    packed(code, Host::MoveAligned, TEMP, RESULT);
    ShiftOpcode::RightDword.emit(code, TEMP, sign_bit(Format::Single));
    ShiftOpcode::LeftDword.emit(code, TEMP, sign_bit(Format::Half));
    packed(code, Host::MoveAligned, RESIDUAL, RESULT);
    ShiftOpcode::LeftDword.emit(code, RESIDUAL, SIGN_BITS as u8);
    ShiftOpcode::RightDword.emit(code, RESIDUAL, SIGN_BITS as u8);
    packed(code, Host::Xor, CONSTANT, CONSTANT);
    packed(code, Host::MoveAligned, MASK, RESIDUAL);
    packed(code, Host::EqualDword, MASK, CONSTANT);
    half_bias(code, CONSTANT);
    packed(code, Host::SubDword, RESIDUAL, CONSTANT);
    ShiftOpcode::RightDword.emit(
        code,
        RESIDUAL,
        (Format::Single.fraction_bits() - Format::Half.fraction_bits()) as u8,
    );
    packed(code, Host::AndNot, MASK, RESIDUAL);
    packed(code, Host::Or, MASK, TEMP);
    Host::PackUnsignedDwordToWord.register(code, MASK, MASK, target);
}

fn checked_half(code: &mut Code, operand: &Operand, target: TargetCpu) {
    packed(code, Host::MoveAligned, ORIGINAL_HALF, SOURCE);
    widen_half(code, false);
    checked_compute(
        code,
        operand.operation,
        Format::Single,
        Shape::Vector128,
        target,
    );
    pack_half(code, target);
    if operand.shape == Shape::Vector128 {
        packed(code, Host::MoveAligned, SAVED_HALF, MASK);
        widen_half(code, true);
        checked_compute(
            code,
            operand.operation,
            Format::Single,
            Shape::Vector128,
            target,
        );
        pack_half(code, target);
        packed(code, Host::UnpackLowQword, SAVED_HALF, MASK);
        packed(code, Host::MoveAligned, RESULT, SAVED_HALF);
    } else {
        packed(code, Host::MoveAligned, RESULT, MASK);
    }
    packed(code, Host::MoveAligned, SOURCE, ORIGINAL_HALF);
}

fn checked_bounds(code: &mut Code, operand: &Operand, helper: &mut Vec<usize>) {
    let Some(width) = operand.operation.signed_width() else {
        return;
    };
    packed(code, Host::MoveAligned, TEMP, RESULT);
    for _ in 0..lanes(operand) {
        read_lane(code, operand.format, TEMP);
        bounded(code, operand.format, width, helper);
        ShiftOpcode::RightBytes.emit(code, TEMP, (operand.format.bits() / BITS_PER_BYTE) as u8);
    }
}

fn checked_inexact(code: &mut Code, operand: &Operand) {
    if !operand.operation.exact() {
        return;
    }
    clear_inexact(code);
    packed(code, Host::MoveAligned, TEMP, RESULT);
    packed(code, Host::EqualByte, TEMP, SOURCE);
    Host::ByteSignMask.register(code, 0, TEMP, TargetCpu::Baseline);
    let mask = (1u32 << (lanes(operand) * (operand.format.bits() / BITS_PER_BYTE))) - 1;
    all_bits(code, mask);
    code.asm().setcc(Cond::Ne, R10);
}

fn checked_rounding(
    code: &mut Code,
    operand: &Operand,
    helper: &mut Vec<usize>,
    target: TargetCpu,
) {
    checked_source(code, operand, helper);
    if operand.format == Format::Half {
        checked_half(code, operand, target);
    } else {
        checked_compute(
            code,
            operand.operation,
            operand.format,
            operand.shape,
            target,
        );
    }
    checked_bounds(code, operand, helper);
    checked_inexact(code, operand);
}

fn commit_result(code: &mut Code, operand: &Operand) {
    if operand.operation.exact() {
        let mut asm = code.asm();
        asm.shift_imm(ShiftOp::Shl, Size::Dword, R10, INEXACT_SHIFT);
        asm.alu(
            Alu::Or,
            Size::Dword,
            guest(core::mem::offset_of!(GuestState, fpsr) as u32),
            R10,
        );
    }
    let result = if operand.shape == Shape::Scalar {
        read_vector(code, operand.destination, SAVED_HALF);
        match operand.format {
            Format::Half => {
                read_lane(code, Format::Half, RESULT);
                code.asm().pinsrw(SAVED_HALF, Rax, FIRST_LANE);
            }
            Format::Single => {
                Host::MoveScalarSingle.register(code, SAVED_HALF, RESULT, TargetCpu::Baseline)
            }
            Format::Double => {
                Host::MoveScalarDouble.register(code, SAVED_HALF, RESULT, TargetCpu::Baseline)
            }
        }
        test_control(code, FPCR_NEP);
        let merging = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, SAVED_HALF);
        let merged = code.len();
        resolve(code, merging, merged);
        SAVED_HALF
    } else {
        if operand.shape == Shape::Vector64 {
            clear_scalar(code, Format::Double, RESULT);
        }
        RESULT
    };
    commit(code, operand.destination, result);
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    let mut helper = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_numerical_vector(code, operand.shape, operand.source, SOURCE);
    // Scalar Half widening and packing cost more than compact integer rounding.
    // Packed Half and S/D still benefit from capability-checked ROUND.
    let scalar_half = operand.format == Format::Half && operand.shape == Shape::Scalar;
    if target.supports(TargetCpu::Sse41) && !scalar_half {
        checked_rounding(code, operand, &mut helper, target);
    } else {
        integer_rounding(code, operand, &mut helper);
    }
    helper_section(code, &helper, pc);
    commit_result(code, operand);
}
