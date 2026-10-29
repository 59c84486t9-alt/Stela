//! FRECPE/FRSQRTE/FRECPX through exact integer arithmetic.
use super::super::isa::ShiftOpcode;
use super::numerical::helper_section;
use super::numerical::{
    ArithmeticOpcode, Condition, INPUT_MINIMUM_EXPONENT, Rounding, branch, clear_scalar,
    emit_opcode, environment_round, exponent_range, exponent_range_below, positive_exponent_range,
    prepare_vector_input_range, prepare_vector_input_range_below, read_numerical_vector, resolve,
    restore_environment, test_control, vector_exponent_range, vector_positive_exponent_range,
};
use super::{Host, commit, packed, read_vector};
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, ShiftOp, Size, Unary};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format},
        simd::{
            arithmetic::Shape,
            estimate::{Kind, Operand},
        },
    },
};
use Gpr::{R8, R9, Rax, Rcx, Rdx};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const DENOMINATOR: u8 = 2;
const TEMP: u8 = 3;
const CONSTANT: u8 = 4;
const EXPONENT: u8 = 5;
const COMPACT: u8 = 6;
const SAVED: u8 = 7;
const ESTIMATE_FRACTION_BITS: u8 = 8;
const ESTIMATE_UNIT: u32 = 1 << ESTIMATE_FRACTION_BITS;
const RECIPROCAL_QUOTIENT_EXPONENT: u32 = 2 * ESTIMATE_FRACTION_BITS as u32 + 2;
const RECIPROCAL_SQRT_QUOTIENT_EXPONENT: u32 = 3 * ESTIMATE_FRACTION_BITS as u32 + 2;
const SIGN_BITS: u8 = 1;
const DWORD_BITS: u8 = u32::BITS as u8;
const HALF_BITS: u8 = u16::BITS as u8;
const UNSIGNED_TABLE_SHIFT: u8 = DWORD_BITS - ESTIMATE_FRACTION_BITS - SIGN_BITS;
const UPPER_HALF_BYTES: u8 = (u64::BITS / u8::BITS) as u8;
const COMPACT_QWORD_LOW_DWORDS: u8 = 0x88;
const BROADCAST_LOW_DWORD: u8 = 0;
const FIRST_LANE: u8 = 0;
const ACCUMULATOR_GPR: u8 = 0;

/// Move the low `format` lane of `vector` into RAX/EAX.
fn lane_to_rax(code: &mut Code, format: Format, vector: u8) {
    if format == Format::Double {
        code.asm().movq_from_xmm(Rax, vector);
    } else {
        code.asm().movd_from_xmm(Rax, vector);
    }
}

fn reciprocal_sqrt(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::ReciprocalSquareRoot | Kind::UnsignedReciprocalSquareRoot
    )
}

fn exponent_bits(format: Format) -> u8 {
    (format.bits() - format.fraction_bits()) as u8 - SIGN_BITS
}

fn fraction_shift(format: Format) -> u8 {
    format.fraction_bits() as u8 - ESTIMATE_FRACTION_BITS
}

fn checked_reciprocal(operand: &Operand, target: TargetCpu) -> bool {
    operand.kind == Kind::Reciprocal
        && operand.shape != Shape::Scalar
        && operand.format != Format::Double
        && target.supports(TargetCpu::Sse41)
}

/// Exact table rounding: r=(2^18+a)/(2a+1), a=256+fraction_top8.
/// The odd denominator cannot tie, so integer DIV needs no FP environment.
fn scalar_reciprocal(code: &mut Code, format: Format) {
    let fraction_mask = (ESTIMATE_UNIT - 1) as i32;
    let fraction_bits = format.fraction_bits() as u8;
    let sign_bit = format.bits() as u8 - SIGN_BITS;
    lane_to_rax(code, format, SOURCE);
    let mut asm = code.asm();
    asm.mov(Size::Qword, R8, Rax);
    asm.shift_imm(ShiftOp::Shr, Size::Qword, Rax, fraction_shift(format));
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, fraction_mask);
    asm.alu_accumulator_imm32(Alu::Or, Size::Dword, ESTIMATE_UNIT as i32);
    // ECX = 2a+1.
    asm.lea(Size::Dword, Rcx, Mem::indexed(Rax, Rax, 1, 1));
    asm.alu_accumulator_imm32(
        Alu::Add,
        Size::Dword,
        (1u32 << RECIPROCAL_QUOTIENT_EXPONENT) as i32,
    );
    asm.alu(Alu::Xor, Size::Dword, Rdx, Rdx);
    asm.unary(Unary::Div, Size::Dword, Rcx);
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, fraction_mask);
    asm.shift_imm(ShiftOp::Shl, Size::Qword, Rax, fraction_shift(format));
    asm.mov(Size::Qword, R9, Rax);
    asm.mov(Size::Qword, Rax, R8);
    asm.shift_imm(ShiftOp::Shr, Size::Qword, Rax, fraction_bits);
    asm.alu_accumulator_imm32(
        Alu::And,
        Size::Dword,
        (2 * format.exponent_bias() + 1) as i32,
    );
    asm.mov_imm32(Rcx, 2 * format.exponent_bias() - 1);
    asm.alu(Alu::Sub, Size::Dword, Rcx, Rax);
    asm.shift_imm(ShiftOp::Shl, Size::Qword, Rcx, fraction_bits);
    asm.alu(Alu::Or, Size::Qword, R9, Rcx);
    asm.shift_imm(ShiftOp::Shr, Size::Qword, R8, sign_bit);
    asm.shift_imm(ShiftOp::Shl, Size::Qword, R8, sign_bit);
    asm.alu(Alu::Or, Size::Qword, R9, R8);
    asm.movq_to_xmm(RESULT, R9);
}

fn dword_constant(code: &mut Code, vector: u8, value: u32) {
    let mut asm = code.asm();
    asm.mov_imm32(Rax, value);
    asm.movd_to_xmm(vector, Rax);
    super::shuffle(code, vector, vector, BROADCAST_LOW_DWORD);
}

fn source_guard(code: &mut Code, operand: &Operand, helper: &mut Vec<usize>) {
    if !operand.kind.is_unsigned() {
        // AH suppresses every estimate exception, including kept enables.
        test_control(code, FPCR_AH);
        let suppressed = branch(code, Condition::NotZero);
        test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
        helper.push(branch(code, Condition::NotZero));
        let accepted = code.len();
        resolve(code, suppressed, accepted);
    }
    read_numerical_vector(code, operand.shape, operand.source, SOURCE);
    if operand.kind.is_unsigned() {
        return;
    }
    let maximum = 2 * operand.format.exponent_bias() - 1;
    if operand.shape == Shape::Scalar {
        if operand.kind == Kind::Reciprocal {
            exponent_range_below(
                code,
                operand.format,
                SOURCE,
                INPUT_MINIMUM_EXPONENT,
                maximum,
            );
        } else if reciprocal_sqrt(operand.kind) {
            positive_exponent_range(code, operand.format, SOURCE, INPUT_MINIMUM_EXPONENT);
        } else {
            exponent_range(code, operand.format, SOURCE, INPUT_MINIMUM_EXPONENT);
        }
        helper.push(branch(code, Condition::AboveOrEqual));
    } else {
        if operand.kind == Kind::Reciprocal {
            // Exclude the top two normal source exponents: their reciprocal
            // can be subnormal or flushed and belongs to precise handling.
            prepare_vector_input_range_below(code, operand.format, maximum);
        } else {
            prepare_vector_input_range(code, operand.format);
        }
        if reciprocal_sqrt(operand.kind) {
            vector_positive_exponent_range(code, operand.format, operand.shape, SOURCE);
        } else {
            vector_exponent_range(code, operand.format, operand.shape, SOURCE);
        }
        helper.push(branch(code, Condition::NotZero));
    }
}

/// Keep sign, biased exponent and the top eight fraction bits in each dword.
/// D metadata is compacted before any host floating operation; H expands first.
fn compact_source(code: &mut Code, format: Format, upper: bool) {
    packed(code, Host::MoveAligned, COMPACT, SOURCE);
    if upper {
        ShiftOpcode::RightBytes.emit(code, COMPACT, UPPER_HALF_BYTES);
    }
    if format == Format::Half {
        packed(code, Host::Xor, TEMP, TEMP);
        packed(code, Host::UnpackLowWord, COMPACT, TEMP);
    }
    if format == Format::Double {
        ShiftOpcode::RightQword.emit(code, COMPACT, fraction_shift(format));
        super::shuffle(code, COMPACT, COMPACT, COMPACT_QWORD_LOW_DWORDS);
    } else {
        ShiftOpcode::RightDword.emit(code, COMPACT, fraction_shift(format));
    }
}

fn result_exponent(code: &mut Code, format: Format, sqrt: bool) {
    let bits = exponent_bits(format);
    packed(code, Host::MoveAligned, TEMP, COMPACT);
    ShiftOpcode::LeftDword.emit(code, TEMP, DWORD_BITS - bits - ESTIMATE_FRACTION_BITS);
    ShiftOpcode::RightDword.emit(code, TEMP, DWORD_BITS - bits);
    let base = (if sqrt { 3 } else { 2 }) * format.exponent_bias() - 1;
    dword_constant(code, EXPONENT, base);
    packed(code, Host::SubDword, EXPONENT, TEMP);
    if sqrt {
        ShiftOpcode::RightDword.emit(code, EXPONENT, 1);
    }
    ShiftOpcode::LeftDword.emit(code, EXPONENT, ESTIMATE_FRACTION_BITS);
}

fn floating_denominator(code: &mut Code, sqrt: bool) {
    packed(code, Host::MoveAligned, DENOMINATOR, COMPACT);
    ShiftOpcode::LeftDword.emit(code, DENOMINATOR, DWORD_BITS - ESTIMATE_FRACTION_BITS);
    ShiftOpcode::RightDword.emit(code, DENOMINATOR, DWORD_BITS - ESTIMATE_FRACTION_BITS);
    if sqrt {
        ShiftOpcode::RightDword.emit(code, DENOMINATOR, 1);
        ShiftOpcode::LeftDword.emit(code, DENOMINATOR, 1);
        dword_constant(code, CONSTANT, ESTIMATE_UNIT + 1);
        packed(code, Host::AddDword, DENOMINATOR, CONSTANT);
        // Y=(fraction_top8 & ~1)+257. Odd exponent uses A=Y;
        // even exponent uses A=2Y, matching both source table branches.
        packed(code, Host::MoveAligned, TEMP, COMPACT);
        ShiftOpcode::LeftDword.emit(code, TEMP, DWORD_BITS - SIGN_BITS - ESTIMATE_FRACTION_BITS);
        ShiftOpcode::ArithmeticDword.emit(code, TEMP, DWORD_BITS - SIGN_BITS);
        packed(code, Host::AndNot, TEMP, DENOMINATOR);
        packed(code, Host::AddDword, DENOMINATOR, TEMP);
    } else {
        ShiftOpcode::LeftDword.emit(code, DENOMINATOR, 1);
        dword_constant(code, CONSTANT, 2 * ESTIMATE_UNIT + 1);
        packed(code, Host::AddDword, DENOMINATOR, CONSTANT);
    }
}

/// Bounded denominators are exact Single integers. Primary-derived midpoint
/// bounds prove nearest(DIV[+SQRT]) followed by nearest integer conversion
/// reproduces every standard estimate key. Host PE is not guest estimate IXC.
fn integer_estimate(code: &mut Code, sqrt: bool) {
    packed(
        code,
        Host::ConvertPackedDwordToSingle,
        DENOMINATOR,
        DENOMINATOR,
    );
    let power = if sqrt {
        RECIPROCAL_SQRT_QUOTIENT_EXPONENT
    } else {
        RECIPROCAL_QUOTIENT_EXPONENT
    };
    let numerator = (Format::Single.exponent_bias() + power) << Format::Single.fraction_bits();
    dword_constant(code, RESULT, numerator);
    emit_opcode(
        code,
        Format::Single,
        Shape::Vector128,
        ArithmeticOpcode::Divide,
        DENOMINATOR,
    );
    if sqrt {
        packed(code, Host::SquareRootPackedSingle, RESULT, RESULT);
    }
    packed(code, Host::ConvertPackedSingleToDword, RESULT, RESULT);
}

/// RCP raises no exceptions. Its error bound makes floor(q') either r or r - 1;
/// the exact odd product A*(2*r0+1) decides the increment.
fn corrected_reciprocal(code: &mut Code, target: TargetCpu) {
    packed(code, Host::ConvertPackedDwordToSingle, RESULT, DENOMINATOR);
    packed(code, Host::ReciprocalPackedSingle, RESULT, RESULT);
    ShiftOpcode::RightDword.emit(code, RESULT, fraction_shift(Format::Single));
    let reciprocal_exponent = Format::Single.exponent_bias() - ESTIMATE_FRACTION_BITS as u32 - 2;
    let integer_bias = (reciprocal_exponent << ESTIMATE_FRACTION_BITS) - ESTIMATE_UNIT;
    dword_constant(code, CONSTANT, integer_bias);
    packed(code, Host::SubDword, RESULT, CONSTANT);
    packed(code, Host::MoveAligned, CONSTANT, RESULT);
    ShiftOpcode::LeftDword.emit(code, CONSTANT, 1);
    Host::MultiplyLowDword.register(code, CONSTANT, DENOMINATOR, target);
    packed(code, Host::AddDword, CONSTANT, DENOMINATOR);
    dword_constant(code, TEMP, 1 << (RECIPROCAL_QUOTIENT_EXPONENT + 1));
    packed(code, Host::GreaterDword, TEMP, CONSTANT);
    packed(code, Host::SubDword, RESULT, TEMP);
}

fn pack_half(code: &mut Code, signed: bool, target: TargetCpu) {
    if signed && target.supports(TargetCpu::Sse41) {
        Host::PackUnsignedDwordToWord.register(code, RESULT, RESULT, target);
    } else {
        if signed {
            // Reconstructed negative H raw bits exceed signedword range.
            // Sign-extend true16 bits before signed saturation packing.
            ShiftOpcode::LeftDword.emit(code, RESULT, DWORD_BITS - HALF_BITS);
            ShiftOpcode::ArithmeticDword.emit(code, RESULT, DWORD_BITS - HALF_BITS);
        }
        packed(code, Host::PackSignedDwordToWord, RESULT, RESULT);
    }
}

fn floating_group(code: &mut Code, operand: &Operand, upper: bool, target: TargetCpu) {
    let sqrt = reciprocal_sqrt(operand.kind);
    compact_source(code, operand.format, upper);
    result_exponent(code, operand.format, sqrt);
    floating_denominator(code, sqrt);
    if !sqrt {
        let sign = exponent_bits(operand.format) + ESTIMATE_FRACTION_BITS;
        ShiftOpcode::RightDword.emit(code, COMPACT, sign);
        ShiftOpcode::LeftDword.emit(code, COMPACT, sign);
    }
    if checked_reciprocal(operand, target) {
        corrected_reciprocal(code, target);
    } else {
        integer_estimate(code, sqrt);
    }
    ShiftOpcode::LeftDword.emit(code, RESULT, DWORD_BITS - ESTIMATE_FRACTION_BITS);
    ShiftOpcode::RightDword.emit(code, RESULT, DWORD_BITS - ESTIMATE_FRACTION_BITS);
    packed(code, Host::Or, RESULT, EXPONENT);
    if !sqrt {
        packed(code, Host::Or, RESULT, COMPACT);
    }
    if operand.format == Format::Double {
        packed(code, Host::Xor, TEMP, TEMP);
        packed(code, Host::UnpackLowDword, RESULT, TEMP);
        ShiftOpcode::LeftQword.emit(code, RESULT, fraction_shift(operand.format));
    } else {
        ShiftOpcode::LeftDword.emit(code, RESULT, fraction_shift(operand.format));
        if operand.format == Format::Half {
            pack_half(code, !sqrt, target);
        }
    }
}

fn floating_estimate(code: &mut Code, operand: &Operand, target: TargetCpu) {
    if operand.shape == Shape::Scalar {
        clear_scalar(code, operand.format, SOURCE);
    }
    if operand.kind == Kind::Reciprocal && operand.shape == Shape::Scalar {
        scalar_reciprocal(code, operand.format);
        return;
    }
    let checked = checked_reciprocal(operand, target);
    if !checked {
        environment_round(code, Rounding::NearestEven);
    }
    floating_group(code, operand, false, target);
    if operand.format == Format::Half && operand.shape == Shape::Vector128 {
        packed(code, Host::MoveAligned, SAVED, RESULT);
        floating_group(code, operand, true, target);
        packed(code, Host::UnpackLowQword, SAVED, RESULT);
        packed(code, Host::MoveAligned, RESULT, SAVED);
    }
    // The domain proves every host operation finite and safe for conversion.
    // Approximation PE is discarded; no guest status arises.
    if !checked {
        restore_environment(code);
    }
}

fn unsigned_estimate(code: &mut Code, kind: Kind, target: TargetCpu) {
    let sqrt = reciprocal_sqrt(kind);
    let checked = !sqrt && target.supports(TargetCpu::Sse41);
    if !checked {
        environment_round(code, Rounding::NearestEven);
    }
    packed(code, Host::MoveAligned, SAVED, SOURCE);
    if sqrt {
        ShiftOpcode::RightDword.emit(code, SAVED, DWORD_BITS - 2);
        packed(code, Host::Xor, TEMP, TEMP);
        packed(code, Host::GreaterDword, SAVED, TEMP);
    } else {
        ShiftOpcode::ArithmeticDword.emit(code, SAVED, DWORD_BITS - SIGN_BITS);
    }
    packed(code, Host::MoveAligned, DENOMINATOR, SOURCE);
    ShiftOpcode::RightDword.emit(code, DENOMINATOR, UNSIGNED_TABLE_SHIFT);
    dword_constant(code, CONSTANT, 1);
    if sqrt {
        packed(code, Host::MoveAligned, TEMP, SOURCE);
        ShiftOpcode::ArithmeticDword.emit(code, TEMP, DWORD_BITS - SIGN_BITS);
        packed(code, Host::MoveAligned, COMPACT, DENOMINATOR);
        ShiftOpcode::LeftDword.emit(code, COMPACT, DWORD_BITS - SIGN_BITS);
        ShiftOpcode::ArithmeticDword.emit(code, COMPACT, DWORD_BITS - SIGN_BITS);
        packed(code, Host::Or, COMPACT, CONSTANT); // even a -> +1; odd a -> -1
        packed(code, Host::And, COMPACT, TEMP); // only a>=256 adjusts A
    }
    ShiftOpcode::LeftDword.emit(code, DENOMINATOR, 1);
    packed(code, Host::AddDword, DENOMINATOR, CONSTANT);
    if sqrt {
        packed(code, Host::AddDword, DENOMINATOR, COMPACT);
    }
    if checked {
        // Invalid unsigned domains are saturated below. Clamp their A to
        // 513..1023 here; valid lanes already contain this denominator bit.
        ShiftOpcode::LeftDword.emit(code, CONSTANT, ESTIMATE_FRACTION_BITS + 1);
        packed(code, Host::Or, DENOMINATOR, CONSTANT);
        corrected_reciprocal(code, target);
    } else {
        integer_estimate(code, sqrt);
    }
    ShiftOpcode::LeftDword.emit(code, RESULT, UNSIGNED_TABLE_SHIFT);
    packed(code, Host::And, RESULT, SAVED);
    packed(code, Host::EqualDword, TEMP, TEMP);
    packed(code, Host::AndNot, SAVED, TEMP);
    packed(code, Host::Or, RESULT, SAVED);
    if !checked {
        restore_environment(code);
    }
}

fn reciprocal_exponent(code: &mut Code, format: Format) {
    lane_to_rax(code, format, SOURCE);
    let kept = format.sign_mask() | format.exponent_mask();
    let mut asm = code.asm();
    if format == Format::Double {
        asm.mov_imm64(Rdx, format.exponent_mask());
        asm.alu(Alu::Xor, Size::Qword, Rax, Rdx);
        asm.mov_imm64(Rcx, kept);
        asm.alu(Alu::And, Size::Qword, Rax, Rcx);
        packed(code, Host::MoveGprQword, RESULT, ACCUMULATOR_GPR);
    } else {
        asm.alu_accumulator_imm32(Alu::Xor, Size::Dword, format.exponent_mask() as i32);
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, kept as i32);
        asm.movd_to_xmm(RESULT, Rax);
    }
}

fn commit_result(code: &mut Code, operand: &Operand) {
    let result = if operand.shape == Shape::Scalar {
        read_vector(code, operand.destination, SAVED);
        match operand.format {
            Format::Half => {
                let mut asm = code.asm();
                asm.movd_from_xmm(Rax, RESULT);
                asm.pinsrw(SAVED, Rax, FIRST_LANE);
            }
            Format::Single => {
                Host::MoveScalarSingle.register(code, SAVED, RESULT, TargetCpu::Baseline)
            }
            Format::Double => {
                Host::MoveScalarDouble.register(code, SAVED, RESULT, TargetCpu::Baseline)
            }
        }
        test_control(code, FPCR_NEP);
        let merging = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, SAVED);
        let merged = code.len();
        resolve(code, merging, merged);
        SAVED
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
    source_guard(code, operand, &mut helper);
    if operand.kind.is_unsigned() {
        unsigned_estimate(code, operand.kind, target);
    } else if operand.kind == Kind::ReciprocalExponent {
        reciprocal_exponent(code, operand.format);
    } else {
        floating_estimate(code, operand, target);
    }
    if !helper.is_empty() {
        helper_section(code, &helper, pc);
    }
    commit_result(code, operand);
}
