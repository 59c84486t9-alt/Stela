//! Conversions between FP and integers.
use super::numerical::jump;
use super::numerical::{
    ArithmeticOpcode, Condition, INPUT_MINIMUM_EXPONENT, Rounding, branch, clear_scalar,
    commit_inexact, emit_opcode, environment_round, exponent_range, prepare_vector_input_range,
    read_numerical_vector, reject_other_status, resolve, restore_environment, test_control,
    vector_exponent_range,
};
use super::{Host, commit, packed, read_vector, vector_offset};
use crate::TargetCpu;
use crate::x86_64::asm::{Alu, Code, Gpr, Rm, ShiftOp, Size, vector_extensions};
use crate::x86_64::asm::{BitTest, FloatLanes};
use crate::x86_64::flag_word;
use crate::x86_64::isa::ShiftOpcode;
use crate::x86_64::simd::encode::guest;
use crate::{
    GuestAddress,
    aarch64::{
        Register,
        floating::{
            FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format, INEXACT,
            integer::{IntegerFormat, IntegerRounding, IntegerWidth},
        },
        simd::{
            arithmetic::Shape,
            conversion::{IntegerConversion, IntegerOperand},
        },
    },
    block::ExitKind,
};
use Gpr::{Rax, Rcx, Rdx};
use alloc::vec::Vec;

const BROADCAST_LOW_SINGLE: u8 = 0;
const SIGN_BIT: u8 = 63;
const RESULT_VECTOR: u8 = 0;
const TEMPORARY_VECTOR: u8 = 1;
const INTEGER_ACCUMULATOR: u8 = 6;
const BITS_PER_BYTE: u32 = u8::BITS;
const SINGLE_EXPONENT_BIAS: i16 = 127;
const DOUBLE_EXPONENT_BIAS: i16 = 1023;
const UNSIGNED_HIGH_EXPONENT: i16 = 63;

fn helper(code: &mut Code, pc: GuestAddress) {
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
}

fn scalar_lanes(format: Format) -> FloatLanes {
    match format {
        Format::Single => FloatLanes::ScalarSingle,
        Format::Double => FloatLanes::ScalarDouble,
        Format::Half => unreachable!("half conversions use the exact core"),
    }
}

fn width(wide: bool) -> Size {
    if wide { Size::Qword } else { Size::Dword }
}

/// `cvtsi2ss/sd xmm0, eax/rax`.
fn to_float(code: &mut Code, format: Format, wide: bool) {
    code.asm()
        .cvtsi2float(scalar_lanes(format), width(wide), RESULT_VECTOR, Rax);
}

/// `cvt(t)ss/sd2si eax/rax, xmm0`.
fn from_float(code: &mut Code, format: Format, truncate: bool, wide: bool) {
    code.asm().cvtfloat2si(
        scalar_lanes(format),
        truncate,
        width(wide),
        Rax,
        Rm::Xmm(RESULT_VECTOR),
    );
}

/// Move the low `width` lane of `vector` into RAX/EAX.
fn lane_from_vector(code: &mut Code, wide: bool, vector: u8) {
    if wide {
        code.asm().movq_from_xmm(Rax, vector);
    } else {
        code.asm().movd_from_xmm(Rax, vector);
    }
}

/// Move RAX/EAX into the low lane of `vector`, zeroing the rest.
fn lane_to_vector(code: &mut Code, wide: bool, vector: u8) {
    if wide {
        code.asm().movq_to_xmm(vector, Rax);
    } else {
        code.asm().movd_to_xmm(vector, Rax);
    }
}

fn rounding(rounding: IntegerRounding) -> Rounding {
    match rounding {
        IntegerRounding::NearestEven => Rounding::NearestEven,
        IntegerRounding::TowardPositive => Rounding::Positive,
        IntegerRounding::TowardNegative => Rounding::Negative,
        IntegerRounding::TowardZero => Rounding::Zero,
        IntegerRounding::NearestAway => unreachable!("ties-away conversions use the exact core"),
    }
}

fn integer_offset(integer: IntegerOperand, lane: u32) -> u32 {
    let IntegerOperand::Simd {
        register, format, ..
    } = integer
    else {
        unreachable!("general register operands have no SIMD offset")
    };
    vector_offset(register) + lane * (format.width.bits() / BITS_PER_BYTE)
}

/// AVX512-FP16 converts Half in one rounding; a fixed-point scale would add
/// another.
pub(super) fn half_supported(operand: &IntegerConversion, target: TargetCpu) -> bool {
    vector_extensions::half_supported(target) && operand.frac_bits == 0
}

fn read_integer(code: &mut Code, integer: IntegerOperand, lane: u32) {
    let format = integer.format();
    match integer {
        IntegerOperand::General { register, .. } => super::super::load(code, register),
        IntegerOperand::Simd { .. } if format.width == IntegerWidth::Bits16 => {
            let element = guest(integer_offset(integer, lane));
            if format.signed {
                code.asm().movsx(Size::Dword, Rax, Size::Word, element);
            } else {
                code.asm().movzx(Size::Dword, Rax, Size::Word, element);
            }
        }
        IntegerOperand::Simd { .. } => {
            code.asm().mov_load(
                width(format.width == IntegerWidth::Bits64),
                Rax,
                guest(integer_offset(integer, lane)),
            );
        }
    }
    if !format.signed && format.width == IntegerWidth::Bits32 {
        // The shared GPR load is 64-bit; unsigned W conversion reads only Wn.
        code.asm().mov(Size::Dword, Rax, Rax);
    }
}

fn float_constant(code: &mut Code, format: Format, exponent: i16, shape: Shape) {
    let (bias, fraction_bits) = match format {
        Format::Single => (SINGLE_EXPONENT_BIAS, Format::Single.fraction_bits()),
        Format::Double => (DOUBLE_EXPONENT_BIAS, Format::Double.fraction_bits()),
        Format::Half => unreachable!("half conversions use the exact core"),
    };
    let mut asm = code.asm();
    asm.mov_imm64(
        Rdx,
        u64::try_from(bias + exponent).expect("normal conversion scale") << fraction_bits,
    );
    asm.movq_to_xmm(TEMPORARY_VECTOR, Rdx);
    if shape != Shape::Scalar {
        if format == Format::Single {
            asm.shufps(
                TEMPORARY_VECTOR,
                Rm::Xmm(TEMPORARY_VECTOR),
                BROADCAST_LOW_SINGLE,
            );
        } else {
            asm.unpcklpd(TEMPORARY_VECTOR, Rm::Xmm(TEMPORARY_VECTOR));
        }
    }
}

fn scale(code: &mut Code, operand: &IntegerConversion, shape: Shape, direction: i16) {
    if operand.frac_bits != 0 {
        float_constant(
            code,
            operand.format,
            direction * i16::from(operand.frac_bits),
            shape,
        );
        emit_opcode(
            code,
            operand.format,
            shape,
            ArithmeticOpcode::Multiply,
            TEMPORARY_VECTOR,
        );
    }
}

fn convert_integer_lane(
    code: &mut Code,
    operand: &IntegerConversion,
    lane: u32,
    target: TargetCpu,
) {
    let integer = operand.integer.format();
    read_integer(code, operand.integer, lane);
    if operand.format == Format::Half {
        let wide = integer.width == IntegerWidth::Bits64;
        if integer.signed {
            vector_extensions::half_from_signed(code, RESULT_VECTOR, wide, Rax);
        } else {
            vector_extensions::scalar_from_unsigned(
                code,
                RESULT_VECTOR,
                Format::Half,
                wide,
                Rax,
                target,
            );
        }
        return;
    }
    let wide = integer.width == IntegerWidth::Bits64 || !integer.signed;
    if integer.signed || integer.width != IntegerWidth::Bits64 {
        to_float(code, operand.format, wide);
    } else if !vector_extensions::scalar_from_unsigned(
        code,
        RESULT_VECTOR,
        operand.format,
        true,
        Rax,
        target,
    ) {
        // High unsigned values do not fit CVTSI's signed input. Retaining a
        // sticky low bit before halving preserves all four rounding modes.
        let mut asm = code.asm();
        asm.mov(Size::Qword, Rcx, Rax);
        asm.shift_imm(ShiftOp::Shr, Size::Qword, Rcx, SIGN_BIT);
        let low = branch(code, Condition::Zero);
        let mut asm = code.asm();
        asm.mov(Size::Qword, Rcx, Rax);
        asm.alu_imm8(Alu::And, Size::Dword, Rcx, 1);
        asm.shift_one(ShiftOp::Shr, Size::Qword, Rax);
        asm.alu(Alu::Or, Size::Qword, Rax, Rcx);
        to_float(code, operand.format, true);
        emit_opcode(
            code,
            operand.format,
            Shape::Scalar,
            ArithmeticOpcode::Add,
            RESULT_VECTOR,
        );
        let done = jump(code);
        let low_start = code.len();
        resolve(code, low, low_start);
        to_float(code, operand.format, true);
        let end = code.len();
        resolve(code, done, end);
    }
    // For S/D and fbits<=64, this power-of-two rescaling stays normal and exact.
    scale(code, operand, Shape::Scalar, -1);
}

fn pack_integer_lane(code: &mut Code, width: IntegerWidth, lane: u32) {
    lane_to_vector(code, width == IntegerWidth::Bits64, TEMPORARY_VECTOR);
    if lane != 0 {
        ShiftOpcode::LeftBytes.emit(
            code,
            TEMPORARY_VECTOR,
            (lane * (width.bits() / BITS_PER_BYTE)) as u8,
        );
    }
    packed(code, Host::Or, INTEGER_ACCUMULATOR, TEMPORARY_VECTOR);
}

fn finish_float(code: &mut Code, operand: &IntegerConversion) {
    commit_inexact(code);
    if operand.integer.shape() == Shape::Scalar {
        test_control(code, FPCR_NEP);
        let merge = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, RESULT_VECTOR);
        let end = code.len();
        resolve(code, merge, end);
    }
    commit(code, operand.float, RESULT_VECTOR);
}

pub(in crate::x86_64) fn from_integer(
    code: &mut Code,
    operand: &IntegerConversion,
    pc: GuestAddress,
    target: TargetCpu,
) {
    if operand.format == Format::Half && !half_supported(operand, target) {
        // S->H after integer->S can double round; there is no baseline H CVT.
        helper(code, pc);
        return;
    }
    let shape = operand.integer.shape();
    let integer = operand.integer.format();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    let enabled = branch(code, Condition::NotZero);
    if shape == Shape::Scalar {
        read_vector(code, operand.float, RESULT_VECTOR);
    }
    environment_round(code, Rounding::Fpcr);
    let signed_single = operand.format == Format::Single && integer.signed;
    if shape != Shape::Scalar
        && (signed_single
            || vector_extensions::packed_conversion_supported(operand.format, integer, target))
    {
        let IntegerOperand::Simd { register, .. } = operand.integer else {
            unreachable!("vector integer source")
        };
        read_numerical_vector(code, shape, register, RESULT_VECTOR);
        if signed_single {
            Host::ConvertPackedDwordToSingle.register(
                code,
                RESULT_VECTOR,
                RESULT_VECTOR,
                TargetCpu::Baseline,
            );
        } else {
            vector_extensions::packed_from_integer(
                code,
                RESULT_VECTOR,
                operand.format,
                integer,
                target,
            );
        }
        scale(code, operand, shape, -1);
    } else if shape == Shape::Scalar {
        convert_integer_lane(code, operand, 0, target);
    } else {
        packed(code, Host::Xor, INTEGER_ACCUMULATOR, INTEGER_ACCUMULATOR);
        for lane in 0..shape.lane_count(operand.format) {
            convert_integer_lane(code, operand, lane, target);
            lane_from_vector(code, operand.format == Format::Double, RESULT_VECTOR);
            pack_integer_lane(code, integer.width, lane);
        }
        packed(code, Host::MoveAligned, RESULT_VECTOR, INTEGER_ACCUMULATOR);
    }
    restore_environment(code);
    let status = reject_other_status(code);
    let success = jump(code);
    let helper_start = code.len();
    resolve(code, enabled, helper_start);
    resolve(code, status, helper_start);
    helper(code, pc);
    let success_start = code.len();
    resolve(code, success, success_start);
    finish_float(code, operand);
}

fn guard_float_source(code: &mut Code, operand: &IntegerConversion) -> usize {
    let shape = operand.integer.shape();
    read_numerical_vector(code, shape, operand.float, RESULT_VECTOR);
    if shape == Shape::Scalar {
        exponent_range(code, operand.format, RESULT_VECTOR, INPUT_MINIMUM_EXPONENT);
        branch(code, Condition::AboveOrEqual)
    } else {
        prepare_vector_input_range(code, operand.format);
        vector_exponent_range(code, operand.format, shape, RESULT_VECTOR);
        branch(code, Condition::NotZero)
    }
}

fn read_float_lane(code: &mut Code, operand: &IntegerConversion, lane: u32) {
    let element =
        guest(vector_offset(operand.float) + lane * (operand.format.bits() / BITS_PER_BYTE));
    if operand.format == Format::Double {
        Host::MoveQword.emit(code, RESULT_VECTOR, element, TargetCpu::Baseline);
    } else {
        code.asm().movd_to_xmm(RESULT_VECTOR, element);
    }
}

/// VCVT(T)SH2(U)SI of the low Half lane. Half's largest finite value fits a
/// dword, so an H integer checks the range of the dword result.
fn half_to_general(
    code: &mut Code,
    integer: IntegerFormat,
    truncate: bool,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    let wide = integer.width == IntegerWidth::Bits64;
    if integer.signed {
        vector_extensions::half_to_signed(code, Rax, RESULT_VECTOR, wide, truncate);
    } else {
        vector_extensions::scalar_to_unsigned(
            code,
            Rax,
            RESULT_VECTOR,
            Format::Half,
            wide,
            truncate,
            target,
        );
    }
    if integer.width == IntegerWidth::Bits16 {
        let mut asm = code.asm();
        asm.mov(Size::Dword, Rdx, Rax);
        if integer.signed {
            asm.alu_imm32(Alu::Add, Size::Dword, Rdx, i32::from(i16::MAX) + 1);
        }
        asm.shift_imm(ShiftOp::Shr, Size::Dword, Rdx, u16::BITS as u8);
        failures.push(branch(code, Condition::NotZero));
    }
}

fn convert_float_lane(
    code: &mut Code,
    operand: &IntegerConversion,
    mode: IntegerRounding,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    let integer = operand.integer.format();
    let truncate = mode == IntegerRounding::TowardZero;
    let wide = integer.width == IntegerWidth::Bits64;
    if operand.format == Format::Half {
        half_to_general(code, integer, truncate, failures, target);
    } else if integer.signed {
        from_float(code, operand.format, truncate, wide);
    } else if !vector_extensions::scalar_to_unsigned(
        code,
        Rax,
        RESULT_VECTOR,
        operand.format,
        wide,
        truncate,
        target,
    ) {
        if integer.width == IntegerWidth::Bits32 {
            from_float(code, operand.format, truncate, true);
            let mut asm = code.asm();
            asm.mov(Size::Qword, Rdx, Rax);
            asm.shift_imm(ShiftOp::Shr, Size::Qword, Rdx, u32::BITS as u8);
            asm.test(Size::Dword, Rdx, Rdx);
            failures.push(branch(code, Condition::NotZero));
        } else {
            float_constant(code, operand.format, UNSIGNED_HIGH_EXPONENT, Shape::Scalar);
            if operand.format == Format::Single {
                code.asm().ucomiss(RESULT_VECTOR, Rm::Xmm(TEMPORARY_VECTOR));
            } else {
                code.asm().ucomisd(RESULT_VECTOR, Rm::Xmm(TEMPORARY_VECTOR));
            }
            let low = branch(code, Condition::Below);
            // Subtraction is exact throughout [2^63,2^64) (Sterbenz). Anything
            // beyond that interval raises native invalid and is retried by the core.
            emit_opcode(
                code,
                operand.format,
                Shape::Scalar,
                ArithmeticOpcode::Subtract,
                TEMPORARY_VECTOR,
            );
            from_float(code, operand.format, truncate, true);
            code.asm().bit_imm(BitTest::Bts, Size::Qword, Rax, SIGN_BIT);
            let done = jump(code);
            let low_start = code.len();
            resolve(code, low, low_start);
            from_float(code, operand.format, truncate, true);
            code.asm().bit_imm(BitTest::Bt, Size::Qword, Rax, SIGN_BIT);
            failures.push(branch(code, Condition::Below));
            let end = code.len();
            resolve(code, done, end);
        }
    }
}

fn finish_integer(code: &mut Code, operand: &IntegerConversion, packed_result: bool) {
    commit_inexact(code);
    match operand.integer {
        IntegerOperand::General { register, .. } => super::super::store(code, register),
        IntegerOperand::Simd {
            register,
            format,
            shape,
        } => {
            if shape != Shape::Scalar {
                if !packed_result {
                    packed(code, Host::MoveAligned, RESULT_VECTOR, INTEGER_ACCUMULATOR);
                }
            } else {
                read_vector(code, register, RESULT_VECTOR);
                if format.width == IntegerWidth::Bits16 {
                    code.asm().pinsrw(RESULT_VECTOR, Rax, 0);
                } else {
                    let wide = format.width == IntegerWidth::Bits64;
                    lane_to_vector(code, wide, TEMPORARY_VECTOR);
                    if wide {
                        Host::MoveScalarDouble
                    } else {
                        Host::MoveScalarSingle
                    }
                    .register(
                        code,
                        RESULT_VECTOR,
                        TEMPORARY_VECTOR,
                        TargetCpu::Baseline,
                    );
                }
                test_control(code, FPCR_NEP);
                let merge = branch(code, Condition::NotZero);
                clear_scalar(code, operand.format, RESULT_VECTOR);
                let end = code.len();
                resolve(code, merge, end);
            }
            commit(code, register, RESULT_VECTOR);
        }
    }
}

pub(in crate::x86_64) fn to_integer(
    code: &mut Code,
    operand: &IntegerConversion,
    mode: IntegerRounding,
    pc: GuestAddress,
    target: TargetCpu,
) {
    if operand.format == Format::Half && !half_supported(operand, target)
        || mode == IntegerRounding::NearestAway
    {
        // SSE2 has no ties-away control. Adding 0.5 before truncation double
        // rounds near half ties; keep the exact integer-core route instead.
        helper(code, pc);
        return;
    }
    let shape = operand.integer.shape();
    let integer = operand.integer.format();
    let signed_single = operand.format == Format::Single && integer.signed;
    let packed_result = shape != Shape::Scalar
        && (signed_single
            || vector_extensions::packed_conversion_supported(operand.format, integer, target));
    let mut helper_patches = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper_patches.push(branch(code, Condition::NotZero));
    helper_patches.push(guard_float_source(code, operand));
    environment_round(code, rounding(mode));
    let mut environment_failures = Vec::new();
    if packed_result {
        scale(code, operand, shape, 1);
        if !signed_single {
            vector_extensions::packed_to_integer(
                code,
                RESULT_VECTOR,
                operand.format,
                integer,
                mode == IntegerRounding::TowardZero,
                target,
            );
        } else if mode == IntegerRounding::TowardZero {
            code.asm().cvttps2dq(RESULT_VECTOR, Rm::Xmm(RESULT_VECTOR));
        } else {
            Host::ConvertPackedSingleToDword.register(
                code,
                RESULT_VECTOR,
                RESULT_VECTOR,
                TargetCpu::Baseline,
            );
        }
    } else {
        if shape != Shape::Scalar {
            packed(code, Host::Xor, INTEGER_ACCUMULATOR, INTEGER_ACCUMULATOR);
        }
        for lane in 0..shape.lane_count(operand.format) {
            read_float_lane(code, operand, lane);
            scale(code, operand, Shape::Scalar, 1);
            convert_float_lane(code, operand, mode, &mut environment_failures, target);
            if shape != Shape::Scalar {
                pack_integer_lane(code, integer.width, lane);
            }
        }
    }
    restore_environment(code);
    helper_patches.push(reject_other_status(code));
    let success = jump(code);
    if !environment_failures.is_empty() {
        // Range failures occur before commit. Their cold path restores exactly
        // the same caller environment as the normal completion path.
        let restore_start = code.len();
        for patch in environment_failures {
            resolve(code, patch, restore_start);
        }
        restore_environment(code);
    }
    let helper_start = code.len();
    for patch in helper_patches {
        resolve(code, patch, helper_start);
    }
    helper(code, pc);
    let success_start = code.len();
    resolve(code, success, success_start);
    finish_integer(code, operand, packed_result);
}

pub(in crate::x86_64) fn javascript(
    code: &mut Code,
    destination: Register,
    source: u8,
    pc: GuestAddress,
    target: TargetCpu,
) {
    const NZCV_ZERO_SHIFT: u32 = 30;
    const INEXACT_TO_NZCV_SHIFT: u8 = (NZCV_ZERO_SHIFT - INEXACT.trailing_zeros()) as u8;
    let operand = IntegerConversion {
        integer: IntegerOperand::General {
            register: destination,
            format: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: true,
            },
        },
        float: source,
        format: Format::Double,
        frac_bits: 0,
    };
    // A normal input whose truncated value fits in 32 bits gives the JavaScript
    // result directly. Other inputs exit to software completion of FJCVTZS,
    // which handles wrapping, special values and zeros.
    to_integer(code, &operand, IntegerRounding::TowardZero, pc, target);
    // commit_inexact leaves only fresh IXC in ECX. Accumulated FPSR.IXC must
    // not clear Z for a later exact input, including a discarded WZR result.
    let shift = match code.is_pinned() {
        true => (flag_word::ZERO.trailing_zeros() - INEXACT.trailing_zeros()) as u8,
        false => INEXACT_TO_NZCV_SHIFT,
    };
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Xor, Size::Dword, Rcx, INEXACT as i8);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Rcx, shift);
    flag_word::store(&mut asm, Rcx);
}
