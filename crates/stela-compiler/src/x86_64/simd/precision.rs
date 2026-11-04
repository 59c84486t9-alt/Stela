//! FCVT between FP formats: SSE2, F16C, AVX512-FP16 or integer paths, software
//! fallback otherwise.
use super::super::isa::ShiftOpcode;
use super::numerical::helper_section;
use super::numerical::{
    ArithmeticOpcode, Condition, INPUT_MINIMUM_EXPONENT, MINIMUM_EXPONENT_VECTOR,
    RESULT_MINIMUM_EXPONENT, Rounding, branch, clear_scalar, commit_inexact, environment_round,
    exponent_range, jump, prepare_half_result_range, prepare_vector_input_range,
    prepare_vector_result_range, read_numerical_vector, reject_other_status, resolve,
    restore_environment, single_vector_arithmetic, test_control, vector_exponent_range,
};
use super::{Host, commit, encode::guest, packed, read_vector, vector_offset};
use crate::x86_64::asm::FloatLanes;
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Rm, ShiftOp, Size, vector_extensions};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{
            FPCR_AHP, FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format, precision::PrecisionRounding,
        },
        simd::{
            arithmetic::Shape,
            conversion::{PrecisionMode, PrecisionOperand},
        },
    },
    block::ExitKind,
};
use Gpr::{Rax, Rcx};
use alloc::vec::Vec;

const RESULT_VECTOR: u8 = 0;
const SOURCE_VECTOR: u8 = 1;
const JAM_VECTOR: u8 = 6;
/// The low Half of a scalar narrowing, ahead of its merge into old Vd.
const HALF_LANE_VECTOR: u8 = 6;
/// VCVTPS2PH's immediate: round by MXCSR.RC.
const CONVERT_USING_MXCSR: u8 = 1 << 2;
const COMPARE_EQUAL: u8 = 0;
const UPPER_QWORD_BYTES: u8 = 8;
const HALF_EXPONENT_BITS: u8 = 5;
const HALF_EXPONENT_MASK: u32 = (1 << HALF_EXPONENT_BITS) - 1;
const HALF_NORMAL_EXPONENT_COUNT: u8 = HALF_EXPONENT_MASK as u8 - 1;
const HALF_SIGN: u32 = 1 << (u16::BITS - 1);
const HALF_MAGNITUDE: u32 = HALF_SIGN - 1;
const HALF_TO_SINGLE_FRACTION_SHIFT: u8 = 13;
const HALF_TO_SINGLE_SIGN_SHIFT: u8 = 16;
const SINGLE_EXPONENT_MASK: u32 =
    (1 << (Format::Single.bits() - Format::Single.fraction_bits() - 1)) - 1;
const HALF_TO_SINGLE_BIAS: u32 =
    ((SINGLE_EXPONENT_MASK >> 1) - (HALF_EXPONENT_MASK >> 1)) << Format::Single.fraction_bits();
const HALF_FIELD_TO_DWORD_TOP: u8 = u32::BITS as u8 - HALF_TO_SINGLE_SIGN_SHIFT + 1;
const HALF_EXPONENT_TO_DWORD_BOTTOM: u8 = u32::BITS as u8 - HALF_EXPONENT_BITS;
const HALF_MAXIMUM_TO_BIAS_BITS: u8 = 2;
const SINGLE_BIAS_POSITION: u8 = HALF_TO_SINGLE_BIAS.trailing_zeros() as u8;
const HALF_VALIDITY_MASK: i8 = 0x0f;
const HALF_NORMAL_VECTOR: u8 = 2;
const HALF_FINITE_VECTOR: u8 = 3;
const HALF_MAXIMUM_VECTOR: u8 = 4;
const HALF_ZERO_VECTOR: u8 = 5;
const HALF_SCALED_VECTOR: u8 = 6;
const HALF_SUBNORMAL_SCALE: u32 = (Format::Single.exponent_bias() + 1
    - Format::Half.exponent_bias()
    - Format::Half.fraction_bits())
    << Format::Single.fraction_bits();
const DOUBLE_TO_SINGLE_DISCARDED_BITS: u8 = 29;
const DOUBLE_TO_SINGLE_DISCARDED_MASK: u32 = (1 << DOUBLE_TO_SINGLE_DISCARDED_BITS) - 1;
const COMPACT_QWORD_LOW_DWORDS: u8 = 0x88;
const DWORD_SIGN_TO_LSB_SHIFT: u8 = u32::BITS as u8 - 1;

fn exception_guard(code: &mut Code, helper: &mut Vec<usize>) {
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
}

fn scalar_commit(code: &mut Code, destination: u8, format: Format) {
    test_control(code, FPCR_NEP);
    let merging = branch(code, Condition::NotZero);
    clear_scalar(code, format, RESULT_VECTOR);
    let merge_target = code.len();
    resolve(code, merging, merge_target);
    commit(code, destination, RESULT_VECTOR);
}

fn half_normal_guard(code: &mut Code, helper: &mut Vec<usize>) {
    let mut asm = code.asm();
    asm.movd_from_xmm(Rax, SOURCE_VECTOR);
    asm.shift_imm(
        ShiftOp::Shr,
        Size::Dword,
        Rax,
        Format::Half.fraction_bits() as u8,
    );
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, HALF_EXPONENT_MASK as i32);
    asm.alu_imm8(Alu::Sub, Size::Dword, Rax, 1);
    asm.alu_imm8(Alu::Cmp, Size::Dword, Rax, HALF_NORMAL_EXPONENT_COUNT as i8);
    helper.push(branch(code, Condition::AboveOrEqual));
}

/// Exact normal half widening uses only field construction. In particular,
/// conversion ignores FZ16, and no host numerical half extension is assumed.
fn half_to_single(code: &mut Code) {
    let mut asm = code.asm();
    asm.movd_from_xmm(Rax, SOURCE_VECTOR);
    asm.mov(Size::Dword, Rcx, Rax);
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, HALF_MAGNITUDE as i32);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Dword,
        Rax,
        HALF_TO_SINGLE_FRACTION_SHIFT,
    );
    asm.alu_accumulator_imm32(Alu::Add, Size::Dword, HALF_TO_SINGLE_BIAS as i32);
    asm.alu_imm32(Alu::And, Size::Dword, Rcx, HALF_SIGN as i32);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Rcx, HALF_TO_SINGLE_SIGN_SHIFT);
    asm.alu(Alu::Or, Size::Dword, Rax, Rcx);
    asm.movd_to_xmm(SOURCE_VECTOR, Rax);
}

fn scalar_odd_jam(code: &mut Code) {
    // The source is a normal double and the result a normal single, so exactly
    // the low 29 fraction bits are discarded.
    let mut asm = code.asm();
    asm.movq_from_xmm(Rax, SOURCE_VECTOR);
    asm.alu_accumulator_imm32(
        Alu::And,
        Size::Dword,
        DOUBLE_TO_SINGLE_DISCARDED_MASK as i32,
    );
    asm.setcc(Cond::Ne, Rax);
    asm.movzx(Size::Dword, Rax, Size::Byte, Rax);
    asm.movd_to_xmm(JAM_VECTOR, Rax);
    packed(code, Host::Or, RESULT_VECTOR, JAM_VECTOR);
}

pub(in crate::x86_64) fn jam_odd_pair(code: &mut Code, one_vector: u8) {
    // The normal single widens exactly and is compared with its source double
    // lane without raising host status. A lane's sticky bit never comes from
    // the aggregate PE flag. The range preparation leaves 1 in every dword of
    // MINIMUM_EXPONENT_VECTOR.
    let mut asm = code.asm();
    asm.cvtps2pd(JAM_VECTOR, Rm::Xmm(RESULT_VECTOR));
    asm.float_compare(
        FloatLanes::PackedDouble,
        JAM_VECTOR,
        Rm::Xmm(SOURCE_VECTOR),
        COMPARE_EQUAL,
    );
    super::shuffle(code, JAM_VECTOR, JAM_VECTOR, COMPACT_QWORD_LOW_DWORDS);
    packed(code, Host::AndNot, JAM_VECTOR, one_vector);
    // PSHUFD duplicates masks into inactive upper lanes. Clear those masks so
    // CVTPD2PS's architecturally zero upper qword remains zero.
    clear_scalar(code, Format::Double, JAM_VECTOR);
    packed(code, Host::Or, RESULT_VECTOR, JAM_VECTOR);
}

fn vector_odd_jam(code: &mut Code) {
    jam_odd_pair(code, MINIMUM_EXPONENT_VECTOR);
}

fn emit_scalar(
    code: &mut Code,
    operand: &PrecisionOperand,
    source: Format,
    destination: Format,
    rounding: PrecisionRounding,
    pc: GuestAddress,
) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_vector(code, operand.source, SOURCE_VECTOR);
    // Precision conversions merge old Vd, unlike binary arithmetic's Vn merge.
    read_vector(code, operand.destination, RESULT_VECTOR);
    if source == Format::Half {
        half_normal_guard(code, &mut helper);
        half_to_single(code);
        if destination == Format::Double {
            code.asm().cvtss2sd(RESULT_VECTOR, Rm::Xmm(SOURCE_VECTOR));
        } else {
            Host::MoveScalarSingle.register(
                code,
                RESULT_VECTOR,
                SOURCE_VECTOR,
                crate::TargetCpu::Baseline,
            );
        }
    } else {
        exponent_range(code, source, SOURCE_VECTOR, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
        if destination == Format::Double {
            // Normal S→D is exact, unaffected by ambient RC/DAZ/FTZ/masks,
            // and raises neither Intel Invalid nor Denormal. Preserve MXCSR.
            code.asm().cvtss2sd(RESULT_VECTOR, Rm::Xmm(SOURCE_VECTOR));
        } else {
            environment_round(
                code,
                if rounding == PrecisionRounding::ToOdd {
                    Rounding::Zero
                } else {
                    Rounding::Fpcr
                },
            );
            code.asm().cvtsd2ss(RESULT_VECTOR, Rm::Xmm(SOURCE_VECTOR));
            restore_environment(code);
            helper.push(reject_other_status(code));
            exponent_range(code, destination, RESULT_VECTOR, RESULT_MINIMUM_EXPONENT);
            helper.push(branch(code, Condition::AboveOrEqual));
            if rounding == PrecisionRounding::ToOdd {
                scalar_odd_jam(code);
            }
        }
    }
    helper_section(code, &helper, pc);
    if source == Format::Double && destination == Format::Single {
        commit_inexact(code);
    }
    scalar_commit(code, operand.destination, destination);
}

/// Branch if any exponent is outside the normal IEEE half range. Keep the
/// normal and finite lane masks for the zero and subnormal path.
fn half_normal_widening_guard(code: &mut Code) -> usize {
    packed(
        code,
        Host::EqualDword,
        HALF_MAXIMUM_VECTOR,
        HALF_MAXIMUM_VECTOR,
    );
    ShiftOpcode::RightDword.emit(code, HALF_MAXIMUM_VECTOR, HALF_EXPONENT_TO_DWORD_BOTTOM);
    packed(code, Host::MoveAligned, HALF_NORMAL_VECTOR, SOURCE_VECTOR);
    ShiftOpcode::LeftDword.emit(code, HALF_NORMAL_VECTOR, HALF_FIELD_TO_DWORD_TOP);
    ShiftOpcode::RightDword.emit(code, HALF_NORMAL_VECTOR, HALF_EXPONENT_TO_DWORD_BOTTOM);
    packed(
        code,
        Host::MoveAligned,
        HALF_FINITE_VECTOR,
        HALF_MAXIMUM_VECTOR,
    );
    packed(
        code,
        Host::GreaterDword,
        HALF_FINITE_VECTOR,
        HALF_NORMAL_VECTOR,
    );
    packed(
        code,
        Host::GreaterDword,
        HALF_NORMAL_VECTOR,
        HALF_ZERO_VECTOR,
    );
    packed(code, Host::And, HALF_NORMAL_VECTOR, HALF_FINITE_VECTOR);
    Host::DwordSignMask.register(code, 0, HALF_NORMAL_VECTOR, TargetCpu::Baseline);
    code.asm()
        .alu_imm8(Alu::Cmp, Size::Dword, Rax, HALF_VALIDITY_MASK);
    branch(code, Condition::NotZero)
}

fn add_half_widening_bias(code: &mut Code) {
    // The guard keeps exponent mask 31; 31 >> 2 gives 7, and 7 << 27 is
    // exactly the S-vs-H exponent bias adjustment. Reuse that constant.
    ShiftOpcode::RightDword.emit(code, HALF_MAXIMUM_VECTOR, HALF_MAXIMUM_TO_BIAS_BITS);
    ShiftOpcode::LeftDword.emit(code, HALF_MAXIMUM_VECTOR, SINGLE_BIAS_POSITION);
    packed(code, Host::AddDword, SOURCE_VECTOR, HALF_MAXIMUM_VECTOR);
}

fn widen_finite_half(code: &mut Code, helper: &mut Vec<usize>) {
    // Exponent 31 needs exact completion for AHP, infinity, and NaNs.
    Host::DwordSignMask.register(code, 0, HALF_FINITE_VECTOR, TargetCpu::Baseline);
    code.asm()
        .alu_imm8(Alu::Cmp, Size::Dword, Rax, HALF_VALIDITY_MASK);
    helper.push(branch(code, Condition::NotZero));
    // Every 15-bit integer converts exactly to single, and scaling by 2^-24
    // produces a normal single or +0. The temporary leaves MXCSR untouched
    // even in lanes where the result comes from the normal representation.
    ShiftOpcode::LeftDword.emit(code, SOURCE_VECTOR, HALF_FIELD_TO_DWORD_TOP);
    ShiftOpcode::RightDword.emit(code, SOURCE_VECTOR, HALF_FIELD_TO_DWORD_TOP);
    packed(
        code,
        Host::ConvertPackedDwordToSingle,
        HALF_SCALED_VECTOR,
        SOURCE_VECTOR,
    );
    code.asm().mov_imm32(Rax, HALF_SUBNORMAL_SCALE);
    code.asm().movd_to_xmm(HALF_FINITE_VECTOR, Rax);
    super::shuffle(code, HALF_FINITE_VECTOR, HALF_FINITE_VECTOR, 0);
    single_vector_arithmetic(
        code,
        ArithmeticOpcode::Multiply,
        HALF_SCALED_VECTOR,
        HALF_FINITE_VECTOR,
    );
    ShiftOpcode::LeftDword.emit(code, SOURCE_VECTOR, HALF_TO_SINGLE_FRACTION_SHIFT);
    add_half_widening_bias(code);
    packed(code, Host::And, SOURCE_VECTOR, HALF_NORMAL_VECTOR);
    packed(code, Host::AndNot, HALF_NORMAL_VECTOR, HALF_SCALED_VECTOR);
    packed(code, Host::Or, SOURCE_VECTOR, HALF_NORMAL_VECTOR);
}

fn emit_widen_half(code: &mut Code, operand: &PrecisionOperand, upper: bool, pc: GuestAddress) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    let part = vector_offset(operand.source) + u32::from(upper) * u32::from(UPPER_QWORD_BYTES);
    Host::MoveQword.emit(code, SOURCE_VECTOR, guest(part), TargetCpu::Baseline);
    packed(code, Host::Xor, HALF_ZERO_VECTOR, HALF_ZERO_VECTOR);
    packed(code, Host::UnpackLowWord, SOURCE_VECTOR, HALF_ZERO_VECTOR);
    packed(code, Host::MoveAligned, RESULT_VECTOR, SOURCE_VECTOR);
    let needs_scaling = half_normal_widening_guard(code);
    // Normal half lanes need only an exponent bias and a field shift.
    ShiftOpcode::LeftDword.emit(code, SOURCE_VECTOR, HALF_FIELD_TO_DWORD_TOP);
    ShiftOpcode::RightDword.emit(
        code,
        SOURCE_VECTOR,
        HALF_FIELD_TO_DWORD_TOP - HALF_TO_SINGLE_FRACTION_SHIFT,
    );
    add_half_widening_bias(code);
    let normal = jump(code);
    let other = code.len();
    resolve(code, needs_scaling, other);
    widen_finite_half(code, &mut helper);
    helper_section(code, &helper, pc);
    let complete = code.len();
    resolve(code, normal, complete);
    ShiftOpcode::LeftDword.emit(code, RESULT_VECTOR, HALF_TO_SINGLE_SIGN_SHIFT);
    ShiftOpcode::RightDword.emit(code, RESULT_VECTOR, DWORD_SIGN_TO_LSB_SHIFT);
    ShiftOpcode::LeftDword.emit(code, RESULT_VECTOR, DWORD_SIGN_TO_LSB_SHIFT);
    packed(code, Host::Or, RESULT_VECTOR, SOURCE_VECTOR);
    commit(code, operand.destination, RESULT_VECTOR);
}

fn emit_widen(code: &mut Code, operand: &PrecisionOperand, upper: bool, pc: GuestAddress) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_vector(code, operand.source, SOURCE_VECTOR);
    if upper {
        ShiftOpcode::RightBytes.emit(code, SOURCE_VECTOR, UPPER_QWORD_BYTES);
    }
    prepare_vector_input_range(code, Format::Single);
    vector_exponent_range(code, Format::Single, Shape::Vector64, SOURCE_VECTOR);
    helper.push(branch(code, Condition::NotZero));
    code.asm().cvtps2pd(RESULT_VECTOR, Rm::Xmm(SOURCE_VECTOR));
    helper_section(code, &helper, pc);
    commit(code, operand.destination, RESULT_VECTOR);
}

fn emit_narrow(
    code: &mut Code,
    operand: &PrecisionOperand,
    upper: bool,
    rounding: PrecisionRounding,
    pc: GuestAddress,
) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_numerical_vector(code, Shape::Vector128, operand.source, SOURCE_VECTOR);
    prepare_vector_input_range(code, Format::Double);
    vector_exponent_range(code, Format::Double, Shape::Vector128, SOURCE_VECTOR);
    helper.push(branch(code, Condition::NotZero));
    environment_round(
        code,
        if rounding == PrecisionRounding::ToOdd {
            Rounding::Zero
        } else {
            Rounding::Fpcr
        },
    );
    code.asm().cvtpd2ps(RESULT_VECTOR, Rm::Xmm(SOURCE_VECTOR));
    restore_environment(code);
    helper.push(reject_other_status(code));
    // Conversion changes both element size and lane count. Rebuild the bounds
    // for the S result and check only its two active output lanes.
    prepare_vector_input_range(code, Format::Single);
    prepare_vector_result_range(code);
    vector_exponent_range(code, Format::Single, Shape::Vector64, RESULT_VECTOR);
    helper.push(branch(code, Condition::NotZero));
    if rounding == PrecisionRounding::ToOdd {
        vector_odd_jam(code);
    }
    helper_section(code, &helper, pc);
    commit_inexact(code);
    if upper {
        read_vector(code, operand.destination, SOURCE_VECTOR);
        code.asm().movlhps(SOURCE_VECTOR, Rm::Xmm(RESULT_VECTOR));
        commit(code, operand.destination, SOURCE_VECTOR);
    } else {
        commit(code, operand.destination, RESULT_VECTOR);
    }
}

/// VCVTPS2PH narrows Single in one rounding, and AVX512-FP16's VCVTSD2SH
/// narrows Double. The DIT profile keeps its reviewed recipe.
pub(super) fn half_narrowing_supported(mode: PrecisionMode, target: TargetCpu) -> bool {
    match mode {
        PrecisionMode::Narrow {
            destination: Format::Half,
            ..
        }
        | PrecisionMode::Scalar {
            source: Format::Single,
            destination: Format::Half,
            ..
        } => target.supports(TargetCpu::F16c) && !target.data_independent_timing(),
        PrecisionMode::Scalar {
            source: Format::Double,
            destination: Format::Half,
            ..
        } => vector_extensions::half_supported(target),
        _ => false,
    }
}

/// Narrow to Half under the guards of the Half arithmetic path: normal inputs,
/// and a helper for other status or a result below exponent 2, so x86's
/// tininess rule never decides a guest result. FPCR.AHP selects a format the
/// host lacks.
fn emit_narrow_half(
    code: &mut Code,
    operand: &PrecisionOperand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    test_control(code, FPCR_AHP);
    helper.push(branch(code, Condition::NotZero));
    let scalar = match operand.mode {
        PrecisionMode::Scalar { source, .. } => Some(source),
        _ => None,
    };
    if let Some(source) = scalar {
        read_vector(code, operand.source, SOURCE_VECTOR);
        exponent_range(code, source, SOURCE_VECTOR, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
        clear_scalar(code, source, SOURCE_VECTOR);
    } else {
        read_numerical_vector(code, Shape::Vector128, operand.source, SOURCE_VECTOR);
        prepare_vector_input_range(code, Format::Single);
        vector_exponent_range(code, Format::Single, Shape::Vector128, SOURCE_VECTOR);
        helper.push(branch(code, Condition::NotZero));
    }
    let result = if scalar.is_some() {
        HALF_LANE_VECTOR
    } else {
        RESULT_VECTOR
    };
    environment_round(code, Rounding::Fpcr);
    if scalar == Some(Format::Double) {
        vector_extensions::half_from_double(code, result, SOURCE_VECTOR);
    } else {
        // VCVTPS2PH encodes its source in ModRM.reg, and clears above the low
        // qword of its destination.
        Host::ConvertSingleToHalf.register_imm(
            code,
            SOURCE_VECTOR,
            result,
            CONVERT_USING_MXCSR,
            target,
        );
    }
    restore_environment(code);
    helper.push(reject_other_status(code));
    prepare_vector_input_range(code, Format::Half);
    prepare_half_result_range(code);
    let shape = if scalar.is_some() {
        Shape::Scalar
    } else {
        Shape::Vector64
    };
    vector_exponent_range(code, Format::Half, shape, result);
    helper.push(branch(code, Condition::NotZero));
    helper_section(code, &helper, pc);
    commit_inexact(code);
    match operand.mode {
        PrecisionMode::Narrow { upper: true, .. } => {
            read_vector(code, operand.destination, SOURCE_VECTOR);
            code.asm().movlhps(SOURCE_VECTOR, Rm::Xmm(RESULT_VECTOR));
            commit(code, operand.destination, SOURCE_VECTOR);
        }
        PrecisionMode::Narrow { .. } => commit(code, operand.destination, RESULT_VECTOR),
        _ => {
            read_vector(code, operand.destination, RESULT_VECTOR);
            let mut asm = code.asm();
            asm.movd_from_xmm(Rax, HALF_LANE_VECTOR);
            asm.pinsrw(RESULT_VECTOR, Rax, 0);
            scalar_commit(code, operand.destination, Format::Half);
        }
    }
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: &PrecisionOperand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    if half_narrowing_supported(operand.mode, target) {
        emit_narrow_half(code, operand, pc, target);
        return;
    }
    match operand.mode {
        PrecisionMode::Scalar {
            source,
            destination,
            rounding,
        } if destination != Format::Half => {
            emit_scalar(code, operand, source, destination, rounding, pc);
        }
        PrecisionMode::Widen {
            source: Format::Half,
            upper,
        } => emit_widen_half(code, operand, upper, pc),
        PrecisionMode::Widen {
            source: Format::Single,
            upper,
        } => emit_widen(code, operand, upper, pc),
        PrecisionMode::Narrow {
            destination: Format::Single,
            upper,
            rounding,
        } => emit_narrow(code, operand, upper, rounding, pc),
        _ => super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint),
    }
}
