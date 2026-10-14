//! Precision conversion: guarded SSE2/integer mappings and exact-core fallback.
use super::super::isa::ShiftOpcode;
use super::numerical::{
    Condition, INPUT_MINIMUM_EXPONENT, MINIMUM_EXPONENT_VECTOR, RESULT_MINIMUM_EXPONENT, Rounding,
    branch, clear_scalar, commit_inexact, environment_round, exponent_range,
    prepare_vector_input_range, prepare_vector_result_range, read_numerical_vector,
    reject_other_status, resolve, restore_environment, test_control, vector_exponent_range,
};
use super::{Host, commit, packed, read_vector};
use crate::{
    GuestAddress,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format, precision::PrecisionRounding},
        simd::{
            arithmetic::Shape,
            conversion::{PrecisionMode, PrecisionOperand},
        },
    },
    block::ExitKind,
};

const RESULT_VECTOR: u8 = 0;
const SOURCE_VECTOR: u8 = 1;
const JAM_VECTOR: u8 = 6;
const CVTSS2SD_XMM0_XMM1: &[u8] = &[0xf3, 0x0f, 0x5a, 0xc1];
const CVTSD2SS_XMM0_XMM1: &[u8] = &[0xf2, 0x0f, 0x5a, 0xc1];
const CVTPS2PD_XMM0_XMM1: &[u8] = &[0x0f, 0x5a, 0xc1];
const CVTPS2PD_XMM6_XMM0: &[u8] = &[0x0f, 0x5a, 0xf0];
const CMPEQPD_XMM6_XMM1: &[u8] = &[0x66, 0x0f, 0xc2, 0xf1, 0];
const CVTPD2PS_XMM0_XMM1: &[u8] = &[0x66, 0x0f, 0x5a, 0xc1];
const PSRLDQ_XMM1_8: &[u8] = &[0x66, 0x0f, 0x73, 0xd9, 8];
const MOVLHPS_XMM1_XMM0: &[u8] = &[0x0f, 0x16, 0xc8];
const MOVSS_XMM0_XMM1: &[u8] = &[0xf3, 0x0f, 0x10, 0xc1];
const MOVD_EAX_XMM1: &[u8] = &[0x66, 0x0f, 0x7e, 0xc8];
const MOVD_XMM1_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc8];
const MOVQ_RAX_XMM1: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc8];
const MOVD_XMM6_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xf0];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const AND_EAX_IMM32: u8 = 0x25;
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const ADD_EAX_IMM32: u8 = 0x05;
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const SHL_ECX_IMM8: &[u8] = &[0xc1, 0xe1];
const SUB_EAX_1: &[u8] = &[0x83, 0xe8, 1];
const CMP_EAX_IMM8: &[u8] = &[0x83, 0xf8];
const SETNE_AL: &[u8] = &[0x0f, 0x95, 0xc0];
const MOVZX_EAX_AL: &[u8] = &[0x0f, 0xb6, 0xc0];
const JMP_REL32: u8 = 0xe9;
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
const HALF_VALIDITY_MASK: u8 = 0x0f;
const HALF_EXPONENT_VECTOR: u8 = 2;
const HALF_VALIDITY_VECTOR: u8 = 3;
const HALF_MAXIMUM_VECTOR: u8 = 4;
const HALF_MINIMUM_VECTOR: u8 = 5;
const DOUBLE_TO_SINGLE_DISCARDED_BITS: u8 = 29;
const DOUBLE_TO_SINGLE_DISCARDED_MASK: u32 = (1 << DOUBLE_TO_SINGLE_DISCARDED_BITS) - 1;
const COMPACT_QWORD_LOW_DWORDS: u8 = 0x88;
const DWORD_SIGN_TO_LSB_SHIFT: u8 = u32::BITS as u8 - 1;

fn exception_guard(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
}

/// Keep all failure branches ahead of guest-state commit. No private host
/// environment may remain installed when this common helper section is emitted.
fn helper_section(code: &mut Vec<u8>, helper: &[usize], pc: GuestAddress) {
    code.push(JMP_REL32);
    let completed = code.len();
    code.extend(0i32.to_le_bytes());
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success_start = code.len();
    for &patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, completed, success_start);
}

fn scalar_commit(code: &mut Vec<u8>, destination: u8, format: Format) {
    test_control(code, FPCR_NEP);
    let merging = branch(code, Condition::NotZero);
    clear_scalar(code, format, RESULT_VECTOR);
    let merge_target = code.len();
    resolve(code, merging, merge_target);
    commit(code, destination, RESULT_VECTOR);
}

fn half_normal_guard(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    code.extend(MOVD_EAX_XMM1);
    code.extend(SHR_EAX_IMM8);
    code.push(Format::Half.fraction_bits() as u8);
    code.push(AND_EAX_IMM32);
    code.extend(HALF_EXPONENT_MASK.to_le_bytes());
    code.extend(SUB_EAX_1);
    code.extend(CMP_EAX_IMM8);
    code.push(HALF_NORMAL_EXPONENT_COUNT);
    helper.push(branch(code, Condition::AboveOrEqual));
}

/// Exact normal half widening uses only field construction. In particular,
/// conversion ignores FZ16, and no host numerical half extension is assumed.
fn half_to_single(code: &mut Vec<u8>) {
    code.extend(MOVD_EAX_XMM1);
    code.extend(MOV_ECX_EAX);
    code.push(AND_EAX_IMM32);
    code.extend(HALF_MAGNITUDE.to_le_bytes());
    code.extend(SHL_EAX_IMM8);
    code.push(HALF_TO_SINGLE_FRACTION_SHIFT);
    code.push(ADD_EAX_IMM32);
    code.extend(HALF_TO_SINGLE_BIAS.to_le_bytes());
    code.extend(AND_ECX_IMM32);
    code.extend(HALF_SIGN.to_le_bytes());
    code.extend(SHL_ECX_IMM8);
    code.push(HALF_TO_SINGLE_SIGN_SHIFT);
    code.extend(OR_EAX_ECX);
    code.extend(MOVD_XMM1_EAX);
}

fn scalar_odd_jam(code: &mut Vec<u8>) {
    // Source is an accepted normal D and result is normal S. Exactly the low
    // 29 original fraction bits are discarded, independently of the sign.
    code.extend(MOVQ_RAX_XMM1);
    code.push(AND_EAX_IMM32);
    code.extend(DOUBLE_TO_SINGLE_DISCARDED_MASK.to_le_bytes());
    code.extend(SETNE_AL);
    code.extend(MOVZX_EAX_AL);
    code.extend(MOVD_XMM6_EAX);
    packed(code, Host::Or, RESULT_VECTOR, JAM_VECTOR);
}

fn vector_odd_jam(code: &mut Vec<u8>) {
    // Normal S widens exactly and compares with its original normal D lane
    // without raising host status, even after caller MXCSR has been restored.
    // Never use aggregate PE to choose a lane's jam bit. Result-range preparation
    // leaves MINIMUM_EXPONENT_VECTOR holding one in every dword.
    code.extend(CVTPS2PD_XMM6_XMM0);
    code.extend(CMPEQPD_XMM6_XMM1);
    super::shuffle(code, JAM_VECTOR, JAM_VECTOR, COMPACT_QWORD_LOW_DWORDS);
    packed(code, Host::AndNot, JAM_VECTOR, MINIMUM_EXPONENT_VECTOR);
    // PSHUFD duplicates masks into inactive upper lanes. Clear those masks so
    // CVTPD2PS's architecturally zero upper qword remains zero.
    clear_scalar(code, Format::Double, JAM_VECTOR);
    packed(code, Host::Or, RESULT_VECTOR, JAM_VECTOR);
}

fn emit_scalar(
    code: &mut Vec<u8>,
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
            code.extend(CVTSS2SD_XMM0_XMM1);
        } else {
            code.extend(MOVSS_XMM0_XMM1);
        }
    } else {
        exponent_range(code, source, SOURCE_VECTOR, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
        if destination == Format::Double {
            // Normal S→D is exact, unaffected by ambient RC/DAZ/FTZ/masks,
            // and raises neither Intel Invalid nor Denormal. Preserve MXCSR.
            code.extend(CVTSS2SD_XMM0_XMM1);
        } else {
            environment_round(
                code,
                if rounding == PrecisionRounding::ToOdd {
                    Rounding::Zero
                } else {
                    Rounding::Fpcr
                },
            );
            code.extend(CVTSD2SS_XMM0_XMM1);
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

fn half_vector_guard(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    packed(
        code,
        Host::EqualDword,
        HALF_MAXIMUM_VECTOR,
        HALF_MAXIMUM_VECTOR,
    );
    ShiftOpcode::RightDword.emit(code, HALF_MAXIMUM_VECTOR, HALF_EXPONENT_TO_DWORD_BOTTOM);
    packed(code, Host::Xor, HALF_MINIMUM_VECTOR, HALF_MINIMUM_VECTOR);
    packed(code, Host::MoveAligned, HALF_EXPONENT_VECTOR, SOURCE_VECTOR);
    ShiftOpcode::LeftDword.emit(code, HALF_EXPONENT_VECTOR, HALF_FIELD_TO_DWORD_TOP);
    ShiftOpcode::RightDword.emit(code, HALF_EXPONENT_VECTOR, HALF_EXPONENT_TO_DWORD_BOTTOM);
    packed(
        code,
        Host::MoveAligned,
        HALF_VALIDITY_VECTOR,
        HALF_MAXIMUM_VECTOR,
    );
    packed(
        code,
        Host::GreaterDword,
        HALF_VALIDITY_VECTOR,
        HALF_EXPONENT_VECTOR,
    );
    packed(
        code,
        Host::GreaterDword,
        HALF_EXPONENT_VECTOR,
        HALF_MINIMUM_VECTOR,
    );
    packed(code, Host::And, HALF_EXPONENT_VECTOR, HALF_VALIDITY_VECTOR);
    Host::DwordSignMask.register(code, 0, HALF_EXPONENT_VECTOR, crate::TargetCpu::Baseline);
    code.extend(CMP_EAX_IMM8);
    code.push(HALF_VALIDITY_MASK);
    helper.push(branch(code, Condition::NotZero));
}

fn emit_widen_half(code: &mut Vec<u8>, operand: &PrecisionOperand, upper: bool, pc: GuestAddress) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_vector(code, operand.source, SOURCE_VECTOR);
    if upper {
        code.extend(PSRLDQ_XMM1_8);
    }
    packed(code, Host::Xor, RESULT_VECTOR, RESULT_VECTOR);
    packed(code, Host::UnpackLowWord, SOURCE_VECTOR, RESULT_VECTOR);
    half_vector_guard(code, &mut helper);
    packed(code, Host::MoveAligned, RESULT_VECTOR, SOURCE_VECTOR);
    // Strip each half sign, align the remaining fields and adjust the bias.
    ShiftOpcode::LeftDword.emit(code, SOURCE_VECTOR, HALF_FIELD_TO_DWORD_TOP);
    ShiftOpcode::RightDword.emit(
        code,
        SOURCE_VECTOR,
        HALF_FIELD_TO_DWORD_TOP - HALF_TO_SINGLE_FRACTION_SHIFT,
    );
    // The guard retains exponent mask 31; 31 >> 2 gives 7, and 7 << 27 is
    // exactly the S-vs-H exponent bias adjustment. Reuse that constant.
    ShiftOpcode::RightDword.emit(code, HALF_MAXIMUM_VECTOR, HALF_MAXIMUM_TO_BIAS_BITS);
    ShiftOpcode::LeftDword.emit(code, HALF_MAXIMUM_VECTOR, SINGLE_BIAS_POSITION);
    packed(code, Host::AddDword, SOURCE_VECTOR, HALF_MAXIMUM_VECTOR);
    ShiftOpcode::LeftDword.emit(code, RESULT_VECTOR, HALF_TO_SINGLE_SIGN_SHIFT);
    ShiftOpcode::RightDword.emit(code, RESULT_VECTOR, DWORD_SIGN_TO_LSB_SHIFT);
    ShiftOpcode::LeftDword.emit(code, RESULT_VECTOR, DWORD_SIGN_TO_LSB_SHIFT);
    packed(code, Host::Or, RESULT_VECTOR, SOURCE_VECTOR);
    helper_section(code, &helper, pc);
    commit(code, operand.destination, RESULT_VECTOR);
}

fn emit_widen(code: &mut Vec<u8>, operand: &PrecisionOperand, upper: bool, pc: GuestAddress) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_vector(code, operand.source, SOURCE_VECTOR);
    if upper {
        code.extend(PSRLDQ_XMM1_8);
    }
    prepare_vector_input_range(code, Format::Single);
    vector_exponent_range(code, Format::Single, Shape::Vector64, SOURCE_VECTOR);
    helper.push(branch(code, Condition::NotZero));
    code.extend(CVTPS2PD_XMM0_XMM1);
    helper_section(code, &helper, pc);
    commit(code, operand.destination, RESULT_VECTOR);
}

fn emit_narrow(
    code: &mut Vec<u8>,
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
    code.extend(CVTPD2PS_XMM0_XMM1);
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
        code.extend(MOVLHPS_XMM1_XMM0);
        commit(code, operand.destination, SOURCE_VECTOR);
    } else {
        commit(code, operand.destination, RESULT_VECTOR);
    }
}

pub(in crate::x86_64) fn emit(code: &mut Vec<u8>, operand: &PrecisionOperand, pc: GuestAddress) {
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
