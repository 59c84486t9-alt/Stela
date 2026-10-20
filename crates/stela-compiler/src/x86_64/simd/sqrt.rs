//! FSQRT: SSE2 for positive normals, software fallback otherwise.
use super::super::isa::ShiftOpcode;
use super::numerical::{
    Condition, INPUT_MINIMUM_EXPONENT, Rounding, VZEROUPPER, branch, clear_scalar, commit_inexact,
    environment_round, positive_exponent_range, prepare_vector_input_range, read_numerical_scalar,
    read_numerical_vector, reject_other_status, resolve, restore_environment, sticky_inexact,
    sticky_result_check, test_control, vector_positive_exponent_range,
};
use super::{Host, commit, packed, read_vector};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, FPCR_ROUNDING_SHIFT, Format},
        simd::{arithmetic::Shape, sqrt::Operand},
    },
    block::ExitKind,
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const TEMP: u8 = 2;
const ZERO: u8 = 3;
const HALF_BIAS: u8 = 4;
const ROUNDING_BIAS: u8 = 5;
const SAVED_HALF: u8 = 6;
const ROUNDING_PARITY: u8 = 7;
const FIRST_LANE: u8 = 0;
const REGISTER_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const JMP_REL32: u8 = 0xe9;
const MOVD_EAX_XMM_PREFIX: &[u8] = &[0x66, 0x0f, 0x7e];
const MOVD_XMM_EAX_PREFIX: &[u8] = &[0x66, 0x0f, 0x6e];
const PINSRW_XMM_EAX_PREFIX: &[u8] = &[0x66, 0x0f, 0xc4];
const MOVZX_EAX_AX: &[u8] = &[0x0f, 0xb7, 0xc0];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const BT_EAX_IMM8: &[u8] = &[0x0f, 0xba, 0xe0];
const ADD_EAX_IMM32: u8 = 0x05;
const ADC_EAX_IMM32: u8 = 0x15;
const SUB_EAX_IMM32: u8 = 0x2d;
const CONVERT_USING_MXCSR: u8 = 1 << 2;
const FPCR_LOW_ROUNDING_BIT: u32 = 1 << FPCR_ROUNDING_SHIFT;
const FPCR_HIGH_ROUNDING_BIT: u32 = 1 << (FPCR_ROUNDING_SHIFT + 1);
const HALF_FRACTION_SHIFT: u8 =
    (Format::Single.fraction_bits() - Format::Half.fraction_bits()) as u8;
const HALF_DISCARDED_MASK: u32 = (1 << HALF_FRACTION_SHIFT) - 1;
const HALF_TO_SINGLE_BIAS: u32 = (Format::Single.exponent_bias() - Format::Half.exponent_bias())
    << Format::Single.fraction_bits();
const HALF_BIAS_POSITION: u8 = HALF_TO_SINGLE_BIAS.trailing_zeros() as u8;
const HALF_BIAS_DIGITS: u8 = (HALF_TO_SINGLE_BIAS >> HALF_BIAS_POSITION).ilog2() as u8 + 1;
const UPPER_HALF_BYTES: u8 = (u64::BITS / u8::BITS) as u8;

fn jump(code: &mut Vec<u8>) -> usize {
    code.push(JMP_REL32);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}

fn source_guard(code: &mut Vec<u8>, operand: &Operand, helper: &mut Vec<usize>) {
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_numerical_vector(code, operand.shape, operand.source, SOURCE);
    if operand.shape == Shape::Scalar {
        positive_exponent_range(code, operand.format, SOURCE, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
    } else {
        prepare_vector_input_range(code, operand.format);
        vector_positive_exponent_range(code, operand.format, operand.shape, SOURCE);
        helper.push(branch(code, Condition::NotZero));
    }
}

/// Every branch enters with the caller's complete MXCSR and stack restored.
/// Guest status and destination commits follow this common cold helper section.
fn helper_section(code: &mut Vec<u8>, helper: &[usize], pc: GuestAddress) {
    let completed = jump(code);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success_start = code.len();
    for &patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, completed, success_start);
}

fn square_root(code: &mut Vec<u8>, format: Format, shape: Shape, source: u8) {
    let opcode = match (format, shape) {
        (Format::Single, Shape::Scalar) => Host::SquareRootScalarSingle,
        (Format::Double, Shape::Scalar) => Host::SquareRootScalarDouble,
        (Format::Single, _) => Host::SquareRootPackedSingle,
        (Format::Double, _) => Host::SquareRootPackedDouble,
        (Format::Half, _) => unreachable!("half roots use exact Single widening"),
    };
    packed(code, opcode, RESULT, source);
}

/// Select positive-result narrowing bias once for both four-lane H groups.
/// Nearest-even adds half-minus-one plus retained parity. Positive rounding
/// adds the entire discarded mask; negative/zero rounding simply truncates.
fn half_constants(code: &mut Vec<u8>) {
    packed(code, Host::Xor, ZERO, ZERO);
    packed(code, Host::EqualDword, HALF_BIAS, HALF_BIAS);
    ShiftOpcode::RightDword.emit(code, HALF_BIAS, u32::BITS as u8 - HALF_BIAS_DIGITS);
    ShiftOpcode::LeftDword.emit(code, HALF_BIAS, HALF_BIAS_POSITION);
    packed(code, Host::Xor, ROUNDING_BIAS, ROUNDING_BIAS);
    packed(code, Host::Xor, ROUNDING_PARITY, ROUNDING_PARITY);
    test_control(code, FPCR_HIGH_ROUNDING_BIT);
    let truncating = branch(code, Condition::NotZero);
    packed(code, Host::EqualDword, ROUNDING_BIAS, ROUNDING_BIAS);
    ShiftOpcode::RightDword.emit(code, ROUNDING_BIAS, u32::BITS as u8 - HALF_FRACTION_SHIFT);
    test_control(code, FPCR_LOW_ROUNDING_BIT);
    let positive = branch(code, Condition::NotZero);
    ShiftOpcode::RightDword.emit(code, ROUNDING_BIAS, 1);
    packed(code, Host::EqualDword, ROUNDING_PARITY, ROUNDING_PARITY);
    ShiftOpcode::RightDword.emit(code, ROUNDING_PARITY, u32::BITS as u8 - 1);
    let selected = code.len();
    for patch in [truncating, positive] {
        resolve(code, patch, selected);
    }
}

/// All active inputs were positive normal H. Integer field construction is exact.
fn widen_half(code: &mut Vec<u8>, upper: bool) {
    packed(code, Host::MoveAligned, RESULT, SOURCE);
    if upper {
        ShiftOpcode::RightBytes.emit(code, RESULT, UPPER_HALF_BYTES);
    }
    packed(code, Host::UnpackLowWord, RESULT, ZERO);
    ShiftOpcode::LeftDword.emit(code, RESULT, HALF_FRACTION_SHIFT);
    packed(code, Host::AddDword, RESULT, HALF_BIAS);
}

/// Rounding single-precision sqrt and then rounding to half gives the same
/// result as direct half-precision sqrt, with single PE exactly matching half
/// inexact. Results are positive normal halves of at most 256, so signed dword
/// packing is exact.
fn half_fields(code: &mut Vec<u8>) {
    packed(code, Host::SubDword, RESULT, HALF_BIAS);
    packed(code, Host::MoveAligned, TEMP, RESULT);
    ShiftOpcode::RightDword.emit(code, TEMP, HALF_FRACTION_SHIFT);
    packed(code, Host::And, TEMP, ROUNDING_PARITY);
    packed(code, Host::AddDword, TEMP, ROUNDING_BIAS);
    packed(code, Host::AddDword, RESULT, TEMP);
    ShiftOpcode::RightDword.emit(code, RESULT, HALF_FRACTION_SHIFT);
}

/// The scalar integer recipe avoids vector constant preparation and packing.
/// BT captures retained parity before ADC adds half-minus-one plus that bit.
fn scalar_half_root(code: &mut Vec<u8>) {
    code.extend(MOVD_EAX_XMM_PREFIX);
    code.push(REGISTER_DIRECT | (SOURCE << MODRM_REGISTER_SHIFT));
    code.extend(MOVZX_EAX_AX);
    code.extend(SHL_EAX_IMM8);
    code.push(HALF_FRACTION_SHIFT);
    code.push(ADD_EAX_IMM32);
    code.extend(HALF_TO_SINGLE_BIAS.to_le_bytes());
    code.extend(MOVD_XMM_EAX_PREFIX);
    code.push(REGISTER_DIRECT | (RESULT << MODRM_REGISTER_SHIFT));
    square_root(code, Format::Single, Shape::Scalar, RESULT);
    code.extend(MOVD_EAX_XMM_PREFIX);
    code.push(REGISTER_DIRECT | (RESULT << MODRM_REGISTER_SHIFT));
    code.push(SUB_EAX_IMM32);
    code.extend(HALF_TO_SINGLE_BIAS.to_le_bytes());
    test_control(code, FPCR_HIGH_ROUNDING_BIT);
    let truncating = branch(code, Condition::NotZero);
    test_control(code, FPCR_LOW_ROUNDING_BIT);
    let positive = branch(code, Condition::NotZero);
    code.extend(BT_EAX_IMM8);
    code.push(HALF_FRACTION_SHIFT);
    code.push(ADC_EAX_IMM32);
    code.extend((HALF_DISCARDED_MASK >> 1).to_le_bytes());
    let nearest_done = jump(code);
    let positive_start = code.len();
    resolve(code, positive, positive_start);
    code.push(ADD_EAX_IMM32);
    code.extend(HALF_DISCARDED_MASK.to_le_bytes());
    let shift_start = code.len();
    for patch in [truncating, nearest_done] {
        resolve(code, patch, shift_start);
    }
    code.extend(SHR_EAX_IMM8);
    code.push(HALF_FRACTION_SHIFT);
    code.extend(MOVD_XMM_EAX_PREFIX);
    code.push(REGISTER_DIRECT | (RESULT << MODRM_REGISTER_SHIFT));
}

fn vector_half_root(code: &mut Vec<u8>, shape: Shape) {
    half_constants(code);
    widen_half(code, false);
    square_root(code, Format::Single, shape, RESULT);
    half_fields(code);
    if shape == Shape::Vector128 {
        packed(code, Host::MoveAligned, SAVED_HALF, RESULT);
        widen_half(code, true);
        square_root(code, Format::Single, Shape::Vector128, RESULT);
        half_fields(code);
        packed(code, Host::PackSignedDwordToWord, SAVED_HALF, RESULT);
        packed(code, Host::MoveAligned, RESULT, SAVED_HALF);
    } else {
        packed(code, Host::PackSignedDwordToWord, RESULT, RESULT);
    }
}

fn narrow_half(code: &mut Vec<u8>, destination: u8, source: u8, target: TargetCpu) {
    // VCVTPS2PH encodes source in ModRM.reg and destination in ModRM.r/m,
    // reversing the register field roles of ordinary two-operand SIMD ops.
    Host::ConvertSingleToHalf.register(code, source, destination, target);
    code.push(CONVERT_USING_MXCSR);
}

fn checked_half_root(code: &mut Vec<u8>, shape: Shape, target: TargetCpu) {
    if shape == Shape::Scalar {
        clear_scalar(code, Format::Half, SOURCE);
    }
    Host::ConvertHalfToSingle.register(code, RESULT, SOURCE, target);
    // Exact hardware widening makes inactive scalar lanes +0, so packed SQRT
    // is safe here. Integer widening's manufactured inactive fields differ.
    square_root(code, Format::Single, Shape::Vector128, RESULT);
    if shape == Shape::Vector128 {
        narrow_half(code, SAVED_HALF, RESULT, target);
        ShiftOpcode::RightBytes.emit(code, SOURCE, UPPER_HALF_BYTES);
        Host::ConvertHalfToSingle.register(code, RESULT, SOURCE, target);
        square_root(code, Format::Single, Shape::Vector128, RESULT);
        narrow_half(code, RESULT, RESULT, target);
        packed(code, Host::UnpackLowQword, SAVED_HALF, RESULT);
        packed(code, Host::MoveAligned, RESULT, SAVED_HALF);
    } else {
        narrow_half(code, RESULT, RESULT, target);
    }
}

fn commit_result(code: &mut Vec<u8>, operand: &Operand) {
    if operand.shape == Shape::Scalar {
        if operand.format == Format::Half {
            // Rebuild the half-precision scalar result in Vd after the
            // arithmetic and packing, which handles source aliases and V31.
            code.extend(MOVD_EAX_XMM_PREFIX);
            code.push(REGISTER_DIRECT | (RESULT << MODRM_REGISTER_SHIFT));
            read_vector(code, operand.destination, RESULT);
            code.extend(PINSRW_XMM_EAX_PREFIX);
            code.push(REGISTER_DIRECT | (RESULT << MODRM_REGISTER_SHIFT));
            code.push(FIRST_LANE);
        }
        test_control(code, FPCR_NEP);
        let merging = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, RESULT);
        let committed = code.len();
        resolve(code, merging, committed);
    } else if operand.shape == Shape::Vector64 {
        clear_scalar(code, Format::Double, RESULT);
    }
    commit(code, operand.destination, RESULT);
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    let checked_half = operand.format == Format::Half && target.supports(TargetCpu::F16c);
    if checked_half {
        // F16C requires usable AVX. Pay this prefix per body before legacy
        // guards, avoiding a transition from arbitrary caller upper YMM state.
        code.extend(VZEROUPPER);
    }
    let mut helper = Vec::new();
    // The sticky-inexact path (`numerical::sticky_inexact`) for S and D: the
    // root of a negative input is NaN and of +infinity infinite, which take
    // the helper; every other root is exact IEEE on both sides.
    let mut sticky_done = None;
    if operand.format != Format::Half {
        let full = sticky_inexact(code);
        // NEP is zero on this path: scalar upper bits clear, as the root
        // of a zeroing load into RESULT leaves them.
        let source = if operand.shape == Shape::Scalar {
            read_numerical_scalar(code, operand.format, operand.source, RESULT);
            RESULT
        } else {
            read_numerical_vector(code, operand.shape, operand.source, SOURCE);
            SOURCE
        };
        square_root(code, operand.format, operand.shape, source);
        helper.push(sticky_result_check(
            code,
            operand.format,
            operand.shape,
            RESULT,
            true,
        ));
        if operand.shape == Shape::Vector64 {
            clear_scalar(code, Format::Double, RESULT);
        }
        commit(code, operand.destination, RESULT);
        sticky_done = Some(jump(code));
        let full_start = code.len();
        for patch in full {
            resolve(code, patch, full_start);
        }
    }
    source_guard(code, operand, &mut helper);
    if operand.shape == Shape::Scalar && operand.format != Format::Half {
        // Legacy scalar SQRT preserves destination upper bits for NEP.
        read_vector(code, operand.destination, RESULT);
    }
    environment_round(code, Rounding::Fpcr);
    if operand.format == Format::Half {
        if checked_half {
            checked_half_root(code, operand.shape, target);
        } else if operand.shape == Shape::Scalar {
            scalar_half_root(code);
        } else {
            vector_half_root(code, operand.shape);
        }
    } else {
        square_root(code, operand.format, operand.shape, SOURCE);
    }
    restore_environment(code);
    helper.push(reject_other_status(code));
    helper_section(code, &helper, pc);
    commit_inexact(code);
    commit_result(code, operand);
    if let Some(done) = sticky_done {
        let end = code.len();
        resolve(code, done, end);
    }
}
