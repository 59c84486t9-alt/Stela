//! FP comparisons: exception-free native ordering and precise numerical fallback.
use super::super::isa::ShiftOpcode;
use super::numerical::{
    Condition, EXPONENT_VECTOR, INPUT_MINIMUM_EXPONENT, MINIMUM_EXPONENT_VECTOR, branch,
    clear_scalar, exponent_range, prepare_vector_input_range, read_numerical_vector, resolve,
    test_control, vector_exponent_range,
};
use super::{Host, commit, packed, read_vector};
use crate::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::{
        flags::{NZCV_C, NZCV_N, NZCV_SHIFT, NZCV_Z},
        floating::{FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format, comparison::Predicate},
        simd::{
            arithmetic::Shape,
            comparison::{CompareSource, Operand},
        },
    },
    block::ExitKind,
};
use alloc::vec::Vec;

const LEFT_VECTOR: u8 = 0;
const RIGHT_VECTOR: u8 = 1;
const ZERO_RESULT_VECTOR: u8 = 2;
const ZERO_VECTOR: u8 = 3;
const QWORD_EQUAL_VECTOR: u8 = 4;
const MERGE_VECTOR: u8 = 6;
const TEMP_VECTOR: u8 = 7;
const SIGN_BITS: u8 = 1;
const HALF_SIGN_SHIFT: u8 = u16::BITS as u8 - SIGN_BITS;
const SINGLE_SIGN_SHIFT: u8 = u32::BITS as u8 - SIGN_BITS;
const REGISTER_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const CMOV_EAX_EDX_MODRM: u8 = 0xc2;
const MOVD_EAX_XMM_PREFIX: &[u8] = &[0x66, 0x0f, 0x7e];
const SSE_ESCAPE: u8 = 0x0f;
const FLOAT_COMPARE_OPCODE: u8 = 0xc2;
const SCALAR_SINGLE_PREFIX: u8 = 0xf3;
const SCALAR_DOUBLE_PREFIX: u8 = 0xf2;
const PACKED_DOUBLE_PREFIX: u8 = 0x66;
const COMPARE_EQUAL: u8 = 0;
const COMPARE_LESS: u8 = 1;
const COMPARE_LESS_EQUAL: u8 = 2;
const HALF_LOW_MASK: u32 = 0xff;
const HALF_FULL_MASK: u32 = 0xffff;
const SINGLE_LOW_MASK: u32 = 0x03;
const SINGLE_FULL_MASK: u32 = 0x0f;
const DOUBLE_FULL_MASK: u32 = 0x05;
const ADJACENT_DWORDS: u8 = 0xb1;
const QWORD_HIGH_DWORDS: u8 = 0xf5;
const UCOMISS_XMM0_XMM1: &[u8] = &[0x0f, 0x2e, 0xc1];
const UCOMISD_XMM0_XMM1: &[u8] = &[0x66, 0x0f, 0x2e, 0xc1];
const CMP_AX_CX: &[u8] = &[0x66, 0x39, 0xc8];
const MOVD_EAX_XMM0: &[u8] = &[0x66, 0x0f, 0x7e, 0xc0];
const MOVD_ECX_XMM0: &[u8] = &[0x66, 0x0f, 0x7e, 0xc1];
const MOVD_ECX_XMM1: &[u8] = &[0x66, 0x0f, 0x7e, 0xc9];
const MOVQ_RAX_XMM0: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc0];
const MOVQ_RCX_XMM0: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc1];
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const MOV_EDX_IMMEDIATE: u8 = 0xba;
const STORE_STATE_EAX: &[u8] = &[0x89, 0x87];
const STORE_STATE_IMMEDIATE: &[u8] = &[0xc7, 0x87];
const SHL_EAX_IMMEDIATE: &[u8] = &[0xc1, 0xe0];
const SHL_RAX_IMMEDIATE: &[u8] = &[0x48, 0xc1, 0xe0];
const SHL_CX_1: &[u8] = &[0x66, 0xc1, 0xe1, 1];
const SHL_ECX_1: &[u8] = &[0xc1, 0xe1, 1];
const SHL_RCX_1: &[u8] = &[0x48, 0xc1, 0xe1, 1];
const TEST_CX_CX: &[u8] = &[0x66, 0x85, 0xc9];
const TEST_ECX_ECX: &[u8] = &[0x85, 0xc9];
const TEST_RCX_RCX: &[u8] = &[0x48, 0x85, 0xc9];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const CMP_EAX_IMMEDIATE: u8 = 0x3d;
const JMP_RELATIVE: u8 = 0xe9;
const MOVSS_XMM6_XMM0: &[u8] = &[0xf3, 0x0f, 0x10, 0xf0];
const MOVSD_XMM6_XMM0: &[u8] = &[0xf2, 0x0f, 0x10, 0xf0];
const PINSRW_XMM6_EAX_0: &[u8] = &[0x66, 0x0f, 0xc4, 0xf0, 0];

#[repr(u8)]
enum FlagSelect {
    Equal = 0x44,
    Below = 0x42,
    Less = 0x4c,
    Sign = 0x48,
}

fn jump(code: &mut Vec<u8>) -> usize {
    code.push(JMP_RELATIVE);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}

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

fn exception_guard(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
}

fn scalar_normal_guard(code: &mut Vec<u8>, format: Format, source: u8, helper: &mut Vec<usize>) {
    exponent_range(code, format, source, INPUT_MINIMUM_EXPONENT);
    helper.push(branch(code, Condition::AboveOrEqual));
}

/// A zero comparison also accepts signed zero and infinity. A zero fraction
/// proves one of those classes or an exact normal power of two; remaining
/// values must pass the ordinary normal guard. No subnormal or NaN executes.
fn scalar_zero_guard(code: &mut Vec<u8>, format: Format, helper: &mut Vec<usize>) {
    code.extend(if format == Format::Double {
        MOVQ_RAX_XMM0
    } else {
        MOVD_EAX_XMM0
    });
    let register_bits = if format == Format::Double {
        code.extend(SHL_RAX_IMMEDIATE);
        u64::BITS
    } else {
        code.extend(SHL_EAX_IMMEDIATE);
        u32::BITS
    };
    code.push((register_bits - format.fraction_bits()) as u8);
    let zero_fraction = branch(code, Condition::Zero);
    scalar_normal_guard(code, format, LEFT_VECTOR, helper);
    let accepted = code.len();
    resolve(code, zero_fraction, accepted);
}

fn active_mask(format: Format, shape: Shape) -> u32 {
    match (format, shape) {
        (Format::Half, Shape::Vector64) => HALF_LOW_MASK,
        (Format::Half, Shape::Vector128) => HALF_FULL_MASK,
        (Format::Single, Shape::Vector64) => SINGLE_LOW_MASK,
        (Format::Single, Shape::Vector128) => SINGLE_FULL_MASK,
        (Format::Double, Shape::Vector128) => DOUBLE_FULL_MASK,
        _ => unreachable!("decoded vector comparison arrangement"),
    }
}

fn shift_left(format: Format) -> ShiftOpcode {
    match format {
        Format::Half => ShiftOpcode::LeftWord,
        Format::Single => ShiftOpcode::LeftDword,
        Format::Double => ShiftOpcode::LeftQword,
    }
}

fn shift_right(format: Format) -> ShiftOpcode {
    match format {
        Format::Half => ShiftOpcode::RightWord,
        Format::Single => ShiftOpcode::RightDword,
        Format::Double => ShiftOpcode::RightQword,
    }
}

fn equal_zero(code: &mut Vec<u8>, format: Format, value: u8, zero: u8, temporary: u8) {
    packed(
        code,
        if format == Format::Half {
            Host::EqualWord
        } else {
            Host::EqualDword
        },
        value,
        zero,
    );
    if format == Format::Double {
        super::shuffle(code, temporary, value, ADJACENT_DWORDS);
        packed(code, Host::And, value, temporary);
    }
}

fn vector_zero_guard(code: &mut Vec<u8>, format: Format, shape: Shape, helper: &mut Vec<usize>) {
    // The shared range leaves per-lane normal validity in EXPONENT_VECTOR.
    // OR fraction-zero validity into it: only zeros/infinities are newly
    // admitted, and none can change host MXCSR or guest FPSR.
    prepare_vector_input_range(code, format);
    vector_exponent_range(code, format, shape, LEFT_VECTOR);
    packed(code, Host::MoveAligned, TEMP_VECTOR, LEFT_VECTOR);
    shift_left(format).emit(
        code,
        TEMP_VECTOR,
        (format.bits() - format.fraction_bits()) as u8,
    );
    equal_zero(
        code,
        format,
        TEMP_VECTOR,
        MINIMUM_EXPONENT_VECTOR,
        MERGE_VECTOR,
    );
    packed(code, Host::Or, EXPONENT_VECTOR, TEMP_VECTOR);
    if format == Format::Half {
        Host::ByteSignMask.register(code, 0, EXPONENT_VECTOR, TargetCpu::Baseline);
    } else {
        Host::DwordSignMask.register(code, 0, EXPONENT_VECTOR, TargetCpu::Baseline);
    }
    let mask = active_mask(format, shape);
    code.push(AND_EAX_IMMEDIATE);
    code.extend(mask.to_le_bytes());
    code.push(CMP_EAX_IMMEDIATE);
    code.extend(mask.to_le_bytes());
    helper.push(branch(code, Condition::NotZero));
}

/// Signed order key for nonzero normal half values. Sign-complementing the
/// fraction/exponent reverses negative magnitudes without a host FP operation.
fn half_order_key(code: &mut Vec<u8>, vector: u8) {
    packed(code, Host::MoveAligned, TEMP_VECTOR, vector);
    ShiftOpcode::ArithmeticWord.emit(code, TEMP_VECTOR, HALF_SIGN_SHIFT);
    ShiftOpcode::RightWord.emit(code, TEMP_VECTOR, SIGN_BITS);
    packed(code, Host::Xor, vector, TEMP_VECTOR);
}

fn select_flags(code: &mut Vec<u8>, condition: FlagSelect) {
    code.extend([SSE_ESCAPE, condition as u8, CMOV_EAX_EDX_MODRM]);
}

fn store_flags(code: &mut Vec<u8>) {
    code.extend(STORE_STATE_EAX);
    code.extend((core::mem::offset_of!(GuestState, nzcv) as u32).to_le_bytes());
}

fn ordered_flags(code: &mut Vec<u8>, integer: bool) {
    code.push(MOV_EAX_IMMEDIATE);
    code.extend(NZCV_C.to_le_bytes());
    code.push(MOV_EDX_IMMEDIATE);
    code.extend(NZCV_N.to_le_bytes());
    select_flags(
        code,
        if integer {
            FlagSelect::Less
        } else {
            FlagSelect::Below
        },
    );
    code.push(MOV_EDX_IMMEDIATE);
    code.extend((NZCV_Z | NZCV_C).to_le_bytes());
    select_flags(code, FlagSelect::Equal);
    store_flags(code);
}

fn zero_flags(code: &mut Vec<u8>, format: Format) {
    code.extend(if format == Format::Double {
        MOVQ_RCX_XMM0
    } else {
        MOVD_ECX_XMM0
    });
    code.extend(match format {
        Format::Half => TEST_CX_CX,
        Format::Single => TEST_ECX_ECX,
        Format::Double => TEST_RCX_RCX,
    });
    code.push(MOV_EAX_IMMEDIATE);
    code.extend(NZCV_C.to_le_bytes());
    code.push(MOV_EDX_IMMEDIATE);
    code.extend(NZCV_N.to_le_bytes());
    select_flags(code, FlagSelect::Sign);
    // Shift off the sign at the actual lane width. Both +0 and -0 set ZF.
    code.extend(match format {
        Format::Half => SHL_CX_1,
        Format::Single => SHL_ECX_1,
        Format::Double => SHL_RCX_1,
    });
    code.push(MOV_EDX_IMMEDIATE);
    code.extend((NZCV_Z | NZCV_C).to_le_bytes());
    select_flags(code, FlagSelect::Equal);
    store_flags(code);
}

fn emit_flags(
    code: &mut Vec<u8>,
    format: Format,
    left: u8,
    right: CompareSource,
    pc: GuestAddress,
) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_vector(code, left, LEFT_VECTOR);
    if let CompareSource::Register(right) = right {
        read_vector(code, right, RIGHT_VECTOR);
        for source in [LEFT_VECTOR, RIGHT_VECTOR] {
            scalar_normal_guard(code, format, source, &mut helper);
        }
        if format == Format::Half {
            half_order_key(code, LEFT_VECTOR);
            half_order_key(code, RIGHT_VECTOR);
            code.extend(MOVD_EAX_XMM0);
            code.extend(MOVD_ECX_XMM1);
            code.extend(CMP_AX_CX);
        } else {
            code.extend(if format == Format::Double {
                UCOMISD_XMM0_XMM1
            } else {
                UCOMISS_XMM0_XMM1
            });
        }
        // JMP and the unexecuted helper preserve the comparison flags.
        helper_section(code, &helper, pc);
        ordered_flags(code, format == Format::Half);
    } else {
        scalar_zero_guard(code, format, &mut helper);
        helper_section(code, &helper, pc);
        zero_flags(code, format);
    }
}

fn emit_conditional_flags(
    code: &mut Vec<u8>,
    format: Format,
    left: u8,
    right: u8,
    condition: u8,
    fallback: u8,
    pc: GuestAddress,
) {
    // A false condition bypasses numerical enables and every operand effect.
    let failed = super::super::condition(code, condition).map(|condition| {
        code.extend([SSE_ESCAPE, condition ^ 1]);
        let patch = code.len();
        code.extend(0i32.to_le_bytes());
        patch
    });
    emit_flags(code, format, left, CompareSource::Register(right), pc);
    if let Some(failed) = failed {
        let completed = jump(code);
        let fallback_start = code.len();
        resolve(code, failed, fallback_start);
        code.extend(STORE_STATE_IMMEDIATE);
        code.extend((core::mem::offset_of!(GuestState, nzcv) as u32).to_le_bytes());
        code.extend((u32::from(fallback) << NZCV_SHIFT).to_le_bytes());
        let completed_target = code.len();
        resolve(code, completed, completed_target);
    }
}

fn absolute(operation: Predicate) -> bool {
    matches!(
        operation,
        Predicate::AbsoluteGreaterEqual | Predicate::AbsoluteGreater
    )
}

fn magnitude(code: &mut Vec<u8>, format: Format) {
    packed(code, Host::EqualDword, TEMP_VECTOR, TEMP_VECTOR);
    shift_right(format).emit(code, TEMP_VECTOR, SIGN_BITS);
    packed(code, Host::And, LEFT_VECTOR, TEMP_VECTOR);
    packed(code, Host::And, RIGHT_VECTOR, TEMP_VECTOR);
}

fn invert_mask(code: &mut Vec<u8>, vector: u8) {
    packed(code, Host::EqualDword, TEMP_VECTOR, TEMP_VECTOR);
    packed(code, Host::Xor, vector, TEMP_VECTOR);
}

fn half_predicate(code: &mut Vec<u8>, operation: Predicate) -> u8 {
    if operation == Predicate::Equal {
        packed(code, Host::EqualWord, LEFT_VECTOR, RIGHT_VECTOR);
        return LEFT_VECTOR;
    }
    if absolute(operation) {
        magnitude(code, Format::Half);
    } else {
        half_order_key(code, LEFT_VECTOR);
        half_order_key(code, RIGHT_VECTOR);
    }
    // Original right is in XMM0 and original left is in XMM1.
    match operation {
        Predicate::Greater | Predicate::AbsoluteGreater => {
            packed(code, Host::GreaterWord, RIGHT_VECTOR, LEFT_VECTOR);
            RIGHT_VECTOR
        }
        Predicate::GreaterEqual | Predicate::AbsoluteGreaterEqual => {
            packed(code, Host::GreaterWord, LEFT_VECTOR, RIGHT_VECTOR);
            invert_mask(code, LEFT_VECTOR);
            LEFT_VECTOR
        }
        Predicate::Less => {
            packed(code, Host::GreaterWord, LEFT_VECTOR, RIGHT_VECTOR);
            LEFT_VECTOR
        }
        Predicate::LessEqual => {
            packed(code, Host::GreaterWord, RIGHT_VECTOR, LEFT_VECTOR);
            invert_mask(code, RIGHT_VECTOR);
            RIGHT_VECTOR
        }
        Predicate::Equal => unreachable!("equality needs no half order transform"),
    }
}

fn floating_predicate(
    code: &mut Vec<u8>,
    operation: Predicate,
    format: Format,
    shape: Shape,
) -> u8 {
    if absolute(operation) {
        magnitude(code, format);
    }
    let (destination, source, predicate) = match operation {
        Predicate::Equal => (LEFT_VECTOR, RIGHT_VECTOR, COMPARE_EQUAL),
        Predicate::Greater | Predicate::AbsoluteGreater => {
            (LEFT_VECTOR, RIGHT_VECTOR, COMPARE_LESS)
        }
        Predicate::GreaterEqual | Predicate::AbsoluteGreaterEqual => {
            (LEFT_VECTOR, RIGHT_VECTOR, COMPARE_LESS_EQUAL)
        }
        Predicate::Less => (RIGHT_VECTOR, LEFT_VECTOR, COMPARE_LESS),
        Predicate::LessEqual => (RIGHT_VECTOR, LEFT_VECTOR, COMPARE_LESS_EQUAL),
    };
    if shape == Shape::Scalar {
        code.push(if format == Format::Double {
            SCALAR_DOUBLE_PREFIX
        } else {
            SCALAR_SINGLE_PREFIX
        });
    } else if format == Format::Double {
        code.push(PACKED_DOUBLE_PREFIX);
    }
    code.extend([
        SSE_ESCAPE,
        FLOAT_COMPARE_OPCODE,
        REGISTER_DIRECT | (destination << MODRM_REGISTER_SHIFT) | source,
        predicate,
    ]);
    destination
}

/// Zero predicates use signed magnitude tests instead of numerical host FP.
/// This also gives exact equality for both signs of zero at every lane width.
fn zero_predicate(code: &mut Vec<u8>, operation: Predicate, format: Format) -> u8 {
    packed(code, Host::MoveAligned, ZERO_RESULT_VECTOR, LEFT_VECTOR);
    shift_left(format).emit(code, ZERO_RESULT_VECTOR, SIGN_BITS);
    shift_right(format).emit(code, ZERO_RESULT_VECTOR, SIGN_BITS);
    packed(code, Host::Xor, ZERO_VECTOR, ZERO_VECTOR);
    equal_zero(
        code,
        format,
        ZERO_RESULT_VECTOR,
        ZERO_VECTOR,
        QWORD_EQUAL_VECTOR,
    );
    if operation == Predicate::Equal {
        return ZERO_RESULT_VECTOR;
    }
    match format {
        Format::Half => ShiftOpcode::ArithmeticWord.emit(code, LEFT_VECTOR, HALF_SIGN_SHIFT),
        Format::Single => ShiftOpcode::ArithmeticDword.emit(code, LEFT_VECTOR, SINGLE_SIGN_SHIFT),
        Format::Double => {
            super::shuffle(code, LEFT_VECTOR, LEFT_VECTOR, QWORD_HIGH_DWORDS);
            ShiftOpcode::ArithmeticDword.emit(code, LEFT_VECTOR, SINGLE_SIGN_SHIFT);
        }
    }
    match operation {
        Predicate::Less => {
            packed(code, Host::AndNot, ZERO_RESULT_VECTOR, LEFT_VECTOR);
            ZERO_RESULT_VECTOR
        }
        Predicate::LessEqual => {
            packed(code, Host::Or, LEFT_VECTOR, ZERO_RESULT_VECTOR);
            LEFT_VECTOR
        }
        Predicate::Greater | Predicate::GreaterEqual => {
            packed(code, Host::EqualDword, ZERO_VECTOR, ZERO_VECTOR);
            packed(code, Host::Xor, LEFT_VECTOR, ZERO_VECTOR);
            if operation == Predicate::Greater {
                packed(code, Host::AndNot, ZERO_RESULT_VECTOR, LEFT_VECTOR);
                ZERO_RESULT_VECTOR
            } else {
                packed(code, Host::Or, LEFT_VECTOR, ZERO_RESULT_VECTOR);
                LEFT_VECTOR
            }
        }
        _ => unreachable!("decoded ordinary comparison with zero"),
    }
}

fn merge_scalar(code: &mut Vec<u8>, format: Format, result: u8) -> u8 {
    if result != LEFT_VECTOR && format != Format::Half {
        packed(code, Host::MoveAligned, LEFT_VECTOR, result);
    }
    match format {
        Format::Half => {
            code.extend(MOVD_EAX_XMM_PREFIX);
            code.push(REGISTER_DIRECT | (result << MODRM_REGISTER_SHIFT));
            code.extend(PINSRW_XMM6_EAX_0);
        }
        Format::Single => code.extend(MOVSS_XMM6_XMM0),
        Format::Double => code.extend(MOVSD_XMM6_XMM0),
    }
    MERGE_VECTOR
}

fn commit_predicate(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    destination: u8,
    result: u8,
    merge: bool,
    zero: bool,
) {
    if shape == Shape::Scalar {
        let result = if merge {
            merge_scalar(code, format, result)
        } else {
            result
        };
        if zero {
            clear_scalar(code, format, result);
        } else {
            test_control(code, FPCR_NEP);
            let merging = branch(code, Condition::NotZero);
            clear_scalar(code, format, result);
            let merge_target = code.len();
            resolve(code, merging, merge_target);
        }
        commit(code, destination, result);
    } else {
        if shape == Shape::Vector64 {
            clear_scalar(code, Format::Double, result);
        }
        commit(code, destination, result);
    }
}

fn emit_predicate(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    let Operand::Predicate {
        operation,
        format,
        shape,
        destination,
        left,
        right,
    } = *operand
    else {
        unreachable!("predicate comparison dispatch");
    };
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    let zero = right == CompareSource::Zero;
    let merge = shape == Shape::Scalar
        && !zero
        && (format == Format::Half
            || absolute(operation)
            || matches!(operation, Predicate::Less | Predicate::LessEqual));
    if let CompareSource::Register(right) = right {
        // Reversed operands make ordered LT/LE implement original GT/GE while
        // preserving original Vm upper bits for the ordinary scalar case.
        read_numerical_vector(code, shape, right, LEFT_VECTOR);
        read_numerical_vector(code, shape, left, RIGHT_VECTOR);
        if merge {
            packed(code, Host::MoveAligned, MERGE_VECTOR, LEFT_VECTOR);
        }
        if shape == Shape::Scalar {
            for source in [LEFT_VECTOR, RIGHT_VECTOR] {
                scalar_normal_guard(code, format, source, &mut helper);
            }
        } else {
            prepare_vector_input_range(code, format);
            for source in [LEFT_VECTOR, RIGHT_VECTOR] {
                vector_exponent_range(code, format, shape, source);
                helper.push(branch(code, Condition::NotZero));
            }
        }
    } else {
        read_numerical_vector(code, shape, left, LEFT_VECTOR);
        if shape == Shape::Scalar {
            scalar_zero_guard(code, format, &mut helper);
        } else {
            vector_zero_guard(code, format, shape, &mut helper);
        }
    }
    let result = if zero {
        zero_predicate(code, operation, format)
    } else if format == Format::Half {
        half_predicate(code, operation)
    } else {
        floating_predicate(code, operation, format, shape)
    };
    helper_section(code, &helper, pc);
    commit_predicate(code, format, shape, destination, result, merge, zero);
}

pub(in crate::x86_64) fn emit(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    match *operand {
        Operand::Flags {
            format,
            left,
            right,
            ..
        } => emit_flags(code, format, left, right, pc),
        Operand::ConditionalFlags {
            format,
            left,
            right,
            condition,
            fallback,
            ..
        } => emit_conditional_flags(code, format, left, right, condition, fallback, pc),
        Operand::Predicate { .. } => emit_predicate(code, operand, pc),
    }
}
