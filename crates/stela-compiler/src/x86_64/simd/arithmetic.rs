//! Scalar and vector numerical blocks: normal SSE2 path, precise integer-core helper exit.
use super::super::isa::ShiftOpcode;
use super::{Host, commit, packed, read_vector, vector_offset};
use crate::{
    GuestAddress, GuestState,
    aarch64::{
        floating::{BinaryOperation, FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format},
        simd::arithmetic::{Operand, Shape},
    },
    block::ExitKind,
};

const MXCSR_EXCEPTION_MASKS: u32 = 0x3f << 7;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_POSITIVE_ROUNDING: u32 = 1 << 14;
const MXCSR_NEGATIVE_ROUNDING: u32 = 1 << 13;
const FPCR_POSITIVE_TO_MXCSR_SHIFT: u8 = 8;
const FPCR_NEGATIVE_TO_MXCSR_SHIFT: u8 = 10;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;
const INPUT_MINIMUM_EXPONENT: u8 = 1;
const RESULT_MINIMUM_EXPONENT: u8 = 2;
const SCALAR_SINGLE_PREFIX: u8 = 0xf3;
const SCALAR_DOUBLE_PREFIX: u8 = 0xf2;
const PACKED_DOUBLE_PREFIX: u8 = 0x66;
const SSE_ESCAPE: u8 = 0x0f;
const LEFT_VECTOR: u8 = 0;
const RIGHT_VECTOR: u8 = 1;
const EXPONENT_VECTOR: u8 = 2;
const VALIDITY_VECTOR: u8 = 3;
const MAXIMUM_EXPONENT_VECTOR: u8 = 4;
const MINIMUM_EXPONENT_VECTOR: u8 = 5;
const SINGLE_VECTOR_MASK: u8 = 0x0f;
const SINGLE_LOW_VECTOR_MASK: u8 = 0x03;
const DOUBLE_VECTOR_MASK: u8 = 0x05;
const SIGN_BITS: u8 = 1;
const SINGLE_EXPONENT_BIAS_BITS: u8 = 7;
const MOVLHPS_XMM1_XMM2: &[u8] = &[0x0f, 0x16, 0xca];
const XMM0_XMM1: u8 = 0xc1;
const TEST_STATE_IMM32: &[u8] = &[0xf7, 0x87];
const MOV_ECX_STATE: &[u8] = &[0x8b, 0x8f];
const OR_STATE_ECX: &[u8] = &[0x09, 0x8f];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const SHR_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe8];
const SHR_ECX_IMM8: &[u8] = &[0xc1, 0xe9];
const AND_EAX_IMM32: u8 = 0x25;
const OR_EAX_IMM32: u8 = 0x0d;
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const TEST_ECX_IMM32: &[u8] = &[0xf7, 0xc1];
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
const SUB_EAX_IMM8: &[u8] = &[0x83, 0xe8];
const CMP_EAX_IMM32: u8 = 0x3d;
const CMP_EAX_IMM8: &[u8] = &[0x83, 0xf8];
const AND_EAX_IMM8: &[u8] = &[0x83, 0xe0];
const MOVD_EAX_XMM0: &[u8] = &[0x66, 0x0f, 0x7e, 0xc0];
const MOVD_EAX_XMM1: &[u8] = &[0x66, 0x0f, 0x7e, 0xc8];
const MOVQ_RAX_XMM0: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc0];
const MOVQ_RAX_XMM1: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc8];
const MOVD_XMM0_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc0];
const MOVQ_XMM0_XMM0: &[u8] = &[0xf3, 0x0f, 0x7e, 0xc0];
const SUB_RSP_16: &[u8] = &[0x48, 0x83, 0xec, 16];
const ADD_RSP_16: &[u8] = &[0x48, 0x83, 0xc4, 16];
const STMXCSR_SAVED: &[u8] = &[0x0f, 0xae, 0x1c, 0x24];
const MOV_CONTROL_EAX: &[u8] = &[0x89, 0x44, 0x24, 4];
const LDMXCSR_CONTROL: &[u8] = &[0x0f, 0xae, 0x54, 0x24, 4];
const STMXCSR_STATUS: &[u8] = &[0x0f, 0xae, 0x5c, 0x24, 8];
const LDMXCSR_SAVED: &[u8] = &[0x0f, 0xae, 0x14, 0x24];
const MOV_ECX_STATUS: &[u8] = &[0x8b, 0x4c, 0x24, 8];

#[repr(u8)]
enum Condition {
    Below = 0x82,
    AboveOrEqual = 0x83,
    Zero = 0x84,
    NotZero = 0x85,
}

#[repr(u8)]
enum ArithmeticOpcode {
    Add = 0x58,
    Subtract = 0x5c,
    Multiply = 0x59,
    Divide = 0x5e,
}

fn branch(code: &mut Vec<u8>, condition: Condition) -> usize {
    code.extend([SSE_ESCAPE, condition as u8]);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}
fn resolve(code: &mut [u8], patch: usize, target: usize) {
    let distance =
        i32::try_from(target - patch - size_of::<i32>()).expect("bounded numerical branch");
    code[patch..patch + size_of::<i32>()].copy_from_slice(&distance.to_le_bytes());
}
fn test_control(code: &mut Vec<u8>, mask: u32) {
    code.extend(TEST_STATE_IMM32);
    code.extend((std::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
    code.extend(mask.to_le_bytes());
}

/// Leave flags from (exponent-minimum) versus the exclusive range length.
/// Below is allocated normal; zero/all-ones exponents fail one unsigned test.
fn exponent_range(code: &mut Vec<u8>, format: Format, right: bool, minimum: u8) {
    code.extend(match (format, right) {
        (Format::Single, false) => MOVD_EAX_XMM0,
        (Format::Single, true) => MOVD_EAX_XMM1,
        (Format::Double, false) => MOVQ_RAX_XMM0,
        (Format::Double, true) => MOVQ_RAX_XMM1,
        _ => unreachable!("half arithmetic always requests the exact core"),
    });
    code.extend(if format == Format::Double {
        SHR_RAX_IMM8
    } else {
        SHR_EAX_IMM8
    });
    code.push(format.fraction_bits() as u8);
    let exponent_mask = (1u32 << (format.bits() - format.fraction_bits() - 1)) - 1;
    code.push(AND_EAX_IMM32);
    code.extend(exponent_mask.to_le_bytes());
    code.extend(SUB_EAX_IMM8);
    code.push(minimum);
    code.push(CMP_EAX_IMM32);
    code.extend((exponent_mask - u32::from(minimum)).to_le_bytes());
}

fn environment(code: &mut Vec<u8>) {
    code.extend(SUB_RSP_16);
    code.extend(STMXCSR_SAVED);
    code.extend(MOV_ECX_STATE);
    code.extend((std::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
    code.extend(MOV_EAX_ECX);
    code.extend(SHR_EAX_IMM8);
    code.push(FPCR_POSITIVE_TO_MXCSR_SHIFT);
    code.push(AND_EAX_IMM32);
    code.extend(MXCSR_POSITIVE_ROUNDING.to_le_bytes());
    code.extend(SHR_ECX_IMM8);
    code.push(FPCR_NEGATIVE_TO_MXCSR_SHIFT);
    code.extend(AND_ECX_IMM32);
    code.extend(MXCSR_NEGATIVE_ROUNDING.to_le_bytes());
    code.extend(OR_EAX_ECX);
    code.push(OR_EAX_IMM32);
    code.extend(MXCSR_EXCEPTION_MASKS.to_le_bytes());
    code.extend(MOV_CONTROL_EAX);
    code.extend(LDMXCSR_CONTROL);
}

fn restore_environment(code: &mut Vec<u8>) {
    code.extend(STMXCSR_STATUS);
    code.extend(LDMXCSR_SAVED);
    code.extend(MOV_ECX_STATUS);
    code.extend(ADD_RSP_16);
}

fn commit_inexact(code: &mut Vec<u8>) {
    code.extend(AND_ECX_IMM32);
    code.extend(MXCSR_INEXACT.to_le_bytes());
    code.extend(SHR_ECX_IMM8);
    code.push(MXCSR_TO_FPSR_INEXACT_SHIFT);
    code.extend(OR_STATE_ECX);
    code.extend((std::mem::offset_of!(GuestState, fpsr) as u32).to_le_bytes());
}

fn arithmetic_opcode(operation: BinaryOperation) -> ArithmeticOpcode {
    match operation {
        BinaryOperation::Add => ArithmeticOpcode::Add,
        BinaryOperation::Subtract => ArithmeticOpcode::Subtract,
        BinaryOperation::Multiply => ArithmeticOpcode::Multiply,
        BinaryOperation::Divide => ArithmeticOpcode::Divide,
    }
}

fn emit_scalar(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    let mut helper = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_vector(code, operand.left, 0);
    read_vector(code, operand.right, 1);
    for right in [false, true] {
        exponent_range(code, operand.format, right, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
    }
    environment(code);
    let opcode = arithmetic_opcode(operand.operation);
    code.extend([
        if operand.format == Format::Single {
            SCALAR_SINGLE_PREFIX
        } else {
            SCALAR_DOUBLE_PREFIX
        },
        SSE_ESCAPE,
        opcode as u8,
        XMM0_XMM1,
    ]);
    restore_environment(code);
    // Caller environment and stack are restored before every branch from here.
    code.extend(TEST_ECX_IMM32);
    code.extend(MXCSR_OTHER_STATUS.to_le_bytes());
    helper.push(branch(code, Condition::NotZero));
    exponent_range(code, operand.format, false, RESULT_MINIMUM_EXPONENT);
    let success = branch(code, Condition::Below);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, success, success_start);

    commit_inexact(code);
    test_control(code, FPCR_NEP);
    let merge = branch(code, Condition::NotZero);
    if operand.format == Format::Double {
        code.extend(MOVQ_XMM0_XMM0);
    } else {
        code.extend(MOVD_EAX_XMM0);
        code.extend(MOVD_XMM0_EAX);
    }
    let merge_target = code.len();
    resolve(code, merge, merge_target);
    commit(code, operand.destination, 0);
}

/// Extract positive exponents into dwords, then compare against an open range.
/// Double exponents occupy the low dword of each qword; their high dwords and
/// inactive S lanes are excluded from the dword sign mask. No numerical FP runs here.
fn vector_exponent_range(code: &mut Vec<u8>, operand: &Operand, source: u8) {
    packed(code, Host::MoveAligned, EXPONENT_VECTOR, source);
    let (left, right) = match operand.format {
        Format::Single => (ShiftOpcode::LeftDword, ShiftOpcode::RightDword),
        Format::Double => (ShiftOpcode::LeftQword, ShiftOpcode::RightQword),
        Format::Half => unreachable!("half arithmetic always requests the exact core"),
    };
    left.emit(code, EXPONENT_VECTOR, SIGN_BITS);
    right.emit(
        code,
        EXPONENT_VECTOR,
        operand.format.fraction_bits() as u8 + SIGN_BITS,
    );
    packed(
        code,
        Host::MoveAligned,
        VALIDITY_VECTOR,
        MAXIMUM_EXPONENT_VECTOR,
    );
    packed(code, Host::GreaterDword, VALIDITY_VECTOR, EXPONENT_VECTOR);
    packed(
        code,
        Host::GreaterDword,
        EXPONENT_VECTOR,
        MINIMUM_EXPONENT_VECTOR,
    );
    packed(code, Host::And, EXPONENT_VECTOR, VALIDITY_VECTOR);
    Host::DwordSignMask.register(code, 0, EXPONENT_VECTOR, crate::TargetCpu::Baseline);
    let mask = match (operand.shape, operand.format) {
        (Shape::Vector64, Format::Single) => {
            code.extend(AND_EAX_IMM8);
            code.push(SINGLE_LOW_VECTOR_MASK);
            SINGLE_LOW_VECTOR_MASK
        }
        (Shape::Vector128, Format::Single) => SINGLE_VECTOR_MASK,
        (Shape::Vector128, Format::Double) => DOUBLE_VECTOR_MASK,
        _ => unreachable!("allocated vector shape"),
    };
    code.extend(CMP_EAX_IMM8);
    code.push(mask);
}

fn read_numerical_vector(code: &mut Vec<u8>, operand: &Operand, source: u8, xmm: u8) {
    if operand.shape == Shape::Vector64 {
        // MOVQ loads only active bits and clears the high qword, even for DIV.
        Host::MoveQword.append(code, crate::TargetCpu::Baseline);
        const STATE_MEMORY: u8 = 0x87;
        const MODRM_REGISTER_SHIFT: u8 = 3;
        code.push(STATE_MEMORY | (xmm << MODRM_REGISTER_SHIFT));
        code.extend(vector_offset(source).to_le_bytes());
    } else {
        read_vector(code, source, xmm);
    }
}

fn emit_vector(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    let mut helper = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_numerical_vector(code, operand, operand.left, LEFT_VECTOR);
    read_numerical_vector(code, operand, operand.right, RIGHT_VECTOR);
    packed(
        code,
        Host::EqualDword,
        MAXIMUM_EXPONENT_VECTOR,
        MAXIMUM_EXPONENT_VECTOR,
    );
    let exponent_bits =
        operand.format.bits() - operand.format.fraction_bits() - u32::from(SIGN_BITS);
    ShiftOpcode::RightDword.emit(
        code,
        MAXIMUM_EXPONENT_VECTOR,
        (u32::BITS - exponent_bits) as u8,
    );
    packed(
        code,
        Host::Xor,
        MINIMUM_EXPONENT_VECTOR,
        MINIMUM_EXPONENT_VECTOR,
    );
    for source in [LEFT_VECTOR, RIGHT_VECTOR] {
        vector_exponent_range(code, operand, source);
        helper.push(branch(code, Condition::NotZero));
    }
    if operand.shape == Shape::Vector64 && operand.operation == BinaryOperation::Divide {
        // Inactive numerators are zero. Supply 1.0 denominators to avoid 0/0
        // contributing host invalid status; inactive original bits never execute.
        packed(code, Host::EqualDword, EXPONENT_VECTOR, EXPONENT_VECTOR);
        ShiftOpcode::RightDword.emit(
            code,
            EXPONENT_VECTOR,
            u32::BITS as u8 - SINGLE_EXPONENT_BIAS_BITS,
        );
        ShiftOpcode::LeftDword.emit(code, EXPONENT_VECTOR, Format::Single.fraction_bits() as u8);
        code.extend(MOVLHPS_XMM1_XMM2);
    }
    environment(code);
    if operand.format == Format::Double {
        code.push(PACKED_DOUBLE_PREFIX);
    }
    code.extend([
        SSE_ESCAPE,
        arithmetic_opcode(operand.operation) as u8,
        XMM0_XMM1,
    ]);
    restore_environment(code);
    code.extend(TEST_ECX_IMM32);
    code.extend(MXCSR_OTHER_STATUS.to_le_bytes());
    helper.push(branch(code, Condition::NotZero));
    packed(
        code,
        Host::EqualDword,
        MINIMUM_EXPONENT_VECTOR,
        MINIMUM_EXPONENT_VECTOR,
    );
    ShiftOpcode::RightDword.emit(code, MINIMUM_EXPONENT_VECTOR, u32::BITS as u8 - SIGN_BITS);
    vector_exponent_range(code, operand, LEFT_VECTOR);
    let success = branch(code, Condition::Zero);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, success, success_start);
    commit_inexact(code);
    if operand.shape == Shape::Vector64 {
        code.extend(MOVQ_XMM0_XMM0);
    }
    commit(code, operand.destination, LEFT_VECTOR);
}

pub(in crate::x86_64) fn emit(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    if operand.format == Format::Half {
        super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    } else if operand.shape == Shape::Scalar {
        emit_scalar(code, operand, pc);
    } else {
        emit_vector(code, operand, pc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numerical_instructions_require_the_block_exit_protocol() {
        const FADD_S: u32 = 0x1e222820;
        const FADD_H: u32 = 0x1ee22820;
        const FADD_2S: u32 = 0x0e22d420;
        const FADD_4H: u32 = 0x0e421420;
        const RET: u32 = 0xd65f03c0;
        for word in [FADD_S, FADD_H, FADD_2S, FADD_4H] {
            let bytes: Vec<u8> = [word, RET]
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect();
            assert!(
                crate::compile(&bytes, GuestAddress(0x1000))
                    .unwrap_err()
                    .0
                    .contains("NumericalRuntimeRequired")
            );
            let block = crate::block::compile(&bytes, GuestAddress(0x1000)).unwrap();
            if [FADD_H, FADD_4H].contains(&word) {
                assert_eq!(block.source_bytes, size_of::<u32>());
                assert_eq!(block.native.source_map, [(GuestAddress(0x1000), 0)]);
            } else {
                assert_eq!(block.native.source_map.len(), 2);
                assert_eq!(block.native.source_map[1].0, GuestAddress(0x1004));
            }
        }
    }
}
