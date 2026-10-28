//! BF16 binary arithmetic. Normal inputs widen exactly to single; a nearest-even
//! double rounding can differ only at a BF16 midpoint, which with host inexact
//! takes software completion.
use crate::x86_64::asm::Code;

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{
            Format, INEXACT, bfloat16::BFLOAT16_TO_SINGLE_SHIFT, features::NumericalFeatures,
        },
        scalable::{ElementSize, VectorLength},
        simd::arithmetic::Shape,
        sve::{
            dot::RightOperand,
            floating::bfloat16::{BinaryOperation, Kind, Operand},
        },
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::{
            ArithmeticOpcode, Condition, branch, emit_opcode_to, integer_rounding_policy,
            prepare_vector_input_range, prepare_vector_result_range, quantize_bfloat_packed,
            resolve, rounding_control, vector_exponent_range,
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const GPR_RAX: u8 = 0;
const SOURCE: u8 = 1;
const TEMPORARY: u8 = 2;
const CONSTANT: u8 = 3;
const ACTIVE: u8 = 6;
const ASSEMBLED: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const BENIGN_LEFT_EXPONENT_INCREMENT: u32 = 1;
const HALF_GROUPS: usize = 2;
const DISCARDED_BITS: u8 = BFLOAT16_TO_SINGLE_SHIFT as u8;
const BF_MIDPOINT: u32 = 1 << (DISCARDED_BITS - 1);
const REPEAT_LOW_LANE: u8 = 0;
const BF_BYTES: u8 = size_of::<u16>() as u8;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;
const TEST_ECX_IMM32: &[u8] = &[0xf7, 0xc1];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const AND_EAX_IMM32: u8 = 0x25;
const SHR_EAX_IMM8: &[u8] = &[0xc1, 0xe8];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const MOV_EAX_IMM32: u8 = 0xb8;
const JMP_REL32: u8 = 0xe9;
const MOVD_XMM_EAX: &[u8] = &[0x66, 0x0f, 0x6e];
const TEST_R10D_R10D: &[u8] = &[0x45, 0x85, 0xd2];
const SETNE_AL: &[u8] = &[0x0f, 0x95, 0xc0];
const MOVZX_EAX_AL: &[u8] = &[0x0f, 0xb6, 0xc0];

fn jump(code: &mut Code) -> usize {
    code.push(JMP_REL32);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn constant(code: &mut Code, vector: u8, value: u32, target: TargetCpu) {
    code.push(MOV_EAX_IMM32);
    code.extend(value.to_le_bytes());
    code.extend(MOVD_XMM_EAX);
    code.push(MODRM_REGISTER | vector << MODRM_REGISTER_SHIFT);
    Host::ShuffleDword.register(code, vector, vector, target);
    code.push(REPEAT_LOW_LANE);
}

fn half_group(group: usize) -> Host {
    match group {
        0 => Host::UnpackLowWord,
        1 => Host::UnpackHighWord,
        _ => unreachable!("two BF half groups"),
    }
}

fn active_mask(
    code: &mut Code,
    operand: Operand,
    chunk: usize,
    group: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    if let Some(predicate) = operand.predicate {
        read_predicate_mask(
            code,
            predicate,
            chunk,
            ElementSize::Halfword,
            ACTIVE,
            TEMPORARY,
            length,
            target,
        );
        half_group(group).register(code, ACTIVE, ACTIVE, target);
    } else {
        Host::EqualDword.register(code, ACTIVE, ACTIVE, target);
    }
}

fn widen(code: &mut Code, register: u8, group: usize, target: TargetCpu) {
    Host::Xor.register(code, TEMPORARY, TEMPORARY, target);
    half_group(group).register(code, register, TEMPORARY, target);
    ShiftOpcode::LeftDword.emit(code, register, DISCARDED_BITS);
}

fn benign_inactive(code: &mut Code, register: u8, value: u32, target: TargetCpu) {
    constant(code, CONSTANT, value, target);
    Host::MoveAligned.register(code, TEMPORARY, ACTIVE, target);
    Host::AndNot.register(code, TEMPORARY, CONSTANT, target);
    Host::And.register(code, register, ACTIVE, target);
    Host::Or.register(code, register, TEMPORARY, target);
}

fn load_right(
    code: &mut Code,
    operand: Operand,
    chunk: usize,
    group: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    match operand.right {
        RightOperand::Vector(register) => {
            load_z_chunk(code, register, chunk, SOURCE, length, target)
        }
        RightOperand::Indexed { register, index } => {
            load_z_chunk(code, register, chunk, SOURCE, length, target);
            if index != 0 {
                ShiftOpcode::RightBytes.emit(code, SOURCE, index * BF_BYTES);
            }
            Host::ShuffleLowWord.register(code, SOURCE, SOURCE, target);
            code.push(REPEAT_LOW_LANE);
            Host::ShuffleDword.register(code, SOURCE, SOURCE, target);
            code.push(REPEAT_LOW_LANE);
        }
    }
    widen(code, SOURCE, group, target);
}

/// Reject possible first-rounding ambiguity before the integer BF rounding.
/// This conservative check also rejects directed/inactive cross-lane ties; it
/// never accepts an ambiguous nearest-even double rounding.
fn midpoint_guard(code: &mut Code, failures: &mut Vec<usize>, target: TargetCpu) {
    code.extend(TEST_ECX_IMM32);
    code.extend(MXCSR_INEXACT.to_le_bytes());
    let exact = branch(code, Condition::Zero);
    Host::MoveAligned.register(code, TEMPORARY, SOURCE, target);
    ShiftOpcode::LeftDword.emit(code, TEMPORARY, u32::BITS as u8 - DISCARDED_BITS);
    ShiftOpcode::RightDword.emit(code, TEMPORARY, u32::BITS as u8 - DISCARDED_BITS);
    constant(code, CONSTANT, BF_MIDPOINT, target);
    Host::EqualDword.register(code, TEMPORARY, CONSTANT, target);
    Host::DwordSignMask.register(code, GPR_RAX, TEMPORARY, target);
    code.extend(TEST_EAX_EAX);
    failures.push(branch(code, Condition::NotZero));
    let end = code.len();
    resolve(code, exact, end);
}

fn arithmetic_opcode(operation: BinaryOperation) -> Option<ArithmeticOpcode> {
    match operation {
        BinaryOperation::Add => Some(ArithmeticOpcode::Add),
        BinaryOperation::Subtract => Some(ArithmeticOpcode::Subtract),
        BinaryOperation::Multiply => Some(ArithmeticOpcode::Multiply),
        _ => None,
    }
}

/// Emit the seven nonwidening BFADD/BFSUB/BFMUL forms. All sources remain in
/// architectural storage until the shared frame commits the complete vector.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Kind::Binary(operation) = operand.kind else {
        return Ok(false);
    };
    if arithmetic_opcode(operation).is_none() {
        return Ok(false);
    }
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    rounding_control(code);
    numerical::install_mxcsr(code, &frame);
    integer_rounding_policy(code, DISCARDED_BITS, false);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        let inactive = operand.predicate.map(|predicate| {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                ElementSize::Halfword,
                ACTIVE,
                TEMPORARY,
                length,
                target,
            );
            Host::ByteSignMask.register(code, GPR_RAX, ACTIVE, target);
            code.extend(TEST_EAX_EAX);
            branch(code, Condition::Zero)
        });
        for group in 0..HALF_GROUPS {
            active_mask(code, operand, chunk, group, length, target);
            guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
            load_z_chunk(code, operand.left, chunk, RESULT, length, target);
            widen(code, RESULT, group, target);
            load_right(code, operand, chunk, group, length, target);
            if operand.predicate.is_some() {
                let one = Format::Single.exponent_bias() << Format::Single.fraction_bits();
                let two = (Format::Single.exponent_bias() + BENIGN_LEFT_EXPONENT_INCREMENT)
                    << Format::Single.fraction_bits();
                benign_inactive(code, RESULT, two, target);
                benign_inactive(code, SOURCE, one, target);
            }
            prepare_vector_input_range(code, Format::Single);
            for input in [RESULT, SOURCE] {
                vector_exponent_range(code, Format::Single, Shape::Vector128, input);
                failures.push(branch(code, Condition::NotZero));
            }
            if operation != BinaryOperation::Multiply {
                numerical::clear_status(code, &frame);
            }
            emit_opcode_to(
                code,
                Format::Single,
                Shape::Vector128,
                arithmetic_opcode(operation).expect("validated BF binary operation"),
                RESULT,
                SOURCE,
            );
            prepare_vector_result_range(code);
            vector_exponent_range(code, Format::Single, Shape::Vector128, RESULT);
            failures.push(branch(code, Condition::NotZero));
            Host::MoveAligned.register(code, SOURCE, RESULT, target);
            // Directed host overflow may return a finite maximum, so every
            // operation retains the non-IXC status guard. A nonexceptional BF
            // p8 product has at most sixteen bits and is exact at Single p24.
            numerical::capture_status(code, &frame);
            code.extend(TEST_ECX_IMM32);
            code.extend(MXCSR_OTHER_STATUS.to_le_bytes());
            failures.push(branch(code, Condition::NotZero));
            if operation != BinaryOperation::Multiply {
                code.extend(MOV_EAX_ECX);
                code.push(AND_EAX_IMM32);
                code.extend(MXCSR_INEXACT.to_le_bytes());
                code.extend(SHR_EAX_IMM8);
                code.push(MXCSR_TO_FPSR_INEXACT_SHIFT);
                numerical::add_fpsr(code, &frame);
                midpoint_guard(code, &mut failures, target);
            }
            quantize_bfloat_packed(code);
            prepare_vector_input_range(code, Format::Single);
            vector_exponent_range(code, Format::Single, Shape::Vector128, RESULT);
            failures.push(branch(code, Condition::NotZero));
            code.extend(TEST_R10D_R10D);
            code.extend(SETNE_AL);
            code.extend(MOVZX_EAX_AL);
            code.extend(SHL_EAX_IMM8);
            code.push(INEXACT.trailing_zeros() as u8);
            numerical::add_fpsr(code, &frame);
            ShiftOpcode::ArithmeticDword.emit(code, RESULT, DISCARDED_BITS);
            Host::PackSignedDwordToWord.register(code, RESULT, RESULT, target);
            if group == 0 {
                Host::MoveAligned.register(code, ASSEMBLED, RESULT, target);
            } else {
                Host::UnpackLowQword.register(code, ASSEMBLED, RESULT, target);
            }
        }
        if let Some(predicate) = operand.predicate {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                ElementSize::Halfword,
                ACTIVE,
                TEMPORARY,
                length,
                target,
            );
            load_z_chunk(code, operand.destination, chunk, RESULT, length, target);
            Host::And.register(code, ASSEMBLED, ACTIVE, target);
            Host::AndNot.register(code, ACTIVE, RESULT, target);
            Host::Or.register(code, ASSEMBLED, ACTIVE, target);
        }
        if let Some(inactive) = inactive {
            let active = jump(code);
            let unchanged = code.len();
            resolve(code, inactive, unchanged);
            load_z_chunk(code, operand.destination, chunk, ASSEMBLED, length, target);
            let staged = code.len();
            resolve(code, active, staged);
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, ASSEMBLED, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
