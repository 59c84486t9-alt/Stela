//! BF16 binary arithmetic. Normal inputs widen exactly to single; a nearest-even
//! double rounding can differ only at a BF16 midpoint, which with host inexact
//! takes software completion.
use crate::x86_64::asm::Gpr::{R10, Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, ShiftOp, Size};

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
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;

fn jump(code: &mut Code) -> usize {
    code.asm().jmp().offset()
}

fn constant(code: &mut Code, vector: u8, value: u32, target: TargetCpu) {
    code.asm().mov_imm32(Rax, value);
    code.asm().movd_to_xmm(vector, Rax);
    code.asm().simd_imm(
        Host::ShuffleDword,
        vector,
        Rm::Xmm(vector),
        REPEAT_LOW_LANE,
        target,
    );
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
            code.asm().simd_imm(
                Host::ShuffleLowWord,
                SOURCE,
                Rm::Xmm(SOURCE),
                REPEAT_LOW_LANE,
                target,
            );
            code.asm().simd_imm(
                Host::ShuffleDword,
                SOURCE,
                Rm::Xmm(SOURCE),
                REPEAT_LOW_LANE,
                target,
            );
        }
    }
    widen(code, SOURCE, group, target);
}

/// Reject possible first-rounding ambiguity before the integer BF rounding.
/// This conservative check also rejects directed/inactive cross-lane ties; it
/// never accepts an ambiguous nearest-even double rounding.
fn midpoint_guard(code: &mut Code, failures: &mut Vec<usize>, target: TargetCpu) {
    code.asm().test_imm(Size::Dword, Rcx, MXCSR_INEXACT as i32);
    let exact = branch(code, Condition::Zero);
    Host::MoveAligned.register(code, TEMPORARY, SOURCE, target);
    ShiftOpcode::LeftDword.emit(code, TEMPORARY, u32::BITS as u8 - DISCARDED_BITS);
    ShiftOpcode::RightDword.emit(code, TEMPORARY, u32::BITS as u8 - DISCARDED_BITS);
    constant(code, CONSTANT, BF_MIDPOINT, target);
    Host::EqualDword.register(code, TEMPORARY, CONSTANT, target);
    code.asm()
        .simd_to_gpr(Host::DwordSignMask, Rax, TEMPORARY, target);
    code.asm().test(Size::Dword, Rax, Rax);
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
            code.asm()
                .simd_to_gpr(Host::ByteSignMask, Rax, ACTIVE, target);
            code.asm().test(Size::Dword, Rax, Rax);
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
            code.asm()
                .test_imm(Size::Dword, Rcx, MXCSR_OTHER_STATUS as i32);
            failures.push(branch(code, Condition::NotZero));
            if operation != BinaryOperation::Multiply {
                let mut asm = code.asm();
                asm.mov(Size::Dword, Rax, Rcx);
                asm.alu_accumulator_imm32(Alu::And, Size::Dword, MXCSR_INEXACT as i32);
                asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, MXCSR_TO_FPSR_INEXACT_SHIFT);
                numerical::add_fpsr(code, &frame);
                midpoint_guard(code, &mut failures, target);
            }
            quantize_bfloat_packed(code);
            prepare_vector_input_range(code, Format::Single);
            vector_exponent_range(code, Format::Single, Shape::Vector128, RESULT);
            failures.push(branch(code, Condition::NotZero));
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
