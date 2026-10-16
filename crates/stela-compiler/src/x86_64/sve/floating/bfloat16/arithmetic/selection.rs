//! Finite/zero BF min/max and clamp; no host FP environment or status effects.
//! Guarded exceptional lanes retain the exact whole-instruction service.
use crate::{
    CompileError, GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{FPCR_AH, features::NumericalFeatures},
        scalable::{ElementSize, VectorLength},
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
        simd::numerical::{Condition, branch, resolve},
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const LEFT: u8 = 1;
const RIGHT: u8 = 2;
const TEMPORARY: u8 = 3;
const SECOND_TEMPORARY: u8 = 4;
const ACTIVE: u8 = 5;
const ZERO: u8 = 6;
const EXPONENT_MAXIMUM: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const BFLOAT_BITS: u8 = u16::BITS as u8;
const BFLOAT_FRACTION_BITS: u8 = 7;
const BFLOAT_EXPONENT_BITS: u8 = 8;
const BFLOAT_SIGN_BITS: u8 = 1;
const SIGN_SHIFT: u8 = BFLOAT_BITS - BFLOAT_SIGN_BITS;
const FRACTION_TO_SIGN_SHIFT: u8 = BFLOAT_BITS - BFLOAT_FRACTION_BITS;
const GPR_RAX: u8 = 0;
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const TEST_STATE_IMMEDIATE: &[u8] = &[0xf7, 0x87];
const PBLENDVB: &[u8] = &[0x66, 0x0f, 0x38, 0x10];
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recipe {
    CompareSelect,
    CheckedBlend,
}

fn reject_mask(code: &mut Vec<u8>, failures: &mut Vec<usize>, target: TargetCpu) {
    Host::ByteSignMask.append(code, target);
    code.push(MODRM_REGISTER | (GPR_RAX << MODRM_REGISTER_SHIFT) | TEMPORARY);
    code.extend(TEST_EAX_EAX);
    failures.push(branch(code, Condition::NotZero));
}

fn constants(code: &mut Vec<u8>, target: TargetCpu) {
    Host::Xor.register(code, ZERO, ZERO, target);
    Host::EqualWord.register(code, EXPONENT_MAXIMUM, EXPONENT_MAXIMUM, target);
    ShiftOpcode::RightWord.emit(code, EXPONENT_MAXIMUM, BFLOAT_BITS - BFLOAT_EXPONENT_BITS);
}

/// Preserve raw inputs and classify only active lanes. Exponent-all-ones values
/// and nonzero subnormals use shared exact completion; signed zeros pass.
fn guard(
    code: &mut Vec<u8>,
    input: u8,
    predicated: bool,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    Host::MoveAligned.register(code, RESULT, input, target);
    ShiftOpcode::LeftWord.emit(code, RESULT, BFLOAT_SIGN_BITS);
    ShiftOpcode::RightWord.emit(code, RESULT, BFLOAT_BITS - BFLOAT_EXPONENT_BITS);
    Host::MoveAligned.register(code, TEMPORARY, RESULT, target);
    Host::EqualWord.register(code, TEMPORARY, EXPONENT_MAXIMUM, target);
    Host::MoveAligned.register(code, SECOND_TEMPORARY, input, target);
    ShiftOpcode::LeftWord.emit(code, SECOND_TEMPORARY, FRACTION_TO_SIGN_SHIFT);
    Host::EqualWord.register(code, SECOND_TEMPORARY, ZERO, target);
    Host::EqualWord.register(code, RESULT, ZERO, target);
    Host::AndNot.register(code, SECOND_TEMPORARY, RESULT, target);
    Host::Or.register(code, TEMPORARY, SECOND_TEMPORARY, target);
    if predicated {
        Host::And.register(code, TEMPORARY, ACTIVE, target);
    }
    reject_mask(code, failures, target);
}

/// Inputs LEFT/RIGHT remain original until comparison. Equal encodings may
/// choose either source; opposite zeros use the required standard numeric order.
fn select(code: &mut Vec<u8>, minimum: bool, alternative: bool, recipe: Recipe, target: TargetCpu) {
    if alternative {
        Host::MoveAligned.register(code, TEMPORARY, LEFT, target);
        Host::Or.register(code, TEMPORARY, RIGHT, target);
        ShiftOpcode::LeftWord.emit(code, TEMPORARY, BFLOAT_SIGN_BITS);
        Host::EqualWord.register(code, TEMPORARY, ZERO, target);
    }
    Host::MoveAligned.register(code, SECOND_TEMPORARY, LEFT, target);
    Host::And.register(code, SECOND_TEMPORARY, RIGHT, target);
    ShiftOpcode::ArithmeticWord.emit(code, SECOND_TEMPORARY, SIGN_SHIFT);
    Host::MoveAligned.register(code, RESULT, LEFT, target);
    Host::GreaterWord.register(code, RESULT, RIGHT, target);
    Host::Xor.register(code, RESULT, SECOND_TEMPORARY, target);
    if minimum {
        Host::EqualWord.register(code, SECOND_TEMPORARY, SECOND_TEMPORARY, target);
        Host::Xor.register(code, RESULT, SECOND_TEMPORARY, target);
    }
    if alternative {
        code.extend(TEST_STATE_IMMEDIATE);
        code.extend((core::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
        code.extend(FPCR_AH.to_le_bytes());
        let ordinary = branch(code, Condition::Zero);
        Host::AndNot.register(code, TEMPORARY, RESULT, target);
        Host::MoveAligned.register(code, RESULT, TEMPORARY, target);
        let destination = code.len();
        resolve(code, ordinary, destination);
    }
    if recipe == Recipe::CheckedBlend {
        debug_assert!(target.supports(TargetCpu::Sse41));
        code.extend(PBLENDVB);
        code.push(MODRM_REGISTER | (RIGHT << MODRM_REGISTER_SHIFT) | LEFT);
        Host::MoveAligned.register(code, RESULT, RIGHT, target);
    } else {
        Host::And.register(code, LEFT, RESULT, target);
        Host::AndNot.register(code, RESULT, RIGHT, target);
        Host::Or.register(code, RESULT, LEFT, target);
    }
}

fn emit_with_recipe(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
    recipe: Recipe,
) -> Result<bool, CompileError> {
    let (minimum, alternative, clamp) = match operand.kind {
        Kind::Binary(BinaryOperation::Minimum) => (true, true, false),
        Kind::Binary(BinaryOperation::Maximum) => (false, true, false),
        Kind::Binary(BinaryOperation::MinimumNumber) => (true, false, false),
        Kind::Binary(BinaryOperation::MaximumNumber) => (false, false, false),
        Kind::Clamp => (false, false, true),
        _ => return Ok(false),
    };
    let RightOperand::Vector(right) = operand.right else {
        return Ok(false);
    };
    if recipe == Recipe::CheckedBlend && !target.supports(TargetCpu::Sse41) {
        return Ok(false);
    }
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    let mut failures = Vec::new();
    constants(code, target);
    for chunk in 0..length.chunks() {
        if let Some(predicate) = operand.predicate {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                ElementSize::Halfword,
                ACTIVE,
                RESULT,
                length,
                target,
            );
        } else if features.full_a64() {
            Host::EqualWord.register(code, ACTIVE, ACTIVE, target);
        }
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, operand.left, chunk, LEFT, length, target);
        load_z_chunk(
            code,
            if clamp { operand.destination } else { right },
            chunk,
            RIGHT,
            length,
            target,
        );
        guard(
            code,
            LEFT,
            operand.predicate.is_some(),
            &mut failures,
            target,
        );
        guard(
            code,
            RIGHT,
            operand.predicate.is_some(),
            &mut failures,
            target,
        );
        select(code, minimum, alternative, recipe, target);
        if clamp {
            Host::MoveAligned.register(code, RIGHT, RESULT, target);
            load_z_chunk(code, right, chunk, LEFT, length, target);
            guard(code, LEFT, false, &mut failures, target);
            select(code, true, false, recipe, target);
        }
        if operand.predicate.is_some() {
            load_z_chunk(code, operand.destination, chunk, LEFT, length, target);
            Host::And.register(code, RESULT, ACTIVE, target);
            Host::AndNot.register(code, ACTIVE, LEFT, target);
            Host::Or.register(code, RESULT, ACTIVE, target);
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    // Paired measurements qualify these lengths; all others keep the baseline.
    const QUALIFIED_MAPPING_LENGTHS: [usize; 2] = [16, 64];
    let recipe = if QUALIFIED_MAPPING_LENGTHS.contains(&length.bytes())
        && target.supports(TargetCpu::Sse41)
    {
        Recipe::CheckedBlend
    } else {
        Recipe::CompareSelect
    };
    emit_with_recipe(code, operand, length, features, pc, target, recipe)
}

#[cfg(test)]
mod tests;
