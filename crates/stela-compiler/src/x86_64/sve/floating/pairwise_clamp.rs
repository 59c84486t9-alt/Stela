//! SVE pairwise min/max and FCLAMP.
use super::minmax::{guard_zero_pairs, selection};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures, minmax::MinMaxOperation},
        scalable::{ElementSize, VectorLength},
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape},
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        sve::floating::classify::{
            guard_active_exception_enables, guard_normal_zero_or_infinity, prepare_classification,
        },
    },
};
use alloc::vec::Vec;
const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const ACTIVE: u8 = 2;
const CLASSIFICATION_SCRATCH: [u8; 3] = [3, 4, 5];
const PREDICATE_SCRATCH: u8 = CLASSIFICATION_SCRATCH[0];
const CLASSIFICATION_MASKS: [u8; 2] = [6, 7];
const OLD_DESTINATION: u8 = CLASSIFICATION_SCRATCH[0];
const OUTPUT_SLOT: usize = 0;

const EVEN_DWORDS: u8 = 0x88;
const ODD_DWORDS: u8 = 0xdd;
const PREPARED_EVEN: u8 = CLASSIFICATION_SCRATCH[0];
const PREPARED_RIGHT: u8 = CLASSIFICATION_SCRATCH[1];

fn shuffle(code: &mut Vec<u8>, destination: u8, source: u8, order: u8, target: TargetCpu) {
    Host::ShuffleDword.register(code, destination, source, target);
    code.push(order);
}

/// Interleave source pairs by output lane; the output predicate is applied only
/// after this permutation, so inactive-index source operands remain available.
fn paired_inputs(code: &mut Vec<u8>, format: Format, target: TargetCpu) {
    if format == Format::Single {
        shuffle(code, PREPARED_EVEN, LEFT, EVEN_DWORDS, target);
        shuffle(code, PREPARED_RIGHT, RIGHT, EVEN_DWORDS, target);
        Host::UnpackLowDword.register(code, PREPARED_EVEN, PREPARED_RIGHT, target);
        shuffle(code, LEFT, LEFT, ODD_DWORDS, target);
        shuffle(code, RIGHT, RIGHT, ODD_DWORDS, target);
        Host::UnpackLowDword.register(code, LEFT, RIGHT, target);
    } else {
        Host::MoveAligned.register(code, PREPARED_EVEN, LEFT, target);
        Host::UnpackLowQword.register(code, PREPARED_EVEN, RIGHT, target);
        Host::UnpackHighQword.register(code, LEFT, RIGHT, target);
    }
    Host::MoveAligned.register(code, RIGHT, LEFT, target);
    Host::MoveAligned.register(code, LEFT, PREPARED_EVEN, target);
}

fn element(format: Format) -> Option<ElementSize> {
    match format {
        Format::Single => Some(ElementSize::Word),
        Format::Double => Some(ElementSize::Doubleword),
        Format::Half => None,
    }
}

/// Four predicated pairwise min/max forms; every failed guard remains atomic
/// at instruction scope. Exactly-one-zero pairs are allowed, ties are not.
pub(in crate::x86_64) fn emit_pairwise(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Some(element) = element(operand.format) else {
        return Ok(false);
    };
    let Kind::MinMax(operation) = operand.kind else {
        return Ok(false);
    };
    let Inputs::Pairwise { left, right } = operand.inputs else {
        return Ok(false);
    };
    let Some(predicate) = operand.predicate else {
        return Ok(false);
    };
    if operand.shape != ResultShape::Vector || left != operand.destination {
        return Ok(false);
    }
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    let classification = prepare_classification(code, operand.format, CLASSIFICATION_MASKS, target);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            predicate,
            chunk,
            element,
            ACTIVE,
            PREDICATE_SCRATCH,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, left, chunk, LEFT, length, target);
        load_z_chunk(code, right, chunk, RIGHT, length, target);
        paired_inputs(code, operand.format, target);
        for input in [LEFT, RIGHT] {
            Host::And.register(code, input, ACTIVE, target);
            guard_normal_zero_or_infinity(
                code,
                classification,
                input,
                CLASSIFICATION_SCRATCH,
                &mut failures,
                target,
            );
        }
        guard_zero_pairs(code, operand.format, &mut failures, target);
        selection(code, operation, operand.format);
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            OLD_DESTINATION,
            length,
            target,
        );
        Host::And.register(code, LEFT, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, OLD_DESTINATION, target);
        Host::Or.register(code, LEFT, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}

/// Destructive FCLAMP: MaxNum(lower, old Zd), then MinNum(result, upper).
/// Aliases stay intact until the final staged commit.
pub(in crate::x86_64) fn emit_clamp(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    if element(operand.format).is_none() {
        return Ok(false);
    }
    let Kind::Clamp = operand.kind else {
        return Ok(false);
    };
    let Inputs::Clamp {
        value,
        lower,
        upper,
    } = operand.inputs
    else {
        return Ok(false);
    };
    if operand.shape != ResultShape::Vector
        || operand.predicate.is_some()
        || value != operand.destination
    {
        return Ok(false);
    }
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    let classification = prepare_classification(code, operand.format, CLASSIFICATION_MASKS, target);
    let mut failures = Vec::new();
    Host::EqualDword.register(code, ACTIVE, ACTIVE, target);
    guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
    for chunk in 0..length.chunks() {
        load_z_chunk(code, lower, chunk, LEFT, length, target);
        load_z_chunk(code, value, chunk, RIGHT, length, target);
        for input in [LEFT, RIGHT] {
            guard_normal_zero_or_infinity(
                code,
                classification,
                input,
                CLASSIFICATION_SCRATCH,
                &mut failures,
                target,
            );
        }
        guard_zero_pairs(code, operand.format, &mut failures, target);
        selection(code, MinMaxOperation::MaximumNumber, operand.format);
        load_z_chunk(code, upper, chunk, RIGHT, length, target);
        guard_normal_zero_or_infinity(
            code,
            classification,
            RIGHT,
            CLASSIFICATION_SCRATCH,
            &mut failures,
            target,
        );
        guard_zero_pairs(code, operand.format, &mut failures, target);
        selection(code, MinMaxOperation::MinimumNumber, operand.format);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}

/// Common-capsule entry point; unrelated arithmetic remains untouched.
pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    if operand.kind == Kind::Clamp {
        emit_clamp(code, operand, length, features, pc, target)
    } else {
        emit_pairwise(code, operand, length, features, pc, target)
    }
}
