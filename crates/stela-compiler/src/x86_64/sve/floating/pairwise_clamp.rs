//! Private pairwise min/max and clamp native candidate; shared staging owns commit.
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures, minmax::MinMaxOperation},
        scalable::{ElementSize, VectorLength},
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
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
const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const ACTIVE: u8 = 2;
const CLASSIFICATION_SCRATCH: [u8; 3] = [3, 4, 5];
const PREDICATE_SCRATCH: u8 = CLASSIFICATION_SCRATCH[0];
const CLASSIFICATION_MASKS: [u8; 2] = [6, 7];
const ZERO_PAIR: u8 = CLASSIFICATION_SCRATCH[0];
const ZERO_VECTOR: u8 = CLASSIFICATION_SCRATCH[1];
const DOUBLE_ZERO_SCRATCH: u8 = CLASSIFICATION_SCRATCH[2];
const OLD_DESTINATION: u8 = CLASSIFICATION_SCRATCH[0];
const OUTPUT_SLOT: usize = 0;
const GPR_RAX: u8 = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const SSE_ESCAPE: u8 = 0x0f;
const PACKED_DOUBLE_PREFIX: u8 = 0x66;
const REMOVE_SIGN_BITS: u8 = 1;
const SWAP_ADJACENT_DWORDS: u8 = 0xb1;
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];

#[repr(u8)]
enum SelectionOpcode {
    Minimum = 0x5d,
    Maximum = 0x5f,
}

/// Reject only active pairs whose two magnitudes are zero. Removing the sign
/// after OR accepts exactly-one-zero inputs while retaining every signed-zero
/// tie for the shared semantic helper. Double requires both dwords to be zero.
/// LEFT/RIGHT/ACTIVE and the invariant classification masks remain live.
fn guard_zero_pairs(
    code: &mut Vec<u8>,
    format: Format,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    Host::MoveAligned.register(code, ZERO_PAIR, LEFT, target);
    Host::Or.register(code, ZERO_PAIR, RIGHT, target);
    match format {
        Format::Single => ShiftOpcode::LeftDword,
        Format::Double => ShiftOpcode::LeftQword,
        Format::Half => unreachable!("native min/max width validated before emission"),
    }
    .emit(code, ZERO_PAIR, REMOVE_SIGN_BITS);
    Host::Xor.register(code, ZERO_VECTOR, ZERO_VECTOR, target);
    Host::EqualDword.register(code, ZERO_PAIR, ZERO_VECTOR, target);
    if format == Format::Double {
        Host::ShuffleDword.register(code, DOUBLE_ZERO_SCRATCH, ZERO_PAIR, target);
        code.push(SWAP_ADJACENT_DWORDS);
        Host::And.register(code, ZERO_PAIR, DOUBLE_ZERO_SCRATCH, target);
    }
    Host::And.register(code, ZERO_PAIR, ACTIVE, target);
    Host::ByteSignMask.register(code, GPR_RAX, ZERO_PAIR, target);
    code.extend(TEST_EAX_EAX);
    code.extend(JNZ_REL32);
    failures.push(code.len());
    code.extend(0_i32.to_le_bytes());
}

fn selection(code: &mut Vec<u8>, operation: MinMaxOperation, format: Format) {
    let opcode = match operation {
        MinMaxOperation::Minimum | MinMaxOperation::MinimumNumber => SelectionOpcode::Minimum,
        MinMaxOperation::Maximum | MinMaxOperation::MaximumNumber => SelectionOpcode::Maximum,
    };
    if format == Format::Double {
        code.push(PACKED_DOUBLE_PREFIX);
    }
    code.extend([
        SSE_ESCAPE,
        opcode as u8,
        MODRM_REGISTER | (LEFT << MODRM_REGISTER_SHIFT) | RIGHT,
    ]);
}

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

/// Unpredicated destructive FCLAMP: MaxNum(lower, oldD), then MinNum(result, upper).
/// The second guard sees the selected first-stage bits and the original upper
/// bank. Source/destination aliases remain intact until the final staged commit.
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
