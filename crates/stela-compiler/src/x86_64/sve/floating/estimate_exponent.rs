//! Exact integer FRECPX/FLOGB candidates over guarded Single/Double lanes.
//! Exceptional inputs retain instruction-wide semantic completion. No host FP
//! operation or MXCSR access participates in this integer-only route.
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::{ElementSize, VectorLength},
        simd::estimate::Kind as EstimateKind,
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

const VALUE: u8 = 0;
const BIAS_OR_EXPONENT_UNIT: u8 = 1;
const ACTIVE: u8 = 2;
const SCRATCH: [u8; 3] = [3, 4, 5];
const MASKS: [u8; 2] = [6, 7];
const FRACTION_MASK: u8 = MASKS[0];
const EXPONENT_MASK: u8 = MASKS[1];
const TEST_MASK: u8 = SCRATCH[0];
const TEMPORARY: u8 = SCRATCH[1];
const OUTPUT_SLOT: usize = 0;
const GPR_RAX: u8 = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const MOV_RAX_IMMEDIATE: &[u8] = &[0x48, 0xb8];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const REPEAT_LOW_DWORD: u8 = 0;
const REPEAT_HIGH_DWORDS: u8 = 0xf5;
const REMOVE_SIGN_BITS: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    ReciprocalExponent,
    LogarithmExponent,
}

fn inputs(operand: Operand) -> Option<(Operation, u8, u8)> {
    let Inputs::Unary { source } = operand.inputs else {
        return None;
    };
    if operand.shape != ResultShape::Vector {
        return None;
    }
    let operation = match operand.kind {
        Kind::Estimate(EstimateKind::ReciprocalExponent) => Operation::ReciprocalExponent,
        Kind::Logb => Operation::LogarithmExponent,
        _ => return None,
    };
    Some((operation, source, operand.predicate?))
}

fn broadcast(code: &mut Vec<u8>, format: Format, value: u64, register: u8, target: TargetCpu) {
    if format == Format::Single {
        code.push(MOV_EAX_IMMEDIATE);
        code.extend((value as u32).to_le_bytes());
    } else {
        code.extend(MOV_RAX_IMMEDIATE);
        code.extend(value.to_le_bytes());
    }
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (register << MODRM_REGISTER_SHIFT) | GPR_RAX);
    if format == Format::Single {
        Host::ShuffleDword.register(code, register, register, target);
        code.push(REPEAT_LOW_DWORD);
    } else {
        Host::UnpackLowQword.register(code, register, register, target);
    }
}

fn replicate_exponent_comparison(
    code: &mut Vec<u8>,
    format: Format,
    register: u8,
    target: TargetCpu,
) {
    if format == Format::Double {
        // Only the high dword contains exponent bits in a Double lane.
        Host::ShuffleDword.register(code, register, register, target);
        code.push(REPEAT_HIGH_DWORDS);
    }
}

fn subtract(code: &mut Vec<u8>, format: Format, destination: u8, source: u8, target: TargetCpu) {
    match format {
        Format::Single => Host::SubDword,
        Format::Double => Host::SubQword,
        Format::Half => unreachable!("validated Single/Double integer kernel"),
    }
    .register(code, destination, source, target);
}

fn right_shift(code: &mut Vec<u8>, format: Format, register: u8, amount: u8) {
    match format {
        Format::Single => ShiftOpcode::RightDword,
        Format::Double => ShiftOpcode::RightQword,
        Format::Half => unreachable!("validated Single/Double integer kernel"),
    }
    .emit(code, register, amount);
}

fn reciprocal_exponent(code: &mut Vec<u8>, format: Format, target: TargetCpu) {
    Host::MoveAligned.register(code, TEST_MASK, VALUE, target);
    Host::And.register(code, TEST_MASK, EXPONENT_MASK, target);
    Host::Xor.register(code, TEMPORARY, TEMPORARY, target);
    Host::EqualDword.register(code, TEMPORARY, TEST_MASK, target);
    replicate_exponent_comparison(code, format, TEMPORARY, target);
    Host::And.register(code, TEMPORARY, BIAS_OR_EXPONENT_UNIT, target);
    // Complement only the raw exponent and retain the original sign. For zero
    // exponent, one field unit changes its complement from all-ones to max-1.
    Host::EqualDword.register(code, TEST_MASK, TEST_MASK, target);
    Host::Xor.register(code, TEST_MASK, FRACTION_MASK, target);
    Host::And.register(code, VALUE, TEST_MASK, target);
    Host::Xor.register(code, VALUE, EXPONENT_MASK, target);
    subtract(code, format, VALUE, TEMPORARY, target);
}

fn logarithm_exponent(
    code: &mut Vec<u8>,
    format: Format,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    Host::And.register(code, VALUE, EXPONENT_MASK, target);
    Host::Xor.register(code, TEST_MASK, TEST_MASK, target);
    Host::EqualDword.register(code, TEST_MASK, VALUE, target);
    replicate_exponent_comparison(code, format, TEST_MASK, target);
    Host::And.register(code, TEST_MASK, ACTIVE, target);
    Host::ByteSignMask.register(code, GPR_RAX, TEST_MASK, target);
    code.extend(TEST_EAX_EAX);
    code.extend(JNZ_REL32);
    failures.push(code.len());
    code.extend(0_i32.to_le_bytes());
    // Zero raises Invalid in FPLogB, so it falls back before staging. Infinity
    // selects signed integer MAX; normals subtract the bias from the field.
    Host::MoveAligned.register(code, TEST_MASK, EXPONENT_MASK, target);
    Host::EqualDword.register(code, TEST_MASK, VALUE, target);
    replicate_exponent_comparison(code, format, TEST_MASK, target);
    right_shift(code, format, VALUE, format.fraction_bits() as u8);
    subtract(code, format, VALUE, BIAS_OR_EXPONENT_UNIT, target);
    Host::EqualDword.register(code, TEMPORARY, TEMPORARY, target);
    right_shift(code, format, TEMPORARY, REMOVE_SIGN_BITS);
    Host::And.register(code, TEMPORARY, TEST_MASK, target);
    Host::AndNot.register(code, TEST_MASK, VALUE, target);
    Host::MoveAligned.register(code, VALUE, TEST_MASK, target);
    Host::Or.register(code, VALUE, TEMPORARY, target);
}

/// Two exact unary predicated forms; masks6/7 and constant1 live across chunks.
/// Clobbers volatile RAX/RCX/RDX, host flags and XMM0..7. RDI/R15, guest NZCV,
/// FPSR, raw FPCR, sources and caller MXCSR survive until the only staged commit.
pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let element = match operand.format {
        Format::Single => ElementSize::Word,
        Format::Double => ElementSize::Doubleword,
        Format::Half => return Ok(false),
    };
    let Some((operation, source, predicate)) = inputs(operand) else {
        return Ok(false);
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    let classification = prepare_classification(code, operand.format, MASKS, target);
    let constant = match operation {
        Operation::ReciprocalExponent => 1 << operand.format.fraction_bits(),
        Operation::LogarithmExponent => u64::from(operand.format.exponent_bias()),
    };
    broadcast(
        code,
        operand.format,
        constant,
        BIAS_OR_EXPONENT_UNIT,
        target,
    );
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code, predicate, chunk, element, ACTIVE, TEST_MASK, length, target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, source, chunk, VALUE, length, target);
        Host::And.register(code, VALUE, ACTIVE, target);
        guard_normal_zero_or_infinity(code, classification, VALUE, SCRATCH, &mut failures, target);
        match operation {
            Operation::ReciprocalExponent => reciprocal_exponent(code, operand.format, target),
            Operation::LogarithmExponent => {
                logarithm_exponent(code, operand.format, &mut failures, target)
            }
        }
        load_z_chunk(code, operand.destination, chunk, TEST_MASK, length, target);
        Host::And.register(code, VALUE, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, TEST_MASK, target);
        Host::Or.register(code, VALUE, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, VALUE, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
