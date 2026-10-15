//! Exact normal IEEE Half widening without host FP controls.
//! The common entry owns availability; exceptional sources take whole-instruction completion.

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures, precision::PrecisionRounding},
        scalable::{ElementSize, VectorLength},
        sve::floating::conversion::{Kind, Operand, Placement},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};

const RESULT: u8 = 0;
const ACTIVE: u8 = 1;
const SCRATCH: u8 = 2;
const OLD_DESTINATION: u8 = 3;
const HALF_MAXIMUM_EXPONENT: u8 = 4;
const VALIDITY: u8 = 5;
const SINGLE_BIAS: u8 = 6;
const INACTIVE_HALF_ONE: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const GPR_RCX: u8 = 1;
const GPR_RAX: u8 = 0;
const MOV_ECX_IMMEDIATE: &[u8] = &[0xb9];
const CMP_EAX_IMMEDIATE8: &[u8] = &[0x83, 0xf8];
const JNE_REL32: &[u8] = &[0x0f, 0x85];
const CVTPS2PD_XMM0_XMM0: &[u8] = &[0x0f, 0x5a, 0xc0];
const REPEAT_DWORD: u8 = 0;
const COMPACT_LOW_QWORD_DWORDS: u8 = 0x88;
const DWORD_SIGN_POSITION: u8 = u32::BITS as u8 - 1;
const HALF_BITS: u8 = u16::BITS as u8;
const HALF_EXPONENT_BITS: u8 = (Format::Half.bits() - Format::Half.fraction_bits() - 1) as u8;
const HALF_EXPONENT_MAXIMUM: u32 = (1 << HALF_EXPONENT_BITS) - 1;
const HALF_EXPONENT_TO_BOTTOM: u8 = u32::BITS as u8 - HALF_EXPONENT_BITS;
const HALF_MAGNITUDE_TO_TOP: u8 = u32::BITS as u8 - HALF_BITS + 1;
const HALF_TO_SINGLE_FRACTION: u8 =
    (Format::Single.fraction_bits() - Format::Half.fraction_bits()) as u8;
const HALF_TO_SINGLE_BIAS: u32 = (Format::Single.exponent_bias() - Format::Half.exponent_bias())
    << Format::Single.fraction_bits();
const HALF_ONE: u32 = Format::Half.exponent_bias() << Format::Half.fraction_bits();
const ALL_DWORDS_NORMAL: u8 = (1 << (u128::BITS / u32::BITS)) - 1;

fn broadcast(code: &mut Vec<u8>, register: u8, value: u32, target: TargetCpu) {
    code.extend(MOV_ECX_IMMEDIATE);
    code.extend(value.to_le_bytes());
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (register << MODRM_REGISTER_SHIFT) | GPR_RCX);
    Host::ShuffleDword.register(code, register, register, target);
    code.push(REPEAT_DWORD);
}

/// Preserve four dword-low16 inputs and the repeated31 exponent constant;
/// clobber three distinct scratch XMMs, EAX and flags. Append a shared-finish
/// failure offset for any exponent outside1..30, with no frame/state effects.
pub(in crate::x86_64) fn guard_normal_half_fields(
    code: &mut Vec<u8>,
    input: u8,
    maximum_exponent: u8,
    scratch: [u8; 3],
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    assert_ne!(input, maximum_exponent);
    for (index, register) in scratch.iter().enumerate() {
        assert!(*register != input && *register != maximum_exponent);
        assert!(!scratch[..index].contains(register));
    }
    let [exponent, validity, zero] = scratch;
    Host::MoveAligned.register(code, exponent, input, target);
    ShiftOpcode::LeftDword.emit(code, exponent, HALF_MAGNITUDE_TO_TOP);
    ShiftOpcode::RightDword.emit(code, exponent, HALF_EXPONENT_TO_BOTTOM);
    Host::MoveAligned.register(code, validity, maximum_exponent, target);
    Host::GreaterDword.register(code, validity, exponent, target);
    Host::Xor.register(code, zero, zero, target);
    Host::GreaterDword.register(code, exponent, zero, target);
    Host::And.register(code, exponent, validity, target);
    Host::DwordSignMask.register(code, GPR_RAX, exponent, target);
    code.extend(CMP_EAX_IMMEDIATE8);
    code.push(ALL_DWORDS_NORMAL);
    code.extend(JNE_REL32);
    failures.push(code.len());
    code.extend(0_i32.to_le_bytes());
}

/// Compute-only extraction of the mature SIMD precision widening projection.
/// Input: four normal IEEE Half encodings in the low16 bits of each dword.
/// Output: four exact Single encodings. `bias` already holds the repeated H→S
/// exponent-bias difference. No frame/state/rounding/status/commit operations.
pub(in crate::x86_64) fn normal_half_to_single_fields(
    code: &mut Vec<u8>,
    input: u8,
    sign: u8,
    bias: u8,
    target: TargetCpu,
) {
    assert!(input != sign && input != bias && sign != bias);
    Host::MoveAligned.register(code, sign, input, target);
    ShiftOpcode::LeftDword.emit(code, sign, HALF_BITS);
    ShiftOpcode::ArithmeticDword.emit(code, sign, DWORD_SIGN_POSITION);
    ShiftOpcode::LeftDword.emit(code, sign, DWORD_SIGN_POSITION);
    ShiftOpcode::LeftDword.emit(code, input, HALF_MAGNITUDE_TO_TOP);
    ShiftOpcode::RightDword.emit(code, input, HALF_MAGNITUDE_TO_TOP - HALF_TO_SINGLE_FRACTION);
    Host::AddDword.register(code, input, bias, target);
    Host::Or.register(code, input, sign, target);
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let (destination, placement) = match operand.kind {
        Kind::Precision {
            source: Format::Half,
            destination: Format::Single,
            rounding: PrecisionRounding::Fpcr,
            placement: placement @ (Placement::Low | Placement::UpperSource),
        } => (Format::Single, placement),
        Kind::Precision {
            source: Format::Half,
            destination: Format::Double,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::Low,
        } => (Format::Double, Placement::Low),
        _ => return Ok(false),
    };
    let element = if destination == Format::Double {
        ElementSize::Doubleword
    } else {
        ElementSize::Word
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    broadcast(code, HALF_MAXIMUM_EXPONENT, HALF_EXPONENT_MAXIMUM, target);
    broadcast(code, SINGLE_BIAS, HALF_TO_SINGLE_BIAS, target);
    broadcast(code, INACTIVE_HALF_ONE, HALF_ONE, target);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            element,
            ACTIVE,
            SCRATCH,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, operand.source, chunk, RESULT, length, target);
        if destination == Format::Double {
            Host::ShuffleDword.register(code, RESULT, RESULT, target);
            code.push(COMPACT_LOW_QWORD_DWORDS);
        }
        if placement == Placement::UpperSource {
            ShiftOpcode::RightDword.emit(code, RESULT, HALF_BITS);
        } else {
            ShiftOpcode::LeftDword.emit(code, RESULT, HALF_BITS);
            ShiftOpcode::RightDword.emit(code, RESULT, HALF_BITS);
        }
        Host::MoveAligned.register(code, SCRATCH, ACTIVE, target);
        if destination == Format::Double {
            Host::ShuffleDword.register(code, SCRATCH, SCRATCH, target);
            code.push(COMPACT_LOW_QWORD_DWORDS);
        }
        // Neutralize inactive values before the normal-only guard. Their exact
        // one results are removed again by the architectural destination mask.
        Host::And.register(code, RESULT, SCRATCH, target);
        Host::AndNot.register(code, SCRATCH, INACTIVE_HALF_ONE, target);
        Host::Or.register(code, RESULT, SCRATCH, target);
        guard_normal_half_fields(
            code,
            RESULT,
            HALF_MAXIMUM_EXPONENT,
            [SCRATCH, VALIDITY, OLD_DESTINATION],
            &mut failures,
            target,
        );
        normal_half_to_single_fields(code, RESULT, SCRATCH, SINGLE_BIAS, target);
        if destination == Format::Double {
            code.extend(CVTPS2PD_XMM0_XMM0);
        }
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            OLD_DESTINATION,
            length,
            target,
        );
        Host::And.register(code, RESULT, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, OLD_DESTINATION, target);
        Host::Or.register(code, RESULT, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
