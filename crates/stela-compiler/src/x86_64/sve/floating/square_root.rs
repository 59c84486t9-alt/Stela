//! SVE FSQRT: SQRTPS/SQRTPD for positive normals, +0 and +infinity.
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
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
        simd::numerical::rounding_control,
        sve::floating::classify::{
            guard_active_exception_enables, guard_normal_zero_or_infinity, prepare_classification,
        },
    },
};
use alloc::vec::Vec;

const VALUE: u8 = 0;
const ACTIVE: u8 = 2;
const SCRATCH: [u8; 3] = [3, 4, 5];
const OLD_DESTINATION: u8 = SCRATCH[0];
const MASKS: [u8; 2] = [6, 7];
const OUTPUT_SLOT: usize = 0;
const GPR_RAX: u8 = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const PACKED_DOUBLE_PREFIX: u8 = 0x66;
const SQRT_PACKED: &[u8] = &[0x0f, 0x51];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const TEST_EAX_IMMEDIATE: u8 = 0xa9;
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const SHR_EAX_IMMEDIATE: &[u8] = &[0xc1, 0xe8];
const DOUBLE_LOW_SIGN_DWORD: u32 = 1;
const DOUBLE_HIGH_SIGN_DWORD: u32 = 3;
const DOUBLE_SIGN_LANES: u32 = (1 << DOUBLE_LOW_SIGN_DWORD) | (1 << DOUBLE_HIGH_SIGN_DWORD);
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;

fn reject(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    code.extend(JNZ_REL32);
    failures.push(code.len());
    code.extend(0_i32.to_le_bytes());
}

fn guard_nonnegative(
    code: &mut Vec<u8>,
    format: Format,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    Host::DwordSignMask.register(code, GPR_RAX, VALUE, target);
    if format == Format::Double {
        // MOVMSKPS sees all four dwords. Only high dwords contain Double signs;
        // the low-dword fraction sign bits must not reject positive operands.
        code.push(TEST_EAX_IMMEDIATE);
        code.extend(DOUBLE_SIGN_LANES.to_le_bytes());
    } else {
        code.extend(TEST_EAX_EAX);
    }
    reject(code, failures);
}

fn square_root(code: &mut Vec<u8>, format: Format) {
    if format == Format::Double {
        code.push(PACKED_DOUBLE_PREFIX);
    }
    code.extend(SQRT_PACKED);
    code.push(MODRM_REGISTER | (VALUE << MODRM_REGISTER_SHIFT) | VALUE);
}

/// Predicated merging FSQRT over a positive exact/rounded IEEE domain. Shared
/// rounding_control maps raw guest RMode; AH does not force RNE for FPSqrt.
/// No architectural output/status commits before the final guard succeeds.
/// Clobbers volatile RAX/RCX/RDX, host flags and XMM0..7, preserving RDI/R15 and
/// caller MXCSR through both accepted and exceptional whole-instruction exits.
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
    if operand.kind != Kind::SquareRoot || operand.shape != ResultShape::Vector {
        return Ok(false);
    }
    let (Inputs::Unary { source }, Some(predicate)) = (operand.inputs, operand.predicate) else {
        return Ok(false);
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    rounding_control(code);
    numerical::install_mxcsr(code, &frame);
    let classification = prepare_classification(code, operand.format, MASKS, target);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            predicate,
            chunk,
            element,
            ACTIVE,
            OLD_DESTINATION,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, source, chunk, VALUE, length, target);
        Host::And.register(code, VALUE, ACTIVE, target);
        guard_normal_zero_or_infinity(code, classification, VALUE, SCRATCH, &mut failures, target);
        guard_nonnegative(code, operand.format, &mut failures, target);
        square_root(code, operand.format);
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            OLD_DESTINATION,
            length,
            target,
        );
        Host::And.register(code, VALUE, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, OLD_DESTINATION, target);
        Host::Or.register(code, VALUE, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, VALUE, target);
    }
    numerical::capture_status(code, &frame);
    code.extend(TEST_ECX_IMMEDIATE);
    code.extend(MXCSR_OTHER_STATUS.to_le_bytes());
    reject(code, &mut failures);
    code.extend(MOV_EAX_ECX);
    code.push(AND_EAX_IMMEDIATE);
    code.extend(MXCSR_INEXACT.to_le_bytes());
    code.extend(SHR_EAX_IMMEDIATE);
    code.push(MXCSR_TO_FPSR_INEXACT_SHIFT);
    numerical::add_fpsr(code, &frame);
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
