//! Fused streaming arithmetic: checked FMA3 or an exact-product SSE2 domain.
//!
//! All inputs are read before the sole instruction-wide destination commit.
//! Exceptional inputs/results and Half use exact whole-instruction completion.
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures, fused::FusedOperation},
        scalable::{BITS_PER_BYTE, ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        simd::arithmetic::Shape,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::{
            ArithmeticOpcode, FusedOpcode, VZEROUPPER, emit_fma, emit_opcode_to,
            prepare_vector_input_range, prepare_vector_result_range, rounding_control,
            vector_exponent_range,
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const MASK_SCRATCH: u8 = 2;
const CONSTANT_SCRATCH: u8 = 3;
const ADDEND: u8 = 6;
const ACTIVE: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const GPR_RAX: u8 = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const SINGLE_BROADCAST_STRIDE: u8 = 0x55;
const DOUBLE_LOW_BROADCAST: u8 = 0x44;
const DOUBLE_HIGH_BROADCAST: u8 = 0xee;
const REPEAT_LOW_DWORD: u8 = 0;
const BENIGN_ADDEND_INCREMENT: u32 = 1;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const MOV_RAX_IMMEDIATE: &[u8] = &[0x48, 0xb8];
const TEST_ECX_ECX: &[u8] = &[0x85, 0xc9];
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const SHR_EAX_IMMEDIATE: &[u8] = &[0xc1, 0xe8];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];

fn reject(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    code.extend(JNZ_REL32);
    failures.push(code.len());
    code.extend(0_i32.to_le_bytes());
}

fn broadcast(code: &mut Vec<u8>, format: Format, bits: u64, target: TargetCpu) {
    if format == Format::Single {
        code.push(MOV_EAX_IMMEDIATE);
        code.extend((bits as u32).to_le_bytes());
    } else {
        code.extend(MOV_RAX_IMMEDIATE);
        code.extend(bits.to_le_bytes());
    }
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (CONSTANT_SCRATCH << MODRM_REGISTER_SHIFT) | GPR_RAX);
    if format == Format::Single {
        Host::ShuffleDword.register(code, CONSTANT_SCRATCH, CONSTANT_SCRATCH, target);
        code.push(REPEAT_LOW_DWORD);
    } else {
        Host::UnpackLowQword.register(code, CONSTANT_SCRATCH, CONSTANT_SCRATCH, target);
    }
}

/// Inactive 2 + 1*1 and every signed variant are exact normal results.
fn benign_inactive(code: &mut Vec<u8>, format: Format, input: u8, target: TargetCpu) {
    let increment = if input == ADDEND {
        BENIGN_ADDEND_INCREMENT
    } else {
        0
    };
    let bits = u64::from(format.exponent_bias() + increment) << format.fraction_bits();
    broadcast(code, format, bits, target);
    Host::MoveAligned.register(code, MASK_SCRATCH, ACTIVE, target);
    Host::AndNot.register(code, MASK_SCRATCH, CONSTANT_SCRATCH, target);
    Host::And.register(code, input, ACTIVE, target);
    Host::Or.register(code, input, MASK_SCRATCH, target);
}

fn load_right(
    code: &mut Vec<u8>,
    source: Source,
    format: Format,
    chunk: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    let register = match source {
        Source::Vector(register) | Source::Indexed { register, .. } => register,
        Source::ImmediateBits(_) => unreachable!("validated fused register source"),
    };
    load_z_chunk(code, register, chunk, RIGHT, length, target);
    if let Source::Indexed { index, .. } = source {
        let order = match format {
            Format::Single => index * SINGLE_BROADCAST_STRIDE,
            Format::Double => {
                if index == 0 {
                    DOUBLE_LOW_BROADCAST
                } else {
                    DOUBLE_HIGH_BROADCAST
                }
            }
            Format::Half => unreachable!("Half uses exact completion"),
        };
        Host::ShuffleDword.register(code, RIGHT, RIGHT, target);
        code.push(order);
    }
}

fn negate_baseline(
    code: &mut Vec<u8>,
    operation: FusedOperation,
    format: Format,
    target: TargetCpu,
) {
    if !operation.negate_left() && !operation.negate_addend() {
        return;
    }
    Host::EqualDword.register(code, MASK_SCRATCH, MASK_SCRATCH, target);
    let shift = if format == Format::Single {
        ShiftOpcode::LeftDword
    } else {
        ShiftOpcode::LeftQword
    };
    shift.emit(code, MASK_SCRATCH, (format.bits() - 1) as u8);
    if operation.negate_left() {
        Host::Xor.register(code, LEFT, MASK_SCRATCH, target);
    }
    if operation.negate_addend() {
        Host::Xor.register(code, ADDEND, MASK_SCRATCH, target);
    }
}

fn fused_opcode(operation: FusedOperation) -> FusedOpcode {
    match operation {
        FusedOperation::Add => FusedOpcode::MultiplyAdd,
        FusedOperation::Subtract => FusedOpcode::NegativeMultiplyAdd,
        FusedOperation::NegatedAdd => FusedOpcode::NegativeMultiplySubtract,
        FusedOperation::NegatedSubtract => FusedOpcode::MultiplySubtract,
    }
}

/// Emit the fourteen canonical fused forms. S/D native admission is deliberately
/// normal-only; exact completion retains all H/S/D semantics outside this domain.
/// RDI/R15 and all guest sources survive; RAX/RCX/RDX/flags/XMM0..7 are volatile.
/// TargetCpu::Fma includes usable AVX OS state. Baseline never emits VEX or FMA.
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
    let (
        Kind::Fused(operation),
        Inputs::Fused {
            addend,
            left,
            right,
        },
        ResultShape::Vector,
    ) = (operand.kind, operand.inputs, operand.shape)
    else {
        return Ok(false);
    };
    match right {
        Source::Vector(_) => {}
        Source::Indexed { index, .. }
            if usize::from(index)
                < VECTOR_CHUNK_BYTES * BITS_PER_BYTE / operand.format.bits() as usize => {}
        _ => return Ok(false),
    }
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    rounding_control(code);
    numerical::install_mxcsr(code, &frame);
    let mut failures = Vec::new();
    let native_fma = target.supports(TargetCpu::Fma);
    for chunk in 0..length.chunks() {
        if let Some(predicate) = operand.predicate {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                element,
                ACTIVE,
                MASK_SCRATCH,
                length,
                target,
            );
        } else if features.full_a64() {
            Host::EqualDword.register(code, ACTIVE, ACTIVE, target);
        }
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, left, chunk, LEFT, length, target);
        load_right(code, right, operand.format, chunk, length, target);
        load_z_chunk(code, addend, chunk, ADDEND, length, target);
        if operand.predicate.is_some() {
            for input in [LEFT, RIGHT, ADDEND] {
                benign_inactive(code, operand.format, input, target);
            }
        }
        prepare_vector_input_range(code, operand.format);
        for input in [LEFT, RIGHT, ADDEND] {
            vector_exponent_range(code, operand.format, Shape::Vector128, input);
            reject(code, &mut failures);
        }
        numerical::clear_status(code, &frame);
        if native_fma {
            emit_fma(
                code,
                operand.format,
                Shape::Vector128,
                fused_opcode(operation),
                target,
            );
            // FMA has completed; clean upper AVX state before legacy guards or any exit.
            // Every host SIMD register is caller-volatile under this backend ABI.
            code.extend(VZEROUPPER);
        } else {
            negate_baseline(code, operation, operand.format, target);
            emit_opcode_to(
                code,
                operand.format,
                Shape::Vector128,
                ArithmeticOpcode::Multiply,
                LEFT,
                RIGHT,
            );
            // An exact normal product permits a separate ADD with one rounding.
            // Any product status, including precision, rejects the entire instruction.
            numerical::capture_status(code, &frame);
            code.extend(TEST_ECX_ECX);
            reject(code, &mut failures);
            prepare_vector_result_range(code);
            vector_exponent_range(code, operand.format, Shape::Vector128, LEFT);
            reject(code, &mut failures);
            numerical::clear_status(code, &frame);
            emit_opcode_to(
                code,
                operand.format,
                Shape::Vector128,
                ArithmeticOpcode::Add,
                LEFT,
                ADDEND,
            );
        }
        prepare_vector_result_range(code);
        vector_exponent_range(code, operand.format, Shape::Vector128, LEFT);
        reject(code, &mut failures);
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
        if operand.predicate.is_some() {
            load_z_chunk(code, operand.destination, chunk, RIGHT, length, target);
            Host::And.register(code, LEFT, ACTIVE, target);
            Host::AndNot.register(code, ACTIVE, RIGHT, target);
            Host::Or.register(code, LEFT, ACTIVE, target);
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
