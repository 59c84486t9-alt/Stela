//! Guarded normal Single/Double binary arithmetic with instruction-wide staging.
//!
//! Exceptional inputs/results and Half retain whole-instruction completion.
//! The shared numerical frame owns MXCSR restoration and the only guest commit.

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{BinaryOperation, Format, features::NumericalFeatures},
        scalable::{ElementSize, VectorLength},
        simd::arithmetic::Shape,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::{
            ArithmeticOpcode, emit_opcode_to, prepare_vector_input_range,
            prepare_vector_result_range, rounding_control, vector_exponent_range,
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const MASK_SCRATCH: u8 = 2;
const CONSTANT_SCRATCH: u8 = 3;
const ACTIVE: u8 = 6;
const OLD_DESTINATION: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const GPR_RAX: u8 = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const REPEAT_LOW_DWORD: u8 = 0;
const BENIGN_LEFT_EXPONENT_INCREMENT: u32 = 1;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;
const REL32_BYTES: usize = size_of::<i32>();
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const MOV_RAX_IMMEDIATE: &[u8] = &[0x48, 0xb8];
const SHR_EAX_IMMEDIATE: &[u8] = &[0xc1, 0xe8];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];

fn reject(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    code.extend(JNZ_REL32);
    failures.push(code.len());
    code.extend([0; REL32_BYTES]);
}

/// Replace inactive lanes with exact benign normals before any host arithmetic.
/// Left=2 and right=1 make every admitted operation exact in inactive lanes.
fn benign_inactive(code: &mut Vec<u8>, format: Format, input: u8, target: TargetCpu) {
    let increment = if input == LEFT {
        BENIGN_LEFT_EXPONENT_INCREMENT
    } else {
        0
    };
    let bits = u64::from(format.exponent_bias() + increment) << format.fraction_bits();
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
    Host::MoveAligned.register(code, MASK_SCRATCH, ACTIVE, target);
    Host::AndNot.register(code, MASK_SCRATCH, CONSTANT_SCRATCH, target);
    Host::And.register(code, input, ACTIVE, target);
    Host::Or.register(code, input, MASK_SCRATCH, target);
}

fn inputs(operand: Operand) -> Option<(BinaryOperation, u8, u8)> {
    let Inputs::Binary {
        left: Source::Vector(left),
        right: Source::Vector(right),
    } = operand.inputs
    else {
        return None;
    };
    if operand.shape != ResultShape::Vector {
        return None;
    }
    // The first batch owns forward destructive forms and unpredicated ADD/SUB/MUL.
    // Reverse forms retain the same exact fallback until their own admission.
    if operand.predicate.is_some() && left != operand.destination {
        return None;
    }
    let operation = match operand.kind {
        Kind::Binary(
            operation @ (BinaryOperation::Add
            | BinaryOperation::Subtract
            | BinaryOperation::Multiply),
        ) => operation,
        Kind::Binary(BinaryOperation::Divide) if operand.predicate.is_some() => {
            BinaryOperation::Divide
        }
        _ => return None,
    };
    Some((operation, left, right))
}

fn arithmetic_opcode(operation: BinaryOperation) -> ArithmeticOpcode {
    match operation {
        BinaryOperation::Add => ArithmeticOpcode::Add,
        BinaryOperation::Subtract => ArithmeticOpcode::Subtract,
        BinaryOperation::Multiply => ArithmeticOpcode::Multiply,
        BinaryOperation::Divide => ArithmeticOpcode::Divide,
        _ => unreachable!("validated core binary operation"),
    }
}

/// Emit seven core vector-register forms within a conservative normal domain.
/// Unsupported shapes/formats leave `code` untouched. The caller owns immutable
/// feature admission and streaming entry checks. RDI/R15, guest NZCV and every
/// source survive; RAX/RCX/RDX, flags and XMM0..7 are caller-volatile.
pub(crate) fn emit(
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
    let Some((operation, left, right)) = inputs(operand) else {
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
    let mut failures = Vec::new();
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
        load_z_chunk(code, right, chunk, RIGHT, length, target);
        if operand.predicate.is_some() {
            benign_inactive(code, operand.format, LEFT, target);
            benign_inactive(code, operand.format, RIGHT, target);
        }
        prepare_vector_input_range(code, operand.format);
        for input in [LEFT, RIGHT] {
            vector_exponent_range(code, operand.format, Shape::Vector128, input);
            reject(code, &mut failures);
        }
        emit_opcode_to(
            code,
            operand.format,
            Shape::Vector128,
            arithmetic_opcode(operation),
            LEFT,
            RIGHT,
        );
        prepare_vector_result_range(code);
        vector_exponent_range(code, operand.format, Shape::Vector128, LEFT);
        reject(code, &mut failures);
        if operand.predicate.is_some() {
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
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
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
