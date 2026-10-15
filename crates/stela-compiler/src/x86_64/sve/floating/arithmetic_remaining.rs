//! Private eleven-form extension of the guarded staged binary arithmetic kernel.
//!
//! Half and exceptional results/status retain whole-instruction completion.
//! With private DAZ=0, normal output plus only precision status excludes active
//! denormal operands; higher-priority DE suppression cannot pass both guards.
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
const REPEAT_SELECTED_DWORD: u8 = 0x55;
const SINGLE_LANES_PER_CHUNK: u8 = 4;
const DOUBLE_LANES_PER_CHUNK: u8 = 2;
const SINGLE_SIGN_SHIFT: u8 = 31;
const DOUBLE_SIGN_SHIFT: u8 = 63;
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

/// Decoded sources already express reverse operation order. The private owner
/// supplies exactly the eleven canonical forms in manifest.json. When both
/// source registers alias, forward/reverse encodings have identical operands.
fn inputs(operand: Operand) -> Option<(BinaryOperation, Source, Source)> {
    let Inputs::Binary { left, right } = operand.inputs else {
        return None;
    };
    if operand.shape != ResultShape::Vector {
        return None;
    }
    let Kind::Binary(operation) = operand.kind else {
        return None;
    };
    let owned = match (operation, left, right, operand.predicate) {
        (
            BinaryOperation::AbsoluteDifference | BinaryOperation::MultiplyExtended,
            Source::Vector(left),
            Source::Vector(_),
            Some(_),
        ) => left == operand.destination,
        (
            BinaryOperation::Add | BinaryOperation::Subtract | BinaryOperation::Multiply,
            Source::Vector(left),
            Source::ImmediateBits(_),
            Some(_),
        ) => left == operand.destination,
        (BinaryOperation::Subtract, Source::ImmediateBits(_), Source::Vector(right), Some(_)) => {
            right == operand.destination
        }
        (
            BinaryOperation::Subtract | BinaryOperation::Divide,
            Source::Vector(_),
            Source::Vector(right),
            Some(_),
        ) => right == operand.destination,
        (BinaryOperation::Multiply, Source::Vector(_), Source::Indexed { .. }, None) => true,
        _ => false,
    };
    owned.then_some((operation, left, right))
}

fn broadcast_bits(
    code: &mut Vec<u8>,
    format: Format,
    bits: u64,
    destination: u8,
    target: TargetCpu,
) {
    match format {
        Format::Single => {
            code.push(MOV_EAX_IMMEDIATE);
            code.extend((bits as u32).to_le_bytes());
        }
        Format::Double => {
            code.extend(MOV_RAX_IMMEDIATE);
            code.extend(bits.to_le_bytes());
        }
        Format::Half => unreachable!("Half remains whole-instruction completion"),
    }
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (destination << MODRM_REGISTER_SHIFT) | GPR_RAX);
    if format == Format::Single {
        Host::ShuffleDword.register(code, destination, destination, target);
        code.push(REPEAT_LOW_DWORD);
    } else {
        Host::UnpackLowQword.register(code, destination, destination, target);
    }
}

/// Indexed inputs select one lane separately in each guest 128-bit segment.
/// No source is loaded from a previously staged destination chunk.
fn load_source(
    code: &mut Vec<u8>,
    source: Source,
    format: Format,
    chunk: usize,
    destination: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    match source {
        Source::Vector(register) => {
            load_z_chunk(code, register, chunk, destination, length, target)
        }
        Source::ImmediateBits(bits) => broadcast_bits(code, format, bits, destination, target),
        Source::Indexed { register, index } => {
            load_z_chunk(code, register, chunk, destination, length, target);
            if format == Format::Single {
                debug_assert!(index < SINGLE_LANES_PER_CHUNK);
                Host::ShuffleDword.register(code, destination, destination, target);
                code.push(index * REPEAT_SELECTED_DWORD);
            } else {
                debug_assert!(format == Format::Double && index < DOUBLE_LANES_PER_CHUNK);
                let opcode = if index == 0 {
                    Host::UnpackLowQword
                } else {
                    Host::UnpackHighQword
                };
                opcode.register(code, destination, destination, target);
            }
        }
    }
}

/// FPAbs transforms the rounded subtraction result. Active NaNs fail the result
/// exponent guard before this finite-only sign clear, preserving AH NaN policy.
fn absolute_result(code: &mut Vec<u8>, format: Format, target: TargetCpu) {
    let sign_shift = if format == Format::Single {
        SINGLE_SIGN_SHIFT
    } else {
        DOUBLE_SIGN_SHIFT
    };
    let magnitude = if format == Format::Single {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    } >> 1;
    debug_assert_eq!(magnitude, (1_u64 << sign_shift) - 1);
    broadcast_bits(code, format, magnitude, MASK_SCRATCH, target);
    Host::And.register(code, LEFT, MASK_SCRATCH, target);
}

fn arithmetic_opcode(operation: BinaryOperation) -> ArithmeticOpcode {
    match operation {
        BinaryOperation::Add => ArithmeticOpcode::Add,
        BinaryOperation::Subtract | BinaryOperation::AbsoluteDifference => {
            ArithmeticOpcode::Subtract
        }
        BinaryOperation::Multiply | BinaryOperation::MultiplyExtended => ArithmeticOpcode::Multiply,
        BinaryOperation::Divide => ArithmeticOpcode::Divide,
        _ => unreachable!("private source selector validated the binary operation"),
    }
}

/// Emit immediate/indexed/reverse arithmetic and finite FABD/FMULX mappings.
/// Unsupported shapes/formats leave `code` untouched. The caller owns immutable
/// feature admission and streaming entry checks. RDI/R15, guest NZCV and every
/// source survive; RAX/RCX/RDX, flags and XMM0..7 are caller-volatile.
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
    prepare_vector_input_range(code, operand.format);
    prepare_vector_result_range(code);
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
        load_source(code, left, operand.format, chunk, LEFT, length, target);
        load_source(code, right, operand.format, chunk, RIGHT, length, target);
        if operand.predicate.is_some() {
            benign_inactive(code, operand.format, LEFT, target);
            benign_inactive(code, operand.format, RIGHT, target);
        }
        emit_opcode_to(
            code,
            operand.format,
            Shape::Vector128,
            arithmetic_opcode(operation),
            LEFT,
            RIGHT,
        );
        vector_exponent_range(code, operand.format, Shape::Vector128, LEFT);
        reject(code, &mut failures);
        if operation == BinaryOperation::AbsoluteDifference {
            absolute_result(code, operand.format, target);
        }
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
