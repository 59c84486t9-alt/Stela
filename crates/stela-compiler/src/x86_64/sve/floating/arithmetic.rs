//! SVE single/double binary arithmetic on normal values, staged per
//! instruction: the core vector forms ([`emit_core`]) and the immediate,
//! indexed and reverse forms with FABD and FMULX ([`emit_operand_forms`]).
//! Half precision and exceptional values use software completion. With DAZ
//! clear, a normal output with only inexact status implies no denormal
//! operand.
use crate::x86_64::asm::Code;

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
            numerical::{self, Environment, Frame, Output},
            read_predicate_mask,
        },
        simd::numerical::{
            ArithmeticOpcode, emit_opcode_to, prepare_vector_input_range,
            prepare_vector_result_range, rounding_control, vector_exponent_range,
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

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

fn reject(code: &mut Code, failures: &mut Vec<usize>) {
    code.extend(JNZ_REL32);
    failures.push(code.len());
    code.extend([0; REL32_BYTES]);
}

/// Broadcast `bits` to every lane of `destination`.
fn broadcast_bits(code: &mut Code, format: Format, bits: u64, destination: u8, target: TargetCpu) {
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

/// Replace inactive lanes with exact benign normals before any host arithmetic.
/// Left=2 and right=1 make every admitted operation exact in inactive lanes.
fn benign_inactive(code: &mut Code, format: Format, input: u8, target: TargetCpu) {
    let increment = if input == LEFT {
        BENIGN_LEFT_EXPONENT_INCREMENT
    } else {
        0
    };
    let bits = u64::from(format.exponent_bias() + increment) << format.fraction_bits();
    broadcast_bits(code, format, bits, CONSTANT_SCRATCH, target);
    Host::MoveAligned.register(code, MASK_SCRATCH, ACTIVE, target);
    Host::AndNot.register(code, MASK_SCRATCH, CONSTANT_SCRATCH, target);
    Host::And.register(code, input, ACTIVE, target);
    Host::Or.register(code, input, MASK_SCRATCH, target);
}

fn arithmetic_opcode(operation: BinaryOperation) -> ArithmeticOpcode {
    match operation {
        BinaryOperation::Add => ArithmeticOpcode::Add,
        BinaryOperation::Subtract | BinaryOperation::AbsoluteDifference => {
            ArithmeticOpcode::Subtract
        }
        BinaryOperation::Multiply | BinaryOperation::MultiplyExtended => ArithmeticOpcode::Multiply,
        BinaryOperation::Divide => ArithmeticOpcode::Divide,
        _ => unreachable!("the input selectors validated the binary operation"),
    }
}

/// The lanes element-sized for `format`, or `None` for Half.
fn element(format: Format) -> Option<ElementSize> {
    match format {
        Format::Single => Some(ElementSize::Word),
        Format::Double => Some(ElementSize::Doubleword),
        Format::Half => None,
    }
}

/// Load the active-lane mask for `chunk` into ACTIVE: the governing
/// predicate's lanes, or all lanes when unpredicated under full A64 rules.
fn active_lanes(
    code: &mut Code,
    operand: Operand,
    element: ElementSize,
    chunk: usize,
    length: VectorLength,
    features: NumericalFeatures,
    target: TargetCpu,
) {
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
}

/// Merge LEFT into the old destination's inactive lanes when predicated.
fn merge_inactive(
    code: &mut Code,
    operand: Operand,
    chunk: usize,
    length: VectorLength,
    target: TargetCpu,
) {
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
}

/// Reject any status other than inexact, add inexact to FPSR and commit.
fn finish_status(
    code: &mut Code,
    frame: &Frame,
    failures: &mut Vec<usize>,
    pc: GuestAddress,
    target: TargetCpu,
) {
    numerical::capture_status(code, frame);
    code.extend(TEST_ECX_IMMEDIATE);
    code.extend(MXCSR_OTHER_STATUS.to_le_bytes());
    reject(code, failures);
    code.extend(MOV_EAX_ECX);
    code.push(AND_EAX_IMMEDIATE);
    code.extend(MXCSR_INEXACT.to_le_bytes());
    code.extend(SHR_EAX_IMMEDIATE);
    code.push(MXCSR_TO_FPSR_INEXACT_SHIFT);
    numerical::add_fpsr(code, frame);
    numerical::finish(code, frame, failures, pc, target);
}

fn core_inputs(operand: Operand) -> Option<(BinaryOperation, u8, u8)> {
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
    // The core forms are the forward destructive forms and unpredicated
    // ADD/SUB/MUL; reverse forms go to [`emit_operand_forms`].
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

/// Emit seven core vector-register forms within a conservative normal domain.
/// Unsupported shapes/formats leave `code` untouched. The caller owns immutable
/// feature admission and streaming entry checks. RDI/R15, guest NZCV and every
/// source survive; RAX/RCX/RDX, flags and XMM0..7 are caller-volatile.
pub(crate) fn emit_core(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Some(element) = element(operand.format) else {
        return Ok(false);
    };
    let Some((operation, left, right)) = core_inputs(operand) else {
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
        active_lanes(code, operand, element, chunk, length, features, target);
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
        merge_inactive(code, operand, chunk, length, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
    }
    finish_status(code, &frame, &mut failures, pc, target);
    Ok(true)
}

/// Decoded sources already encode reversed operand order. With both source
/// registers aliased, forward and reverse forms decode identically.
fn operand_form_inputs(operand: Operand) -> Option<(BinaryOperation, Source, Source)> {
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

/// Indexed inputs select one lane separately in each guest 128-bit segment.
/// No source is loaded from a previously staged destination chunk.
fn load_source(
    code: &mut Code,
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
fn absolute_result(code: &mut Code, format: Format, target: TargetCpu) {
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

/// Emit immediate/indexed/reverse arithmetic and finite FABD/FMULX mappings.
/// Unsupported shapes/formats leave `code` untouched. The caller owns immutable
/// feature admission and streaming entry checks. RDI/R15, guest NZCV and every
/// source survive; RAX/RCX/RDX, flags and XMM0..7 are caller-volatile.
pub(in crate::x86_64) fn emit_operand_forms(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Some(element) = element(operand.format) else {
        return Ok(false);
    };
    let Some((operation, left, right)) = operand_form_inputs(operand) else {
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
        active_lanes(code, operand, element, chunk, length, features, target);
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
        merge_inactive(code, operand, chunk, length, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
    }
    finish_status(code, &frame, &mut failures, pc, target);
    Ok(true)
}
