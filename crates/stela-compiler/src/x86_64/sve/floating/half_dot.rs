//! Guarded streaming Half dot and widening with one transactional Z/FPSR commit.
//!
//! Selected Half inputs must be finite normals; other classes use the existing
//! exact whole-instruction completion. Single accumulators may also be signed
//! zero or infinity. Half products are exact Single values, so FDOT's pair add
//! and accumulator add retain their two distinct architectural roundings.

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        simd::arithmetic::Shape,
        sve::dot::{Kind, Operand, RightOperand, VectorPart},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
        },
        simd::numerical::{
            Condition, FusedOpcode, branch, emit_fma, prepare_vector_input_range, rounding_control,
            vector_half_exponent_range, widen_half_to_single,
        },
        sve::floating::classify::{
            guard_active_exception_enables, guard_normal_zero_or_infinity, prepare_classification,
        },
    },
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const RIGHT_HIGH: u8 = 2;
const LEFT_HIGH: u8 = 3;
const WIDEN_SIGN: u8 = 4;
const ZERO: u8 = 5;
const ADDEND: u8 = 6;
const WIDEN_BIAS: u8 = 7;
const CLASSIFICATION_CONSTANTS: [u8; 2] = [WIDEN_SIGN, ZERO];
const CLASSIFICATION_SCRATCH: [u8; 3] = [RIGHT_HIGH, LEFT_HIGH, WIDEN_BIAS];
const OUTPUT_SLOT: usize = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const GPR_RAX: u8 = 0;
const HALF_BYTES: usize = size_of::<u16>();
const SINGLE_DWORD_BYTES: usize = size_of::<u32>();
const SINGLE_LANES_PER_CHUNK: usize = VECTOR_CHUNK_BYTES / SINGLE_DWORD_BYTES;
const HALF_GROUP_BYTES: u8 = (SINGLE_LANES_PER_CHUNK * HALF_BYTES) as u8;
const HALF_LOW_GROUP_MASK: u32 = (1 << HALF_GROUP_BYTES) - 1;
const HALF_FULL_CHUNK_MASK: u32 = (1 << VECTOR_CHUNK_BYTES) - 1;
const BOTTOM_WORD_ORDER: u8 = 0xd8;
const TOP_WORD_ORDER: u8 = 0x8d;
const GROUP_DWORD_ORDER: u8 = 0xd8;
const EVEN_PRODUCT_ORDER: u8 = 0x88;
const ODD_PRODUCT_ORDER: u8 = 0xdd;
const REPEAT_DWORD: u8 = 0x55;
const REPEAT_LOW_DWORD: u8 = 0;
const REPEAT_LOW_WORD: u8 = 0;
const HALF_TO_SINGLE_BIAS: u32 = (Format::Single.exponent_bias() - Format::Half.exponent_bias())
    << Format::Single.fraction_bits();
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const MOV_RAX_IMMEDIATE: &[u8] = &[0x48, 0xb8];
const BOTTOM_HALF_BYTES: [u8; 8] = [0, 1, 4, 5, 8, 9, 12, 13];
const TOP_HALF_BYTES: [u8; 8] = [2, 3, 6, 7, 10, 11, 14, 15];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const SHR_EAX_IMMEDIATE: &[u8] = &[0xc1, 0xe8];
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const MULPS: &[u8] = &[0x0f, 0x59];
const ADDPS: &[u8] = &[0x0f, 0x58];
const SUBPS: &[u8] = &[0x0f, 0x5c];
const SHUFPS: &[u8] = &[0x0f, 0xc6];
const VZEROUPPER: &[u8] = &[0xc5, 0xf8, 0x77];

/// Candidate selection remains explicit so research and production share the
/// same qualified kernel implementations.
#[derive(Debug, Clone, Copy, Default)]
pub(in crate::x86_64) struct Recipe {
    pub half_convert: bool,
    pub byte_shuffle: bool,
    pub fused_widening: bool,
}

fn register(code: &mut Vec<u8>, opcode: &[u8], destination: u8, source: u8) {
    code.extend(opcode);
    code.push(MODRM_REGISTER | destination << MODRM_REGISTER_SHIFT | source);
}

fn shuffle(code: &mut Vec<u8>, opcode: Host, vector: u8, order: u8, target: TargetCpu) {
    opcode.register(code, vector, vector, target);
    code.push(order);
}

fn reject(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    failures.push(branch(code, Condition::NotZero));
}

fn source_register(right: RightOperand) -> u8 {
    match right {
        RightOperand::Vector(register) | RightOperand::Indexed { register, .. } => register,
    }
}

/// Compact H0/H2/H4/H6 or H1/H3/H5/H7 into the low four Half fields.
fn select_part(code: &mut Vec<u8>, vector: u8, part: VectorPart, target: TargetCpu) {
    let order = match part {
        VectorPart::Bottom => BOTTOM_WORD_ORDER,
        VectorPart::Top => TOP_WORD_ORDER,
    };
    shuffle(code, Host::ShuffleLowWord, vector, order, target);
    shuffle(code, Host::ShuffleHighWord, vector, order, target);
    shuffle(code, Host::ShuffleDword, vector, GROUP_DWORD_ORDER, target);
}

fn select_sources(code: &mut Vec<u8>, operand: Operand, recipe: Recipe, target: TargetCpu) {
    match operand.kind {
        Kind::HalfDot => {
            if let RightOperand::Indexed { index, .. } = operand.right {
                // Each selected dword is one complete pair in this chunk.
                shuffle(
                    code,
                    Host::ShuffleDword,
                    RIGHT,
                    index * REPEAT_DWORD,
                    target,
                );
            }
        }
        Kind::HalfMultiplyLong { part, .. } => {
            if recipe.byte_shuffle {
                let selector = match part {
                    VectorPart::Bottom => BOTTOM_HALF_BYTES,
                    VectorPart::Top => TOP_HALF_BYTES,
                };
                code.extend(MOV_RAX_IMMEDIATE);
                code.extend(u64::from_le_bytes(selector).to_le_bytes());
                Host::MoveGprQword.append(code, target);
                code.push(MODRM_REGISTER | RIGHT_HIGH << MODRM_REGISTER_SHIFT | GPR_RAX);
                // The upper selector can repeat: widening consumes only low64.
                Host::UnpackLowQword.register(code, RIGHT_HIGH, RIGHT_HIGH, target);
                Host::ByteShuffle.register(code, LEFT, RIGHT_HIGH, target);
            } else {
                select_part(code, LEFT, part, target);
            }
            match operand.right {
                RightOperand::Vector(_) if recipe.byte_shuffle => {
                    Host::ByteShuffle.register(code, RIGHT, RIGHT_HIGH, target);
                }
                RightOperand::Vector(_) => select_part(code, RIGHT, part, target),
                RightOperand::Indexed { index, .. } => {
                    if index != 0 {
                        ShiftOpcode::RightBytes.emit(code, RIGHT, index * HALF_BYTES as u8);
                    }
                    shuffle(code, Host::ShuffleLowWord, RIGHT, REPEAT_LOW_WORD, target);
                }
            }
        }
        _ => unreachable!("only Half forms enter selected source handling"),
    }
}

fn prepare_widening(code: &mut Vec<u8>, target: TargetCpu) {
    Host::Xor.register(code, ZERO, ZERO, target);
    code.push(MOV_EAX_IMMEDIATE);
    code.extend(HALF_TO_SINGLE_BIAS.to_le_bytes());
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | WIDEN_BIAS << MODRM_REGISTER_SHIFT | GPR_RAX);
    shuffle(
        code,
        Host::ShuffleDword,
        WIDEN_BIAS,
        REPEAT_LOW_DWORD,
        target,
    );
}

fn widen(code: &mut Vec<u8>, vector: u8, recipe: Recipe, target: TargetCpu) {
    if recipe.half_convert {
        Host::ConvertHalfToSingle.register(code, vector, vector, target);
    } else {
        widen_half_to_single(code, vector, vector, WIDEN_SIGN, ZERO, WIDEN_BIAS);
    }
}

fn dot(code: &mut Vec<u8>, operand: Operand, recipe: Recipe, target: TargetCpu) {
    Host::MoveAligned.register(code, LEFT_HIGH, LEFT, target);
    ShiftOpcode::RightBytes.emit(code, LEFT_HIGH, HALF_GROUP_BYTES);
    let indexed = matches!(operand.right, RightOperand::Indexed { .. });
    if !indexed {
        Host::MoveAligned.register(code, RIGHT_HIGH, RIGHT, target);
        ShiftOpcode::RightBytes.emit(code, RIGHT_HIGH, HALF_GROUP_BYTES);
    }
    if !recipe.half_convert {
        prepare_widening(code, target);
    }
    for vector in [LEFT, RIGHT, LEFT_HIGH] {
        widen(code, vector, recipe, target);
    }
    if !indexed {
        widen(code, RIGHT_HIGH, recipe, target);
    }
    register(code, MULPS, LEFT, RIGHT);
    register(
        code,
        MULPS,
        LEFT_HIGH,
        if indexed { RIGHT } else { RIGHT_HIGH },
    );
    Host::MoveAligned.register(code, RIGHT_HIGH, LEFT, target);
    register(code, SHUFPS, LEFT, LEFT_HIGH);
    code.push(EVEN_PRODUCT_ORDER);
    register(code, SHUFPS, RIGHT_HIGH, LEFT_HIGH);
    code.push(ODD_PRODUCT_ORDER);
    register(code, ADDPS, LEFT, RIGHT_HIGH);
    // The preceding ADDPS is the architectural FPDot rounding. This ADDPS is
    // a separate FPAdd; never combine either with an accumulator FMA.
    register(code, ADDPS, LEFT, ADDEND);
}

fn multiply_long(code: &mut Vec<u8>, subtract: bool, recipe: Recipe, target: TargetCpu) {
    if !recipe.half_convert {
        prepare_widening(code, target);
    }
    for vector in [LEFT, RIGHT] {
        widen(code, vector, recipe, target);
    }
    if recipe.fused_widening {
        emit_fma(
            code,
            Format::Single,
            Shape::Vector128,
            if subtract {
                FusedOpcode::NegativeMultiplyAdd
            } else {
                FusedOpcode::MultiplyAdd
            },
            target,
        );
    } else {
        register(code, MULPS, LEFT, RIGHT);
        if subtract {
            register(code, SUBPS, ADDEND, LEFT);
            Host::MoveAligned.register(code, LEFT, ADDEND, target);
        } else {
            register(code, ADDPS, LEFT, ADDEND);
        }
    }
}

pub(in crate::x86_64) fn emit_candidate(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
    recipe: Recipe,
) -> Result<bool, CompileError> {
    if !matches!(operand.kind, Kind::HalfDot | Kind::HalfMultiplyLong { .. }) {
        return Ok(false);
    }
    if operand.element_size != ElementSize::Word {
        return Err(CompileError("Half numerical outputs must be Single".into()));
    }
    if recipe.half_convert && !target.supports(TargetCpu::F16c)
        || recipe.fused_widening && !target.supports(TargetCpu::Fma)
        || recipe.byte_shuffle && !target.supports(TargetCpu::Ssse3)
    {
        return Err(CompileError(
            "Half candidate host capability unavailable".into(),
        ));
    }
    if recipe.half_convert || recipe.fused_widening {
        code.extend(VZEROUPPER);
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
    if features.full_a64() {
        Host::EqualDword.register(code, LEFT, LEFT, target);
        guard_active_exception_enables(code, LEFT, features, &mut failures, target);
    }
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.left, chunk, LEFT, length, target);
        load_z_chunk(
            code,
            source_register(operand.right),
            chunk,
            RIGHT,
            length,
            target,
        );
        select_sources(code, operand, recipe, target);
        prepare_vector_input_range(code, Format::Half);
        let selected_mask = if operand.kind == Kind::HalfDot {
            HALF_FULL_CHUNK_MASK
        } else {
            HALF_LOW_GROUP_MASK
        };
        for source in [LEFT, RIGHT] {
            vector_half_exponent_range(code, source, selected_mask);
            reject(code, &mut failures);
        }
        load_z_chunk(code, operand.destination, chunk, ADDEND, length, target);
        let classification =
            prepare_classification(code, Format::Single, CLASSIFICATION_CONSTANTS, target);
        guard_normal_zero_or_infinity(
            code,
            classification,
            ADDEND,
            CLASSIFICATION_SCRATCH,
            &mut failures,
            target,
        );
        match operand.kind {
            Kind::HalfDot => dot(code, operand, recipe, target),
            Kind::HalfMultiplyLong { subtract, .. } => {
                multiply_long(code, subtract, recipe, target)
            }
            _ => unreachable!("integer dot rejected before emission"),
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

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    // These two vector lengths have source-bound, paired mapping measurements.
    // Other lengths retain the existing mapping until separately qualified.
    const QUALIFIED_MAPPING_LENGTHS: [usize; 2] = [16, 64];
    let mut recipe = Recipe::default();
    if QUALIFIED_MAPPING_LENGTHS.contains(&length.bytes()) {
        match operand.kind {
            Kind::HalfMultiplyLong { .. }
                if target.supports(TargetCpu::F16c) && target.supports(TargetCpu::Fma) =>
            {
                recipe.half_convert = true;
                recipe.fused_widening = true;
            }
            Kind::HalfDot
                if matches!(operand.right, RightOperand::Vector(_))
                    && target.supports(TargetCpu::F16c) =>
            {
                recipe.half_convert = true;
            }
            _ => {}
        }
    }
    emit_candidate(code, operand, length, features, pc, target, recipe)
}

#[cfg(test)]
mod tests;
