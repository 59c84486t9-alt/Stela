//! BFDOT (classic and FEAT_EBF16) and BFMLAL/BFMLSL.
use alloc::vec::Vec;
mod classic_dot;
mod enhanced_dot;
mod multiply_long;

use crate::{
    CompileError, GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{FPCR_EBF, features::NumericalFeatures},
        scalable::VectorLength,
        sve::{
            dot::RightOperand,
            floating::bfloat16::{Kind, Operand},
        },
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
        },
        simd::numerical::{Condition, branch, resolve, rounding_control},
    },
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const ADDEND: u8 = 6;
const OUTPUT_SLOT: usize = 0;
const REPEAT_DWORD: u8 = 0x55;
const TEST_STATE_IMMEDIATE: &[u8] = &[0xf7, 0x87];
const JMP_REL32: u8 = 0xe9;
const REL32_BYTES: usize = size_of::<i32>();

fn test_control(code: &mut Vec<u8>, mask: u32) {
    code.extend(TEST_STATE_IMMEDIATE);
    code.extend((core::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
    code.extend(mask.to_le_bytes());
}

fn shuffle(code: &mut Vec<u8>, register: u8, order: u8, target: TargetCpu) {
    Host::ShuffleDword.register(code, register, register, target);
    code.push(order);
}

/// Return false before emitting for the separately owned BF16 arithmetic forms.
/// Every output is private until all source/result guards have passed.
pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    if !matches!(operand.kind, Kind::Dot | Kind::MultiplyLong { .. }) || operand.predicate.is_some()
    {
        return Ok(false);
    }
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    let mut failures = Vec::new();
    // Immutable availability and imported EBF select one whole-instruction
    // branch. Neither enhanced nor classic dot inherits long arithmetic traps.
    let enhanced = if operand.kind == Kind::Dot && features.ebf16() {
        test_control(code, FPCR_EBF);
        Some(branch(code, Condition::NotZero))
    } else {
        None
    };
    if operand.kind == Kind::Dot {
        classic_dot::install_environment(code, &frame);
    } else {
        multiply_long::install_environment(code, &frame, features, &mut failures);
    }
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.left, chunk, LEFT, length, target);
        let (right, index) = match operand.right {
            RightOperand::Vector(register) => (register, None),
            RightOperand::Indexed { register, index } => (register, Some(index)),
        };
        load_z_chunk(code, right, chunk, RIGHT, length, target);
        match operand.kind {
            Kind::Dot => {
                if let Some(index) = index {
                    shuffle(code, RIGHT, index * REPEAT_DWORD, target);
                }
                classic_dot::pair_sum(code, &frame, &mut failures, target);
                load_z_chunk(code, operand.destination, chunk, RIGHT, length, target);
                classic_dot::add_accumulator(code, &frame, &mut failures, target);
            }
            Kind::MultiplyLong { subtract, part } => {
                multiply_long::prepare_sources(code, part, index, subtract, target);
                load_z_chunk(code, operand.destination, chunk, ADDEND, length, target);
                multiply_long::evaluate(code, &frame, &mut failures, target);
            }
            _ => unreachable!("validated classic BF operation"),
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
    }
    if let Some(enhanced) = enhanced {
        code.push(JMP_REL32);
        let classic_done = code.len();
        code.extend([0; REL32_BYTES]);
        let enhanced_start = code.len();
        resolve(code, enhanced, enhanced_start);
        // Enhanced BFDOT uses guest RC under both AH values; status/traps are
        // suppressed by its ISA semantics, including FullA64 retained enables.
        rounding_control(code);
        numerical::install_mxcsr(code, &frame);
        for chunk in 0..length.chunks() {
            load_z_chunk(code, operand.left, chunk, LEFT, length, target);
            let (right, index) = match operand.right {
                RightOperand::Vector(register) => (register, None),
                RightOperand::Indexed { register, index } => (register, Some(index)),
            };
            load_z_chunk(code, right, chunk, RIGHT, length, target);
            if let Some(index) = index {
                shuffle(code, RIGHT, index * REPEAT_DWORD, target);
            }
            load_z_chunk(code, operand.destination, chunk, ADDEND, length, target);
            enhanced_dot::emit_chunk(code, &frame, &mut failures);
            numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
        }
        let finished = code.len();
        resolve(code, classic_done, finished);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
