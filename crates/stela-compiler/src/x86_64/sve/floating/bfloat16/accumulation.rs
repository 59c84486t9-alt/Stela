//! BFDOT (classic and FEAT_EBF16) and BFMLAL/BFMLSL.
use crate::x86_64::asm::Gpr::Rdi;
use crate::x86_64::asm::{Code, Mem, Rm, Size};
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

fn test_control(code: &mut Code, mask: u32) {
    code.asm().test_imm32(
        Size::Dword,
        Mem::base_disp32(Rdi, (core::mem::offset_of!(GuestState, fpcr)) as i32),
        mask as i32,
    );
}

fn shuffle(code: &mut Code, register: u8, order: u8, target: TargetCpu) {
    code.asm().simd_imm(
        Host::ShuffleDword,
        register,
        Rm::Xmm(register),
        order,
        target,
    );
}

/// Returns false before emitting for the BF16 arithmetic forms, which are
/// emitted elsewhere. Outputs stay private until every guard passes.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
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
        let classic_done = code.asm().jmp().offset();
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
