//! Integer-only magnitude extrema for every finite H/S/D lane and infinity.
//! Active NaNs use exact source completion; inactive poison never evaluates.
use super::classify::guard_active_exception_enables;
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::{ElementSize, VectorLength},
        sve::floating::faminmax::Operand,
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::absolute_selection,
    },
};
use alloc::vec::Vec;

const LEFT: u8 = 5;
const RIGHT: u8 = 6;
const ACTIVE: u8 = 7;
const SCRATCH: [u8; 4] = [0, 1, 2, 3];
fn element(format: Format) -> ElementSize {
    match format {
        Format::Half => ElementSize::Halfword,
        Format::Single => ElementSize::Word,
        Format::Double => ElementSize::Doubleword,
    }
}

/// Integer positive-magnitude order includes subnormals without host FP status.
/// Reviewed static scopes use checked SSE4.1/SSE4.2 tiers for Single/Double.
/// Complete output staging preserves sources/aliases on any guard failure.
pub(crate) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    let mut failures = Vec::new();
    // Full-wrapper comparisons cover these static scopes without Full A64.
    // EBF16/RPRES do not affect this emitter; other scopes retain baseline.
    let selection_target = if !features.full_a64() {
        match (operand.format, length.bytes()) {
            (Format::Single, 16 | 64 | 256) if target.supports(TargetCpu::Sse41) => {
                TargetCpu::Sse41
            }
            (Format::Double, 16 | 64 | 256) if target.supports(TargetCpu::Sse42) => {
                TargetCpu::Sse42
            }
            _ => TargetCpu::Baseline,
        }
    } else {
        TargetCpu::Baseline
    };
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            element(operand.format),
            ACTIVE,
            0,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, operand.destination, chunk, LEFT, length, target);
        load_z_chunk(code, operand.right, chunk, RIGHT, length, target);
        // Inactive poison becomes +0 before the shared NaN guard.
        Host::And.register(code, LEFT, ACTIVE, target);
        Host::And.register(code, RIGHT, ACTIVE, target);
        absolute_selection::guard_and_magnitudes(
            code,
            operand.format,
            LEFT,
            RIGHT,
            SCRATCH,
            &mut failures,
            selection_target,
        );
        absolute_selection::emit(
            code,
            operand.format,
            operand.operation,
            LEFT,
            RIGHT,
            SCRATCH,
            selection_target,
        );
        load_z_chunk(code, operand.destination, chunk, SCRATCH[0], length, target);
        Host::AndNot.register(code, ACTIVE, SCRATCH[0], target);
        Host::Or.register(code, LEFT, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, 0, chunk, LEFT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
