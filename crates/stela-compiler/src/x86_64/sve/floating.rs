//! Guarded native mappings for source-admitted streaming numerical families.

mod add_reductions;
mod arithmetic;
mod arithmetic_dispatch;
mod arithmetic_remaining;
mod bfloat16;
mod classify;
mod comparison;
mod complex;
mod conversion;
mod estimate_exponent;
mod floating_estimates;
mod fused;
mod half_dot;
mod indexed_half;
mod minmax;
mod pairwise_clamp;
mod reduction_minmax;
mod refinement;
mod scale;
mod square_root;
mod unsigned_estimates;

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::features::NumericalFeatures, scalable::VectorLength, sve::floating::Operation,
    },
};

/// Try the admitted instruction's native mapping. A declined shape leaves its
/// architectural effects to the shared exact numerical completion boundary.
pub(crate) fn emit(
    code: &mut Vec<u8>,
    word: u32,
    operation: Operation,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    match operation {
        Operation::Arithmetic(operand) => {
            arithmetic_dispatch::emit(code, word, operand, length, features, pc, target)
        }
        Operation::Dot(operand) => half_dot::emit(code, operand, length, features, pc, target),
        Operation::Bfloat16(operand) => bfloat16::emit(code, operand, length, features, pc, target),
        Operation::Comparison(operand) => {
            comparison::emit(code, operand, length, features, pc, target)
        }
        Operation::Conversion(operand) => {
            conversion::widening::emit(code, operand, length, features, pc, target)
        }
    }
}
