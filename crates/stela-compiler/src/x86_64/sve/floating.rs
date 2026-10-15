//! Guarded native mappings for the three admitted SVE numerical families.

mod arithmetic;
mod classify;
mod comparison;
mod conversion;

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
    operation: Operation,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    match operation {
        Operation::Arithmetic(operand) => {
            arithmetic::emit(code, operand, length, features, pc, target)
        }
        Operation::Comparison(operand) => {
            comparison::emit(code, operand, length, features, pc, target)
        }
        Operation::Conversion(operand) => {
            conversion::widening::emit(code, operand, length, features, pc, target)
        }
    }
}
