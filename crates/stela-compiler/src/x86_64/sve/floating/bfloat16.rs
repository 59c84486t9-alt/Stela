//! BF arithmetic and Single accumulation use distinct native kernel families.
mod accumulation;
mod arithmetic;

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::features::NumericalFeatures,
        scalable::VectorLength,
        sve::floating::bfloat16::{Kind, Operand},
    },
};

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    match operand.kind {
        Kind::Binary(_) | Kind::Clamp | Kind::MultiplyAdd { .. } => {
            arithmetic::emit(code, operand, length, features, pc, target)
        }
        Kind::Dot | Kind::MultiplyLong { .. } => {
            accumulation::emit(code, operand, length, features, pc, target)
        }
    }
}
