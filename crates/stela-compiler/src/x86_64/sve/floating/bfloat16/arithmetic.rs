//! Non-widening BF16 arithmetic.
use crate::x86_64::asm::Code;
mod binary;
mod fused;
mod selection;

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::features::NumericalFeatures,
        scalable::VectorLength,
        sve::floating::bfloat16::{BinaryOperation, Kind, Operand},
    },
};

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    match operand.kind {
        Kind::Binary(
            BinaryOperation::Add | BinaryOperation::Subtract | BinaryOperation::Multiply,
        ) => binary::emit(code, operand, length, features, pc, target),
        Kind::Binary(_) | Kind::Clamp => {
            selection::emit(code, operand, length, features, pc, target)
        }
        Kind::MultiplyAdd { .. } => fused::emit(code, operand, length, features, pc, target),
        _ => Ok(false),
    }
}
