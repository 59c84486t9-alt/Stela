//! BF16 numerical mappings, grouped by their distinct rounding contracts.
mod conversion;
mod dot;
mod multiply;

use crate::{GuestAddress, TargetCpu, aarch64::simd::bfloat16::Operand};

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    match operand {
        Operand::Conversion(operand) => conversion::emit(code, operand, pc),
        Operand::Dot(operand) => dot::emit_dot(code, operand, pc),
        Operand::MultiplyAdd(operand) => multiply::emit(code, operand, pc, target),
        Operand::Matrix(operand) => dot::emit_matrix(code, operand, pc),
    }
}
