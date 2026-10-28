//! AdvSIMD BF16 instructions.
use crate::x86_64::asm::Code;
mod conversion;
mod dot;
mod multiply;

use crate::{GuestAddress, TargetCpu, aarch64::simd::bfloat16::Operand};

pub(in crate::x86_64) fn emit(
    code: &mut Code,
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

pub(in crate::x86_64) use conversion::{
    conversion_inexact, guard_conversion_enables, prepare_conversion_rounding,
    quantize_normal_conversion,
};
