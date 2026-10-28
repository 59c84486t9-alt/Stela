//! SVE predicated conversions.
use crate::x86_64::asm::Code;
mod bfloat;
mod double_narrowing;
mod half_integer;
mod half_narrowing;
mod half_widening;
mod integer;
mod unsigned64;
pub(crate) mod widening;

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::VectorLength,
        sve::floating::conversion::{Kind, Operand},
    },
};

/// Preserve existing Single-to-Double mappings and use the verified baseline
/// for integer conversions.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    match operand.kind {
        Kind::Precision {
            source: Format::Single,
            destination: Format::Double,
            ..
        } => widening::emit(code, operand, length, features, pc, target),
        Kind::Precision {
            source: Format::Half,
            ..
        } => half_widening::emit(code, operand, length, features, pc, target),
        Kind::Precision {
            destination: Format::Half,
            ..
        } => half_narrowing::emit(code, operand, length, features, pc, target),
        Kind::Precision {
            source: Format::Double,
            destination: Format::Single,
            ..
        } => double_narrowing::emit(code, operand, length, features, pc, target),
        Kind::ToInteger { .. } | Kind::FromInteger { .. } => {
            integer::emit(code, operand, length, features, pc, target)
        }
        Kind::Bfloat16 { .. } => bfloat::emit(code, operand, length, features, pc, target),
        _ => Ok(false),
    }
}
