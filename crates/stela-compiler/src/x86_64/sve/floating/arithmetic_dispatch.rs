//! Selection between native and software arithmetic paths.
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::features::NumericalFeatures,
        scalable::VectorLength,
        simd::estimate::Kind as EstimateKind,
        sve::floating::arithmetic::{self as guest, Inputs, Kind, Operand, ResultShape},
    },
};
use alloc::vec::Vec;

use super::{
    add_reductions, arithmetic, complex, estimate_exponent, floating_estimates, fused, minmax,
    pairwise_clamp, reduction_minmax as minmax_reductions, refinement, scale, square_root,
    unsigned_estimates,
};

/// The admission check supplies the original word and its decoded operand. The
/// encoding class comes from the shared metadata, so reversed forms with
/// aliased registers cannot reach the forward-only emitter.
pub(super) fn emit(
    code: &mut Vec<u8>,
    word: u32,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    if let Some(core) = guest::decode_core_binary(word) {
        let core = core.map_err(|()| CompileError("reserved core binary allocation".into()))?;
        assert_eq!(core, operand, "admitted source/operand identity changed");
        return arithmetic::emit_core(code, core, length, features, pc, target);
    }
    let before = code.len();
    if super::indexed_half::emit(code, operand, length, features, pc, target)? {
        return Ok(true);
    }
    assert_eq!(
        code.len(),
        before,
        "declined indexed Half emitter changed output"
    );
    match (operand.kind, operand.inputs, operand.shape) {
        (Kind::Binary(_), Inputs::Binary { .. }, ResultShape::Vector) => {
            arithmetic::emit_operand_forms(code, operand, length, features, pc, target)
        }
        (Kind::Fused(_), Inputs::Fused { .. }, ResultShape::Vector) => {
            fused::emit(code, operand, length, features, pc, target)
        }
        (Kind::ComplexAdd(_) | Kind::ComplexMultiplyAdd(_), _, ResultShape::Vector) => {
            complex::emit(code, operand, length, features, pc, target)
        }
        (Kind::MinMax(_), Inputs::Binary { .. }, ResultShape::Vector) => {
            minmax::emit(code, operand, length, features, pc, target)
        }
        (Kind::MinMax(_), Inputs::Pairwise { .. }, ResultShape::Vector)
        | (Kind::Clamp, Inputs::Clamp { .. }, ResultShape::Vector) => {
            pairwise_clamp::emit(code, operand, length, features, pc, target)
        }
        (Kind::Binary(_), Inputs::Pairwise { .. } | Inputs::Reduction { .. }, _) => {
            add_reductions::emit(code, operand, length, features, pc, target)
        }
        (Kind::MinMax(_), Inputs::Reduction { .. }, _) => {
            minmax_reductions::emit(code, operand, length, features, pc, target)
        }
        (Kind::Estimate(EstimateKind::ReciprocalExponent) | Kind::Logb, _, _) => {
            estimate_exponent::emit(code, operand, length, features, pc, target)
        }
        (Kind::SquareRoot, _, _) => square_root::emit(code, operand, length, features, pc, target),
        (Kind::Scale, _, _) => scale::emit(code, operand, length, features, pc, target),
        (Kind::Estimate(EstimateKind::Reciprocal | EstimateKind::ReciprocalSquareRoot), _, _) => {
            floating_estimates::emit(code, operand, length, features, pc, target)
        }
        (
            Kind::Estimate(
                EstimateKind::UnsignedReciprocal | EstimateKind::UnsignedReciprocalSquareRoot,
            ),
            _,
            _,
        ) => unsigned_estimates::emit(code, operand, length, features, pc, target),
        (Kind::Refinement(_), _, _) => {
            refinement::emit(code, operand, length, features, pc, target)
        }
        _ => Ok(false),
    }
}
