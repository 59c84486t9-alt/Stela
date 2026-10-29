//! Completion of FRECPS and FRSQRTS.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_NEP, UnsupportedControl, refinement},
        simd::{arithmetic::Shape, refinement::Operand},
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let left = state.v[usize::from(operand.left)];
    let right = state.v[usize::from(operand.right)];
    let fpcr = state.fpcr;
    let mut result = if operand.shape == Shape::Scalar && fpcr & FPCR_NEP != 0 {
        left
    } else {
        [0; VECTOR_LIMBS]
    };
    let mut exceptions = 0;
    for lane in 0..operand.shape.lane_count(operand.format) {
        let outcome = refinement::evaluate(
            operand.kind,
            operand.format,
            fpcr,
            read_lane(&left, operand.format.bits(), lane),
            read_lane(&right, operand.format.bits(), lane),
        )?;
        write_lane(&mut result, operand.format.bits(), lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
