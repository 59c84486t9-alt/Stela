//! Transactional scalar/vector round-to-integral completion.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_NEP, UnsupportedControl, rounding},
        simd::{arithmetic::Shape, rounding::Operand},
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let source = state.v[usize::from(operand.source)];
    let destination = state.v[usize::from(operand.destination)];
    let fpcr = state.fpcr;
    let mut result = if operand.shape == Shape::Scalar && fpcr & FPCR_NEP != 0 {
        destination
    } else {
        [0; VECTOR_LIMBS]
    };
    let mut exceptions = 0;
    for lane in 0..operand.shape.lane_count(operand.format) {
        let outcome = rounding::evaluate(
            operand.format,
            operand.operation,
            fpcr,
            read_lane(&source, operand.format.bits(), lane),
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
