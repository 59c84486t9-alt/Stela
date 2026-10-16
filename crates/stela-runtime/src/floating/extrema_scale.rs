//! Completion of AdvSIMD FAMIN/FAMAX and FSCALE.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{UnsupportedControl, absolute_minmax, exponent},
        simd::extrema_scale::{Kind, Operand},
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    // Every source is snapshotted before staging, including Vd=Vn=Vm and V31.
    let left = state.v[usize::from(operand.left)];
    let right = state.v[usize::from(operand.right)];
    let mut result = [0; VECTOR_LIMBS];
    let mut exceptions = 0;
    for lane in 0..operand.shape.lane_count(operand.format) {
        let left = read_lane(&left, operand.format.bits(), lane);
        let right = read_lane(&right, operand.format.bits(), lane);
        let outcome = match operand.kind {
            Kind::Absolute(operation) => {
                absolute_minmax::evaluate(operand.format, operation, state.fpcr, left, right)
            }
            Kind::Scale => exponent::scale(operand.format, state.fpcr, left, right),
        }?;
        write_lane(&mut result, operand.format.bits(), lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
