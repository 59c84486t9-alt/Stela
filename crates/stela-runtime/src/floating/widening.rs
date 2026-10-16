//! Completion of FMLAL and FMLSL.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{Format, UnsupportedControl, widening},
        simd::widening::Operand,
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let addend = state.v[usize::from(operand.destination)];
    let left = state.v[usize::from(operand.left)];
    let right = state.v[usize::from(operand.right)];
    let fpcr = state.fpcr;
    let source_start = operand.part.source_lane_offset(operand.shape);
    let mut result = [0; VECTOR_LIMBS];
    let mut exceptions = 0;
    for lane in 0..operand.shape.lane_count(Format::Single) {
        let source_lane = source_start + lane;
        let right_lane = operand.right_lane.map_or(source_lane, u32::from);
        let outcome = widening::evaluate(
            operand.operation,
            fpcr,
            read_lane(&addend, Format::Single.bits(), lane) as u32,
            read_lane(&left, Format::Half.bits(), source_lane) as u16,
            read_lane(&right, Format::Half.bits(), right_lane) as u16,
        )?;
        write_lane(&mut result, Format::Single.bits(), lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
