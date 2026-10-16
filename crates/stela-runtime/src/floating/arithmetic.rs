//! Completion of elementwise, indexed and pairwise arithmetic.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_NEP, UnsupportedControl, evaluate},
        simd::arithmetic::{Inputs, Operand, Shape},
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

const PAIR_LANES: u32 = 2;

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let (left, right) = match operand.inputs {
        Inputs::Elementwise { left, right }
        | Inputs::Indexed { left, right, .. }
        | Inputs::Pairwise { left, right } => {
            (state.v[usize::from(left)], state.v[usize::from(right)])
        }
        Inputs::PairwiseScalar { source } => {
            let source = state.v[usize::from(source)];
            (source, source)
        }
    };
    let mut result = if operand.shape == Shape::Scalar
        && !matches!(operand.inputs, Inputs::PairwiseScalar { .. })
        && state.fpcr & FPCR_NEP != 0
    {
        left
    } else {
        [0; VECTOR_LIMBS]
    };
    let lanes = operand.shape.lane_count(operand.format);
    let bits = operand.format.bits();
    let mut exceptions = 0;
    for lane in 0..lanes {
        let (left_bits, right_bits) = match operand.inputs {
            Inputs::Elementwise { .. } => {
                (read_lane(&left, bits, lane), read_lane(&right, bits, lane))
            }
            Inputs::Indexed { right_lane, .. } => (
                read_lane(&left, bits, lane),
                read_lane(&right, bits, u32::from(right_lane)),
            ),
            Inputs::Pairwise { .. } => {
                let pairs_per_source = lanes / PAIR_LANES;
                let (source, pair) = if lane < pairs_per_source {
                    (&left, lane)
                } else {
                    (&right, lane - pairs_per_source)
                };
                (
                    read_lane(source, bits, pair * PAIR_LANES),
                    read_lane(source, bits, pair * PAIR_LANES + 1),
                )
            }
            Inputs::PairwiseScalar { .. } => {
                (read_lane(&left, bits, 0), read_lane(&right, bits, 1))
            }
        };
        let outcome = evaluate(
            operand.format,
            operand.operation,
            state.fpcr,
            left_bits,
            right_bits,
        )?;
        write_lane(&mut result, bits, lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
