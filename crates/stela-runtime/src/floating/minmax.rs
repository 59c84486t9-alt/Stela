//! Transactional elementwise, pairwise and balanced reduction completion.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_NEP, Format, UnsupportedControl, minmax},
        simd::{
            arithmetic::Shape,
            minmax::{BinaryMode, Operand},
        },
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

const PAIR_LANES: u32 = 2;
const MAX_REDUCTION_LANES: usize = VECTOR_LIMBS * u64::BITS as usize / Format::Half.bits() as usize;

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let format = operand.format();
    let operation = operand.operation();
    let mut result = [0; VECTOR_LIMBS];
    let mut exceptions = 0;
    match *operand {
        Operand::Binary {
            shape,
            mode,
            left,
            right,
            ..
        } => {
            let left = state.v[usize::from(left)];
            let right = state.v[usize::from(right)];
            if shape == Shape::Scalar && state.fpcr & FPCR_NEP != 0 {
                result = left;
            }
            let lanes = shape.lane_count(format);
            for lane in 0..lanes {
                let (left_bits, right_bits) = match mode {
                    BinaryMode::Elementwise => (
                        read_lane(&left, format.bits(), lane),
                        read_lane(&right, format.bits(), lane),
                    ),
                    BinaryMode::Pairwise => {
                        let half = lanes / PAIR_LANES;
                        let (source, pair) = if lane < half {
                            (&left, lane)
                        } else {
                            (&right, lane - half)
                        };
                        (
                            read_lane(source, format.bits(), pair * PAIR_LANES),
                            read_lane(source, format.bits(), pair * PAIR_LANES + 1),
                        )
                    }
                };
                let outcome =
                    minmax::evaluate(format, operation, state.fpcr, left_bits, right_bits)?;
                write_lane(&mut result, format.bits(), lane, outcome.bits);
                exceptions |= outcome.exceptions;
            }
        }
        Operand::PairwiseScalar { source, .. } => {
            let source = state.v[usize::from(source)];
            let outcome = minmax::evaluate(
                format,
                operation,
                state.fpcr,
                read_lane(&source, format.bits(), 0),
                read_lane(&source, format.bits(), 1),
            )?;
            write_lane(&mut result, format.bits(), 0, outcome.bits);
            exceptions |= outcome.exceptions;
        }
        Operand::Reduction { shape, source, .. } => {
            let source = state.v[usize::from(source)];
            let mut lanes = shape.lane_count(format);
            let mut values = [0; MAX_REDUCTION_LANES];
            for (lane, value) in values.iter_mut().enumerate().take(lanes as usize) {
                *value = read_lane(&source, format.bits(), lane as u32);
            }
            // Adjacent pairs form each level of Arm's balanced reduction tree.
            // Intermediate NaN results and their exceptions must survive to
            // the next level; a left fold can choose a different final value.
            while lanes > 1 {
                for pair in 0..lanes / PAIR_LANES {
                    let outcome = minmax::evaluate(
                        format,
                        operation,
                        state.fpcr,
                        values[(pair * PAIR_LANES) as usize],
                        values[(pair * PAIR_LANES + 1) as usize],
                    )?;
                    values[pair as usize] = outcome.bits;
                    exceptions |= outcome.exceptions;
                }
                lanes /= PAIR_LANES;
            }
            write_lane(&mut result, format.bits(), 0, values[0]);
        }
    }
    state.v[usize::from(operand.destination())] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
