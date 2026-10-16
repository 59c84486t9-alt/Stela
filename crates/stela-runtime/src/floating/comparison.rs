//! Completion of NZCV and predicate comparisons.
use stela_compiler::{
    GuestState,
    aarch64::{
        flags::{NZCV_SHIFT, condition_holds},
        floating::{FPCR_NEP, Format, UnsupportedControl, comparison},
        simd::{
            arithmetic::Shape,
            comparison::{CompareSource, Operand},
        },
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

fn source(state: &GuestState, operand: CompareSource) -> [u64; VECTOR_LIMBS] {
    match operand {
        CompareSource::Register(register) => state.v[usize::from(register)],
        CompareSource::Zero => [0; VECTOR_LIMBS],
    }
}

fn complete_flags(
    state: &mut GuestState,
    format: Format,
    left: u8,
    right: CompareSource,
    signal_all_nans: bool,
) -> Result<(), UnsupportedControl> {
    let left = read_lane(&state.v[usize::from(left)], format.bits(), 0);
    let right = read_lane(&source(state, right), format.bits(), 0);
    let outcome = comparison::flags(format, signal_all_nans, state.fpcr, left, right)?;
    state.nzcv = outcome.nzcv;
    state.fpsr |= outcome.exceptions;
    Ok(())
}

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    match *operand {
        Operand::Flags {
            format,
            left,
            right,
            signal_all_nans,
        } => complete_flags(state, format, left, right, signal_all_nans),
        Operand::ConditionalFlags {
            format,
            left,
            right,
            signal_all_nans,
            condition,
            fallback,
        } => {
            if !condition_holds(condition, state.nzcv) {
                // A false condition does not execute FP arithmetic or inspect
                // exception enables, and leaves sticky status untouched.
                state.nzcv = u32::from(fallback) << NZCV_SHIFT;
                return Ok(());
            }
            complete_flags(
                state,
                format,
                left,
                CompareSource::Register(right),
                signal_all_nans,
            )
        }
        Operand::Predicate {
            operation,
            format,
            shape,
            destination,
            left,
            right,
        } => {
            let left = state.v[usize::from(left)];
            let right_value = source(state, right);
            let mut result = if shape == Shape::Scalar
                && matches!(right, CompareSource::Register(_))
                && state.fpcr & FPCR_NEP != 0
            {
                right_value
            } else {
                [0; VECTOR_LIMBS]
            };
            let mut exceptions = 0;
            for lane in 0..shape.lane_count(format) {
                let outcome = comparison::predicate(
                    format,
                    operation,
                    state.fpcr,
                    read_lane(&left, format.bits(), lane),
                    read_lane(&right_value, format.bits(), lane),
                )?;
                write_lane(&mut result, format.bits(), lane, outcome.bits);
                exceptions |= outcome.exceptions;
            }
            state.v[usize::from(destination)] = result;
            state.fpsr |= exceptions;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
