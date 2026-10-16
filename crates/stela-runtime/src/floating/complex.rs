//! Transactional vector complex addition and partial multiply-add completion.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{
            Format, UnsupportedControl,
            complex::{self, COMPONENTS},
        },
        simd::complex::{Kind, Operand, Source},
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

const PAIR_LANES: u32 = COMPONENTS as u32;

fn pair(vector: &[u64; VECTOR_LIMBS], format: Format, first: u32) -> [u64; COMPONENTS] {
    core::array::from_fn(|component| read_lane(vector, format.bits(), first + component as u32))
}

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let addend = state.v[usize::from(operand.destination)];
    let left = state.v[usize::from(operand.left)];
    let (register, index) = match operand.right {
        Source::Vector(register) => (register, None),
        Source::Indexed { register, index } => (register, Some(u32::from(index))),
    };
    let right = state.v[usize::from(register)];
    let fpcr = state.fpcr;
    let mut result = [0; VECTOR_LIMBS];
    let mut exceptions = 0;
    for pair_index in 0..operand.shape.lane_count(operand.format) / PAIR_LANES {
        let first = pair_index * PAIR_LANES;
        let right_first = index.map_or(first, |index| index * PAIR_LANES);
        let left_pair = pair(&left, operand.format, first);
        let right_pair = pair(&right, operand.format, right_first);
        let outcome = match operand.kind {
            Kind::Add => complex::add_pair(
                operand.format,
                operand.rotation,
                fpcr,
                left_pair,
                right_pair,
            ),
            Kind::MultiplyAdd => complex::multiply_add_pair(
                operand.format,
                operand.rotation,
                fpcr,
                pair(&addend, operand.format, first),
                left_pair,
                right_pair,
            ),
        }?;
        for (component, bits) in outcome.bits.into_iter().enumerate() {
            write_lane(
                &mut result,
                operand.format.bits(),
                first + component as u32,
                bits,
            );
        }
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
